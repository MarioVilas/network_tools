#!/usr/bin/env python

# Copyright (c) 2009-2013, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import re

from time import gmtime, asctime
from os import unlink
from os.path import exists, getmtime
from threading import RLock
from urllib import quote, unquote

# Lazy imports.
sqlite3 = None
urllib2 = None
shutil  = None
etree   = None

def get_cpe_version(cpe):
    if not isinstance(cpe, basestring):
        raise TypeError("Expected string, got %r instead" % type(cpe))
    if cpe.startswith("cpe:/"):
        return "2.2"
    elif cpe.startswith("cpe:2.3:"):
        return "2.3"
    else:
        raise ValueError("Not a valid CPE name: %s" % cpe)

def cpe22_unquote(s):
    if not s:
        return s
    r = []
    i = -1
    while i < len(s):
        i += 1
        c = s[i]
        if c == "\\":
            r.append("\\\\")
            continue
        if c != "%":
            r.append(c)
            continue
        h = s[ i + 1 : i + 2 ]
        if len(h) > 0 and h[0] == "%":
            r.append(c)
            i += 1
            continue
        if len(h) != 2 or \
           h[0] not in "0123456789abcdefABCDEF" or \
           h[1] not in "0123456789abcdefABCDEF":
            r.append(c)
            continue
        r.append("\\")
        r.append( chr( int(h, 16) ) )
    return "".join(r)

_cpe23_split = re.compile(r"(?<!\\)\:")
def parse_cpe(cpe):
    ver = get_cpe_version(cpe)
    if ver == "2.2":
        parsed = [cpe22_unquote(x.strip()) for x in cpe[5:].split(":")]
        if len(parsed) < 11:
            parsed.extend( "*" * (11 - len(parsed)) )
    elif ver == "2.3":
        parsed = [x.strip() for x in _cpe23_split.split(cpe[8:])]
        if len(parsed) != 11:
            raise ValueError("Not a valid CPE 2.3 name: %s" % cpe)
    else:
        raise ValueError("Not a valid CPE 2.2 or 2.3 name: %s" % cpe)
    return parsed

def unparse_cpe23(parsed):
    return "cpe:2.3:" + ":".join(x.replace(":", r"\:") for x in parsed)

def cpe22to23(cpe):
    return unparse_cpe23( parse_cpe(cpe) )


def transactional(fn):
    def wrapper(self, *args, **kwargs):
        return self._transaction(fn, args, kwargs)
    return wrapper

def iter_transactional(fn):
    def wrapper(self, *args, **kwargs):
        return self._iter_transaction(fn, args, kwargs)
    return wrapper

class CPEDB(object):
    """
    Translates between CPE 2.2 and CPE 2.3 names, and looks up user-friendly
    software names from CPE names and visceversa.

    The official CPE dictionary was converted to SQLite format from the
    original XML file mantained by NIST: https://nvd.nist.gov/cpe.cfm
    """

    DEFAULT_DB_FILE = "official-cpe-dictionary_v2.3.db"
    XML_FILE = "official-cpe-dictionary_v2.3.xml"
    DOWNLOAD_URL = (
        "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/" + XML_FILE
    )

    def __init__(self, db_file = None):

        # If no filename is given, use the default.
        if not db_file:
            db_file = self.DEFAULT_DB_FILE

        # Create the lock to make this class thread safe.
        self.__lock = RLock()

        # The busy flag prevents reentrance.
        self.__busy = False

        # Determine if the database existed.
        is_new = exists(db_file)

        # Open the database file.
        global sqlite3
        if sqlite3 is None:
            import sqlite3
        self.__db = sqlite3.connect(db_file)

        # Initialize the database if needed.
        # On error close the database and raise an exception.
        try:
            is_empty = self.__initialize()
            if is_empty:
                self.update(force = True)
        except:
            self.close()
            if is_new:
                unlink(db_file)
            raise

    def close(self):
        try:
            self.__db.close()
        finally:
            self.__db     = None
            self.__cursor = None
            self.__lock   = None

    def __enter__(self):
        return self

    def __exit__(self, etype, value, tb):
        try:
            self.close()
        except Exception:
            pass

    def _transaction(self, fn, args, kwargs):
        with self.__lock:
            if self.__busy:
                raise RuntimeError("The database is busy")
            try:
                self.__busy   = True
                self.__cursor = self.__db.cursor()
                try:
                    retval = fn(self, *args, **kwargs)
                    self.__db.commit()
                    return retval
                except:
                    self.__db.rollback()
                    raise
            finally:
                self.__cursor = None
                self.__busy   = False

    def _iter_transaction(self, fn, args, kwargs):
        with self.__lock:
            if self.__busy:
                raise RuntimeError("The database is busy")
            try:
                self.__busy   = True
                self.__cursor = self.__db.cursor()
                try:
                    for item in fn(self, *args, **kwargs):
                        yield item
                    self.__db.commit()
                except:
                    self.__db.rollback()
                    raise
            finally:
                self.__cursor = None
                self.__busy   = False

    @transactional
    def __initialize(self):

        # If the file already contains the schema, do nothing.
        self.__cursor.execute(
            "SELECT count(*) FROM sqlite_master"
            " WHERE type = 'table' AND name = 'cpe';"
        )
        if self.__cursor.fetchone()[0]:
            return False

        # Create the database schema.
        self.__cursor.executescript(
            """
            CREATE TABLE `cpe` (
                `rowid` INTEGER PRIMARY KEY,
                `name23` STRING UNIQUE NOT NULL,
                `name22` STRING NOT NULL,
                `title` STRING NOT NULL,
                `deprecated` INTEGER(1) NOT NULL DEFAULT 0,
                `part` STRING NOT NULL DEFAULT '*',
                `vendor` STRING NOT NULL DEFAULT '*',
                `product` STRING NOT NULL DEFAULT '*',
                `version` STRING NOT NULL DEFAULT '*',
                `update` STRING NOT NULL DEFAULT '*',
                `edition` STRING NOT NULL DEFAULT '*',
                `language` STRING NOT NULL DEFAULT '*',
                `sw_edition` STRING NOT NULL DEFAULT '*',
                `target_sw` STRING NOT NULL DEFAULT '*',
                `target_hw` STRING NOT NULL DEFAULT '*',
                `other` STRING NOT NULL DEFAULT '*'
            );
            CREATE INDEX `cpe_name22` ON `cpe`(`name22`);
            CREATE INDEX `cpe_title` ON `cpe`(`title`);
            CREATE INDEX `cpe_part` ON `cpe`(`part`);
            CREATE INDEX `cpe_vendor` ON `cpe`(`vendor`);
            CREATE INDEX `cpe_product` ON `cpe`(`product`);
            CREATE INDEX `cpe_version` ON `cpe`(`version`);
            CREATE INDEX `cpe_update` ON `cpe`(`update`);
            CREATE INDEX `cpe_edition` ON `cpe`(`edition`);
            CREATE INDEX `cpe_language` ON `cpe`(`language`);
            CREATE INDEX `cpe_sw_edition` ON `cpe`(`sw_edition`);
            CREATE INDEX `cpe_target_sw` ON `cpe`(`target_sw`);
            CREATE INDEX `cpe_target_hw` ON `cpe`(`target_hw`);
            CREATE INDEX `cpe_other` ON `cpe`(`other`);
            """
        )
        return True

    @transactional
    def update(self, force = False):
        """
        Update the database.

        This downloads a newer XML file from NIST if available,
        and recreates the database from it.

        :param force: True to force the update, False to only
            load the data from NIST if outdated.
        :type force: bool
        """

        # Lazy imports.
        global etree
        if etree is None:
            try:
                from xml.etree import cElementTree as etree
            except ImportError:
                from xml.etree import ElementTree as etree
        global urllib2
        if urllib2 is None:
            import urllib2
        global shutil
        if shutil is None:
            import shutil

        # If the XML file from NIST is missing, broken or older, download it.
        xml_file = self.XML_FILE
        tree = None
        if not exists(xml_file):
            src = urllib2.urlopen(self.DOWNLOAD_URL)
        else:
            try:
                tree = etree.parse(xml_file)
                src  = None
            except Exception:
                src = urllib2.urlopen(self.DOWNLOAD_URL)
            else:
                try:
                    ims = asctime(gmtime(getmtime(xml_file)))
                    req = urllib2.Request(self.DOWNLOAD_URL, headers = {
                        "If-Modified-Since": ims
                    })
                    src = urllib2.urlopen(req)
                except urllib2.HTTPError, e:
                    if e.code != 304:
                        raise
                    src = None
        if src is not None:
            force = True
            with open(xml_file, "wb") as dst:
                shutil.copyfileobj(src, dst)

        # Do we have to reload the data?
        if force:

            # Open the XML file.
            if tree is None:
                tree = etree.parse(xml_file)
            root = tree.getroot()

            # Delete the old data.
            self.__cursor.execute("DELETE FROM `cpe`;")

            # Parse the XML file and store the data into the database.
            prefix20 = "{http://cpe.mitre.org/dictionary/2.0}"
            prefix23 = "{http://scap.nist.gov/schema/cpe-extension/2.3}"
            prefixns = "{http://www.w3.org/XML/1998/namespace}"
            for item in root.iter(prefix20 + "cpe-item"):
                name22 = item.attrib["name"]
                name23 = item.find(".//%scpe23-item" % prefix23).attrib["name"]
                deprecated = int(
                            item.attrib.get("deprecated", "false") == "true")
                titles = {
                    t.attrib[prefixns + "lang"]: t.text
                    for t in item.iter(prefix20 + "title")
                }
                try:
                    title = titles["en-US"]
                except KeyError:
                    found = False
                    for lang, title in sorted(titles.items()):
                        if lang.startswith("en-"):
                            found = True
                            break
                    if not found:
                        title = titles[sorted(titles.keys())[0]]
                params = (name23, name22, title, deprecated)
                params = params + tuple( parse_cpe(name23) )
                self.__cursor.execute(
                    "INSERT INTO `cpe` VALUES "
                    "(NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                    params
                )

    @transactional
    def resolve(self, cpe, include_deprecated = True):
        """
        Resolve the given CPE with wildcards.

        :param CPE: CPE name.
        :type CPE: str | unicode

        :param include_deprecated: True to include deprecated names in the
            results, False otherwise.
        :type include_deprecated: bool

        :returns: Set of matching CPE names.
        :rtype: set(str|unicode)
        """

        ver = get_cpe_version(cpe).replace(".", "")
        parsed = parse_cpe(cpe)

        params = [x for x in parsed if x != "*"]
        if not params:
            return set([cpe])
        params.insert(0, cpe)

        columns = ["part", "vendor", "product", "version", "update"]
        if ver == "23":
            columns.extend([
                "edition", "language", "sw_edition",
                "target_sw", "target_hw", "other"
            ])

        query = "SELECT `name%s` FROM `cpe` WHERE " % ver
        if not include_deprecated:
            query += "`deprecated` = 0 AND "
        query += "(`name%s` = ?" % ver
        query += " OR (%s)" % " AND ".join(
            "`%s` = ?" % columns[i]
            for i in xrange(len(columns))
            if parsed[i] != "*"
        )
        query += ");"

        self.__cursor.execute(query, params)
        return set(row[0] for row in self.__cursor.fetchall())

    @transactional
    def get_title(self, cpe):
        """
        Get the user-friendly title of a CPE name.

        :param CPE: CPE name.
        :type CPE: str | unicode
        """
        ver = get_cpe_version(cpe).replace(".", "")
        query = (
            "SELECT `title` FROM `cpe` WHERE `name%s` = ? LIMIT 1;"
        ) % ver
        self.__cursor.execute(query, (cpe,))
        row = self.__cursor.fetchone()
        if not row:
            raise KeyError("CPE name not found: %s" % cpe)
        return row[0]

    @transactional
    def search(self, **kwargs):
        """
        Search the CPE database for the requested fields.
        The value '*' is assumed for missing fields.

        :keyword title: User-friendly product name.
        :type title: str | unicode

        :keyword part: CPE class. Use "a" for applications,
            "o" for operating systems or "h" for hardware devices.
        :type part: str | unicode

        :keyword vendor: Person or organization that manufactured or
            created the product.
        :type vendor: str | unicode

        :keyword product: The most common and recognizable title or name
            of the product.
        :type product: str | unicode

        :keyword version: Vendor-specific alphanumeric strings
            characterizing the particular release version of the product.
        :type version: str | unicode

        :keyword update: Vendor-specific alphanumeric strings
            characterizing the particular update, service pack, or point
            release of the product.
        :type update: str | unicode

        :keyword edition: Legacy 'edition' attribute from CPE 2.2.
        :type edition: str | unicode

        :keyword language: Language tag for the language supported in the user
            interface of the product.
        :type language: str | unicode

        :keyword sw_edition: Characterizes how the product is tailored to a
            particular market or class of end users.
        :type sw_edition: str | unicode

        :keyword target_sw: Software computing environment within which the
            product operates.
        :type target_sw: str | unicode

        :keyword target_hw: Instruction set architecture (e.g., x86) on which
            the product operates.
        :type target_hw: str | unicode

        :keyword other: Any other general descriptive or identifying
            information which is vendor- or product-specific and which
            does not logically fit in any other attribute value.
        :type other: str | unicode

        :returns: Set of matching CPE names.
        :rtype: set(str|unicode)
        """
        columns = [
            "title",
            "part", "vendor", "product", "version", "update", "edition",
            "language", "sw_edition", "target_sw", "target_hw", "other"
        ]
        if set(kwargs).difference(columns):
            raise TypeError("Unknown keyword arguments: %s"
                    % ", " % sorted(set(kwargs).difference(columns)) )
        query = "SELECT `name23` FROM `cpe` WHERE "
        query += " AND ".join(
            "`%s` LIKE ?" % field
            for field in columns
            if field in kwargs and kwargs[field] != "*"
        )
        params = [
            "%%%s%%" % kwargs[field].replace("%", "%%")
            for field in columns
            if field in kwargs and kwargs[field] != "*"
        ]
        self.__cursor.execute(query, params)
        return set(row[0] for row in self.__cursor.fetchall())

if __name__ == "__main__":
    import sqlite3
    import urllib2
    import shutil
    import sys
    import platform

    title = sys.platform
    version = "*"
    target_hw = "*"
    if title == "win32":
        title = "windows " + platform.win32_ver()[0]
    elif title.startswith("linux"):
        title, version = platform.linux_distribution()[:1]
        #target_hw = platform.uname()[-1]
    elif title == "mac":
        title = "mac os x"
        version = platform.mac_ver()[1]
        #target_hw = platform.uname()[-1]

    with CPEDB() as db:
        db.update()
        for cpe in db.search(title=title, version=version, part="o", target_hw=target_hw):
            #print cpe
            print db.get_title(cpe)
