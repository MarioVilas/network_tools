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
import sqlite3

from datetime import date
from os import unlink
from os.path import exists, getmtime
from shutil import copyfileobj
from time import gmtime, asctime
from threading import RLock
from urllib import quote, unquote
from urllib2 import urlopen, Request, HTTPError

try:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree


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


class VulnerabilityDB(object):
    """
    Vulnerability ID database.

    The CPE dictionary is generated from the XML file mantained by NIST:
    https://nvd.nist.gov/cpe.cfm

    The CVE database is generated from the XML files mantained by NIST:
    https://nvd.nist.gov/download.cfm#CVE_FEED
    """

    DEFAULT_DB_FILE = "vulnid.db"

    CPE_XML_FILE = "official-cpe-dictionary_v2.3.xml"
    CPE_URL_BASE = "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/"

    CVE_XML_FILE = "nvdcve-2.0-%s.xml" # % year
    CVE_URL_BASE = "http://static.nvd.nist.gov/feeds/xml/cve/"

    SCHEMA = \
    """
    PRAGMA foreign_keys = ON;
    PRAGMA application_id = 1447642178;

    ---------------------
    -- File timestamps --
    ---------------------

    CREATE TABLE IF NOT EXISTS `files` (
        `filename` STRING NOT NULL UNIQUE ON CONFLICT REPLACE,
        `last_modified` INTEGER NOT NULL
    );

    ---------
    -- CPE --
    ---------

    CREATE TABLE IF NOT EXISTS `cpe` (
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
    CREATE INDEX IF NOT EXISTS `cpe_name22` ON `cpe`(`name22`);
    CREATE INDEX IF NOT EXISTS `cpe_title` ON `cpe`(`title`);
    CREATE INDEX IF NOT EXISTS `cpe_part` ON `cpe`(`part`);
    CREATE INDEX IF NOT EXISTS `cpe_vendor` ON `cpe`(`vendor`);
    CREATE INDEX IF NOT EXISTS `cpe_product` ON `cpe`(`product`);
    CREATE INDEX IF NOT EXISTS `cpe_version` ON `cpe`(`version`);
    CREATE INDEX IF NOT EXISTS `cpe_update` ON `cpe`(`update`);
    CREATE INDEX IF NOT EXISTS `cpe_edition` ON `cpe`(`edition`);
    CREATE INDEX IF NOT EXISTS `cpe_language` ON `cpe`(`language`);
    CREATE INDEX IF NOT EXISTS `cpe_sw_edition` ON `cpe`(`sw_edition`);
    CREATE INDEX IF NOT EXISTS `cpe_target_sw` ON `cpe`(`target_sw`);
    CREATE INDEX IF NOT EXISTS `cpe_target_hw` ON `cpe`(`target_hw`);
    CREATE INDEX IF NOT EXISTS `cpe_other` ON `cpe`(`other`);

    ---------
    -- CVE --
    ---------

    CREATE TABLE IF NOT EXISTS `cve` (
        `rowid` INTEGER PRIMARY KEY,
        `year` INTEGER NOT NULL,
        `id` INTEGER NOT NULL,
        `published` STRING,
        `last_modified` STRING,
        `cvss_score` STRING,
        `cvss_access_vector` STRING,
        `cvss_access_complexity` STRING,
        `cvss_authentication` STRING,
        `cvss_integrity_impact` STRING,
        `cvss_source` STRING,
        `cvss_generated` STRING,
        `cwe` STRING,
        `summary` STRING,
        UNIQUE (`year`, `id`)
    );
    CREATE INDEX IF NOT EXISTS `cve_year` ON `cve`(`year`);
    CREATE INDEX IF NOT EXISTS `cve_cvss_score` ON `cve`(`cvss_score`);
    CREATE INDEX IF NOT EXISTS `cve_cwe` ON `cve`(`cwe`);

    CREATE TABLE IF NOT EXISTS `cve_cpe` (
        `id_cve` INTEGER NOT NULL,
        `id_cpe` INTEGER NOT NULL,
        FOREIGN KEY(`id_cve`) REFERENCES `cve`(`rowid`) ON DELETE CASCADE,
        FOREIGN KEY(`id_cpe`) REFERENCES `cpe`(`rowid`) ON DELETE CASCADE,
        UNIQUE(`id_cve`, `id_cpe`)
    );

    CREATE TABLE IF NOT EXISTS `cve_references` (
        `id_cve` INTEGER NOT NULL,
        `url` STRING NOT NULL,
        FOREIGN KEY(`id_cve`) REFERENCES `cve`(`rowid`) ON DELETE CASCADE
    );
    """


    def __init__(self, db_file = None):

        # If no filename is given, use the default.
        if not db_file:
            db_file = self.DEFAULT_DB_FILE

        # Create the lock to make this class thread safe.
        self.__lock = RLock()

        # The busy flag prevents reentrance.
        self.__busy = False

        # Determine if the database existed.
        is_new = not exists(db_file)

        # Open the database file.
        self.__db = sqlite3.connect(db_file)

        # Populate the database on the first run.
        # On error delete the database and raise an exception.
        try:
            if is_new:
                self.update()
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


    # Create the database schema.
    @transactional
    def __create_schema(self):
        self.__cursor.executescript(self.SCHEMA)

    # If the XML file is missing, broken or older, download it.
    # This method assumes it's being called from within an open transaction.
    def __download(self, base_url, xml_file):

        # HTTP request to make.
        req = Request(base_url + xml_file)

        # Get the last modified time from the database if available.
        self.__cursor.execute(
            "SELECT `last_modified` FROM `files`"
            " WHERE `filename` = ? LIMIT 1;",
            (xml_file,)
        )
        row = self.__cursor.fetchone()
        if row:
            db_time = row[0]
        else:
            db_time = None

        # Also try looking for the file locally.
        # If found but can't be read, delete it.
        if exists(xml_file):
            try:
                xml_parser = etree.iterparse(
                    xml_file, events=("start", "end"))
                local_time = getmtime(xml_file)
            except Exception:
                xml_parser = None
                local_time = None
                unlink(xml_file)
        else:
            xml_parser = None
            local_time = None

        # Use the local file if newer or not yet loaded in the database.
        if local_time and (not db_time or local_time > db_time):
            return xml_parser

        # Otherwise, download the file if newer or not yet loaded.
        if db_time:
            req.add_header(
                "If-Modified-Since",            # -1 minute to compensate
                asctime(gmtime(db_time - 3600)) # possible timing errors
            )
        try:
            src = urlopen(req)
            downloaded = True
        except HTTPError, e:
            if not db_time or e.code != 304:
                raise
            downloaded = False
        if downloaded:
            try:
                with open(xml_file, "wb") as dst:
                    copyfileobj(src, dst)
            except:
                unlink(xml_file)
                raise
            xml_parser = None # free memory before using more
            xml_parser = etree.iterparse(
                xml_file, events=("start", "end"))
        return xml_parser

    # Save the timestamp for this file and delete it.
    # This method assumes it's being called from within an open transaction.
    def __finished_downloading(self, filename):
        self.__cursor.execute(
            "INSERT INTO `files` VALUES (?, ?);",
            (filename, getmtime(filename))
        )
        unlink(filename)

    @transactional
    def __load_cpe(self):

        # Download and open the XML file.
        xml_file   = self.CPE_XML_FILE
        xml_parser = self.__download(self.CPE_URL_BASE, xml_file)

        # Do we need to load new data?
        if xml_parser:

            # Delete the old data.
            self.__cursor.execute("DELETE FROM `cpe`;")

            # Parse the XML file and store the data into the database.
            prefix20 = "{http://cpe.mitre.org/dictionary/2.0}"
            prefix23 = "{http://scap.nist.gov/schema/cpe-extension/2.3}"
            prefixns = "{http://www.w3.org/XML/1998/namespace}"
            context  = iter(xml_parser)
            _, root  = context.next()
            main_tag = prefix20 + "cpe-item"
            for event, item in context:
                if event != "end" or item.tag != main_tag:
                    continue
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

            # Save the timestamp for this file and delete it.
            self.__finished_downloading(xml_file)

    @transactional
    def __load_cve(self, year):

        # Determine if we already have CVE data for this year.
        self.__cursor.execute(
            "SELECT COUNT(`rowid`) FROM `cve` WHERE `year` = ? LIMIT 1;",
            (year,)
        )
        db_is_empty = not bool(self.__cursor.fetchone()[0])

        # Download and open the XML file for this year.
        xml_file = self.CVE_XML_FILE % year
        root, downloaded = self.__download(
            self.CVE_URL_BASE, xml_file,
            always_open = db_is_empty)

        # Do we need to load new data?
        if downloaded or db_is_empty:

            # Delete the old data.
            self.__cursor.execute(
                "DELETE FROM `cve` WHERE `year` = ?;"
                (year,)
            )

            # Parse the XML file and store the data into the database.


            raise NotImplementedError()



            # Save the timestamp for this file.
            self.__finished_downloading(xml_file)

        # Delete the file.
        unlink(xml_file)


    def update(self):
        """
        Update the database.

        This automatically downloads up-to-date XML files from NIST when needed
        and recreates the database from them.
        """

        # Create the database schema.
        self.__create_schema()

        # Load the CPE data.
        # This must be loaded before CVE because CVE references CPE.
        self.__load_cpe()

        # Load the CVE data for each year from 2002 until today.
        ##for year in xrange(2002, date.today().year + 1):
        ##    self.__load_cve( str(year) )

    @transactional
    def resolve_cpe(self, cpe, include_deprecated = True):
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
    def get_cpe_title(self, cpe):
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
    def search_cpe(self, **kwargs):
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

    with VulnerabilityDB() as db:
        db.update()
        for cpe in db.search_cpe(title=title, version=version, part="o", target_hw=target_hw):
            #print cpe
            print db.get_cpe_title(cpe)
