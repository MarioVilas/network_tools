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


def transactional(fn):
    def wrapper(self, *args, **kwargs):
        return self._transaction(fn, args, kwargs)
    return wrapper


class CVEDB(object):
    """
    CVE database.

    Generated from the XML files mantained by NIST:
    https://nvd.nist.gov/download.cfm#CVE_FEED
    """

    # Set to False to suppress prints
    DEBUG = True

    # Default database filename.
    DEFAULT_DB_FILE = "nvdcve-2.0.db"

    # CVE data URL base and XML files. Order is important!
    CVE_URL_BASE = "http://static.nvd.nist.gov/feeds/xml/cve/"
    CVE_XML_FILES = [
        "nvdcve-2.0-%s.xml" % year
        for year in xrange(2002, date.today().year + 1)
    ]
    CVE_XML_FILES.append("nvdcve-2.0-modified.xml")
    CVE_XML_FILES.append("nvdcve-2.0-recent.xml")
    CVE_XML_FILES = tuple(CVE_XML_FILES)

    # Vendor statements URL base and XML file.
    VENDOR_URL_BASE = "https://nvd.nist.gov/download/"
    VENDOR_XML_FILE = "vendorstatements.xml"

    # Database schema creation script.
    SCHEMA = \
    """
    PRAGMA foreign_keys = ON;
    PRAGMA auto_vacuum = NONE;

    ---------------------
    -- File timestamps --
    ---------------------

    CREATE TABLE IF NOT EXISTS `files` (
        `filename` STRING NOT NULL UNIQUE ON CONFLICT REPLACE,
        `last_modified` INTEGER NOT NULL,
        `last_modified_string` STRING NOT NULL
    );

    ---------
    -- CVE --
    ---------

    CREATE TABLE IF NOT EXISTS `cve` (
        `rowid` INTEGER PRIMARY KEY,
        `year` INTEGER NOT NULL,
        `number` INTEGER NOT NULL,
        `cvss_score` STRING,
        `cvss_access_vector` STRING,
        `cvss_access_complexity` STRING,
        `cvss_authentication` STRING,
        `cvss_integrity_impact` STRING,
        `cwe` STRING,
        `summary` STRING,
        UNIQUE (`year`, `number`)
    );
    CREATE INDEX IF NOT EXISTS `cve_year` ON `cve`(`year`);
    CREATE INDEX IF NOT EXISTS `cve_cvss_score` ON `cve`(`cvss_score`);
    CREATE INDEX IF NOT EXISTS `cve_cwe` ON `cve`(`cwe`);

    CREATE TABLE IF NOT EXISTS `cve_cpe_names` (
        `rowid` INTEGER PRIMARY KEY,
        `cpe_name` STRING NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS `cve_cpe` (
        `id_cve` INTEGER NOT NULL,
        `id_cpe` INTEGER NOT NULL,
        FOREIGN KEY(`id_cve`) REFERENCES `cve`(`rowid`) ON DELETE CASCADE,
        FOREIGN KEY(`id_cpe`) REFERENCES `cve_cpe_names`(`rowid`) ON DELETE CASCADE,
        UNIQUE (`id_cve`, `id_cpe`) ON CONFLICT IGNORE
    );

    CREATE TABLE IF NOT EXISTS `cve_ref_urls` (
        `rowid` INTEGER PRIMARY KEY,
        `url` STRING NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS `cve_references` (
        `id_cve` INTEGER NOT NULL,
        `id_ref` INTEGER NOT NULL,
        FOREIGN KEY(`id_cve`) REFERENCES `cve`(`rowid`) ON DELETE CASCADE,
        FOREIGN KEY(`id_ref`) REFERENCES `cve_ref_urls`(`rowid`) ON DELETE CASCADE,
        UNIQUE (`id_cve`, `id_ref`) ON CONFLICT IGNORE
    );

    CREATE TABLE IF NOT EXISTS `cve_vendor_statements` (
        `id_cve` INTEGER NOT NULL,
        `contributor` STRING,
        `organization` STRING,
        `statement` STRING NOT NULL,
        FOREIGN KEY(`id_cve`) REFERENCES `cve`(`rowid`) ON DELETE CASCADE,
        UNIQUE (`id_cve`, `contributor`, `organization`) ON CONFLICT REPLACE
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


    def update(self):
        """
        Update the database.

        This automatically downloads up-to-date XML files from NIST when needed
        and recreates the database from them.
        """

        # Create the database schema.
        self.__create_schema()

        # Load the CVE data for each year from 2002 until today.
        # The order of this list is important! At the end of it
        # are the files with the most recent updates.
        for xml_file in self.CVE_XML_FILES:
            self.__load_cve_file(xml_file)

        # Load the vendor statements.
        self.__load_vendor_statements()

    @transactional
    def __create_schema(self):
        self.__cursor.executescript(self.SCHEMA)

    @transactional
    def __load_cve_file(self, xml_file):

        # Download and open the XML file.
        xml_parser = self.__download(self.CVE_URL_BASE, xml_file)

        # Do we need to load new data?
        if xml_parser:
            if self.DEBUG:
                print "Loading file: %s" % xml_file

            # Parse the XML file and store the data into the database.
            context  = iter(xml_parser)
            _, root  = context.next()
            for event, item in context:
                if event == "end" and item.tag.endswith("}entry"):
                    self.__load_cve_entry(item)
                    root.clear()

            # Delete the XML file.
            unlink(xml_file)
            if self.DEBUG:
                print "Deleted file: %s" % xml_file

    # This method assumes it's being called from within an open transaction.
    def __load_cve_entry(self, item):
        ns_v = "{http://scap.nist.gov/schema/vulnerability/0.4}"
        ns_c = "{http://scap.nist.gov/schema/cvss-v2/0.2}"
        ns_s = "{http://scap.nist.gov/schema/feed/vulnerability/2.0}"
        cvename = item.attrib["id"]
        assert cvename.startswith("CVE-"), cvename
        assert len(cvename) in (13, 14), cvename
        year = int(cvename[4:8])
        number = int(cvename[9:])
        has_cwe = item.find(".//%scwe" % ns_v)
        if has_cwe is not None:
            cwe = has_cwe.attrib["id"]
        else:
            cwe = None
        soft = item.find(".//%svulnerable-software-list" % ns_v)
        if soft is not None:
            products = [
                child.text
                for child in soft.iter("%sproduct" % ns_v)
            ]
        else:
            products = []
        cvss = item.find(".//%sbase_metrics" % ns_c)
        if cvss is not None:
            cvss_score = item.find(".//%sscore" % ns_c).text
            cvss_access_vector = item.find(".//%saccess-vector" % ns_c).text
            cvss_access_complexity = item.find(".//%saccess-complexity" % ns_c).text
            cvss_authentication = item.find(".//%sauthentication" % ns_c).text
            cvss_integrity_impact = item.find(".//%sintegrity-impact" % ns_c).text
        else:
            cvss_score             = None
            cvss_access_vector     = None
            cvss_access_complexity = None
            cvss_authentication    = None
            cvss_integrity_impact  = None
        references = []
        for refs in item.iter("%sreferences" % ns_v):
            references.extend(
                child.attrib["href"]
                for child in refs.iter("%sreference" % ns_v)
            )
        has_summary = item.find(".//%ssummary" % ns_v)
        if has_summary is not None:
            summary = has_summary.text
        else:
            summary = None
        self.__cursor.execute(
            "SELECT `rowid` FROM `cve`"
            " WHERE `year` = ? AND `number` = ? LIMIT 1;",
            (year, number)
        )
        has_cve_id = self.__cursor.fetchone()
        if has_cve_id:
            cve_id = has_cve_id[0]
            if summary is not None and \
               summary.startswith("** REJECT **"):
                if self.DEBUG:
                    print "Deleting %s..." % cvename
                self.__cursor.execute(
                    "DELETE FROM `cve` WHERE `rowid` = ?;",
                    (cve_id,)
                )
                return
            ##if self.DEBUG:
            ##    print "Updating %s..." % cvename
            self.__cursor.execute(
                "UPDATE `cve` SET"
                " `cvss_score` = ?,"
                " `cvss_access_vector` = ?,"
                " `cvss_access_complexity` = ?,"
                " `cvss_authentication` = ?,"
                " `cvss_integrity_impact` = ?,"
                " `cwe` = ?,"
                " `summary` = ?"
                " WHERE `rowid` = ?;",
                (cvss_score, cvss_access_vector,
                 cvss_access_complexity, cvss_authentication,
                 cvss_integrity_impact, cwe, summary, cve_id)
            )
        else:
            if summary is not None and \
               summary.startswith("** REJECT **"):
                return
            ##if self.DEBUG:
            ##    print "Adding %s..." % cvename
            self.__cursor.execute(
                "INSERT INTO `cve` VALUES (NULL, "
                "?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (year, number, cvss_score, cvss_access_vector,
                 cvss_access_complexity, cvss_authentication,
                 cvss_integrity_impact, cwe, summary)
            )
            cve_id = self.__cursor.lastrowid
        for ref in references:
            self.__cursor.execute(
                "SELECT `rowid` FROM `cve_ref_urls`"
                " WHERE `url` = ? LIMIT 1;",
                (ref,)
            )
            has_ref_id = self.__cursor.fetchone()
            if has_ref_id:
                ref_id = has_ref_id[0]
            else:
                self.__cursor.execute(
                    "INSERT INTO `cve_ref_urls` VALUES (NULL, ?);",
                    (ref,)
                )
                ref_id = self.__cursor.lastrowid
            self.__cursor.execute(
                "INSERT INTO `cve_references` VALUES (?, ?);",
                (cve_id, ref_id)
            )
        for cpe in products:
            self.__cursor.execute(
                "SELECT `rowid` FROM `cve_cpe_names`"
                " WHERE `cpe_name` = ? LIMIT 1;",
                (cpe,)
            )
            has_cpe_id = self.__cursor.fetchone()
            if has_cpe_id:
                cpe_id = has_cpe_id[0]
            else:
                self.__cursor.execute(
                    "INSERT INTO `cve_cpe_names` VALUES (NULL, ?);",
                    (cpe,)
                )
                cpe_id = self.__cursor.lastrowid
            self.__cursor.execute(
                "INSERT INTO `cve_cpe` VALUES (?, ?);",
                (cve_id, cpe_id)
            )

    @transactional
    def __load_vendor_statements(self):

        # Download and parse the vendor statements XML file.
        xml_file   = self.VENDOR_XML_FILE
        xml_parser = self.__download(self.VENDOR_URL_BASE, xml_file,
                                     big_file = False)

        # Do we need to load new data?
        if xml_parser:
            if self.DEBUG:
                print "Loading file: %s" % xml_file

            # Parse the XML file and store the data into the database.
            for item in xml_parser.iter("statement"):
                self.__load_vendor_statement_entry(item)

            # Delete the XML file.
            unlink(xml_file)
            if self.DEBUG:
                print "Deleted file: %s" % xml_file

    # This method assumes it's being called from within an open transaction.
    def __load_vendor_statement_entry(self, item):
        cvename      = item.attrib.get("cvename", None)
        contributor  = item.attrib.get("contributor", None)
        organization = item.attrib.get("organization", None)
        statement    = item.text
        year   = int(cvename[4:8])
        number = int(cvename[9:])
        self.__cursor.execute(
            "SELECT `rowid` FROM `cve`"
            " WHERE `year` = ? AND `number` = ? LIMIT 1;",
            (year, number)
        )
        has_cve = self.__cursor.fetchone()
        if not has_cve:
            if self.DEBUG:
                print "Warning: %s not in database!" % cvename
        else:
            cve_id = has_cve[0]
            self.__cursor.execute(
                "INSERT OR REPLACE INTO `cve_vendor_statements` VALUES "
                "(   ?,        ?,           ?,           ?    );",
                 (cve_id, contributor, organization, statement)
            )

    # If the XML file is missing, broken or older, download it.
    # This method assumes it's being called from within an open transaction.
    def __download(self, base_url, xml_file, big_file = True):

        # HTTP request to make.
        req = Request(base_url + xml_file)

        # Get the last modified time from the database if available.
        self.__cursor.execute(
            "SELECT `last_modified`, `last_modified_string` FROM `files`"
            " WHERE `filename` = ? LIMIT 1;",
            (xml_file,)
        )
        row = self.__cursor.fetchone()
        if row:
            db_time, db_time_str = row
        else:
            db_time = None
            db_time_str = None

        # Also try looking for the file locally.
        # If found but can't be read, delete it.
        if exists(xml_file):
            try:
                if big_file:
                    xml_parser = etree.iterparse(
                        xml_file, events=("start", "end"))
                else:
                    xml_parser = etree.parse(xml_file)
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
            if self.DEBUG:
                print "Found local file: %s" % xml_file
            self.__cursor.execute(
                "INSERT INTO `files` VALUES (?, ?, ?);",
                (xml_file, local_time, asctime(gmtime(local_time)))
            )
            return xml_parser

        # Otherwise, download the file if newer or not yet loaded.
        if db_time_str:
            req.add_header("If-Modified-Since", db_time_str)
        try:
            src = urlopen(req)
            downloaded = True
            db_time_str = src.info().get("Last-Modified", None)
        except HTTPError, e:
            if not db_time or e.code != 304:
                raise
            downloaded = False
            if self.DEBUG:
                print "Already up-to-date: %s" % xml_file
        if downloaded:
            if self.DEBUG:
                print "Downloading from: %s" % req.get_full_url()
            try:
                with open(xml_file, "wb") as dst:
                    copyfileobj(src, dst)
            except:
                unlink(xml_file)
                raise
            xml_parser = None # free memory before using more
            if big_file:
                xml_parser = etree.iterparse(
                    xml_file, events=("start", "end"))
            else:
                xml_parser = etree.parse(xml_file)
            if not db_time:
                db_time = getmtime(xml_file)
            if not db_time_str:
                db_time_str = asctime(gmtime(db_time))
            self.__cursor.execute(
                "INSERT INTO `files` VALUES (?, ?, ?);",
                (xml_file, db_time, db_time_str)
            )

            # Return the open XML file.
            return xml_parser


if __name__ == "__main__":

    is_new = not exists(CVEDB.DEFAULT_DB_FILE)
    with CVEDB() as db:
        if not is_new:
            db.update()
            pass
