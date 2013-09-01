import os
import os.path
import shutil
import sqlite3
import sys
import urllib2

try:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree

# Configuration.
url = "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml"
xml_file = "official-cpe-dictionary_v2.3.xml"
db_file = "official-cpe-dictionary_v2.3.db"

# Download the CPE dictionary.
if not os.path.exists(xml_file):
    print "Downloading: " + url
    src = urllib2.urlopen(url)
    with open(xml_file, "wb") as dst:
        shutil.copyfileobj(src, dst)

# Parse the XML file.
tree = etree.parse(xml_file)
root = tree.getroot()

# Convert the XML into a SQLite database.
if os.path.exists(db_file):
    os.unlink(db_file)
db = sqlite3.connect(db_file)
try:
    cursor = db.cursor()
    try:
        cursor.executescript(
            """
            CREATE TABLE cpe (
                id INTEGER PRIMARY KEY,
                name23 STRING UNIQUE NOT NULL,
                name22 STRING NOT NULL,
                deprecated INTEGER(1) NOT NULL DEFAULT 0
            );
            CREATE INDEX cpe_name22 ON cpe(name22);
            CREATE TABLE cpe_title (
                id_cpe INTEGER NOT NULL,
                lang STRING NOT NULL,
                title STRING NOT NULL,
                FOREIGN KEY(id_cpe) REFERENCES cpe(id)
            );
            CREATE INDEX cpe_title_lang ON cpe_title(lang);
            CREATE INDEX cpe_title_title ON cpe_title(title);
            """
        )
        gen = root.find(".//{http://cpe.mitre.org/dictionary/2.0}generator")
        print gen.find("{http://cpe.mitre.org/dictionary/2.0}product_name").text
        print gen.find("{http://cpe.mitre.org/dictionary/2.0}product_version").text
        print "CPE " + gen.find("{http://cpe.mitre.org/dictionary/2.0}schema_version").text
        print gen.find("{http://cpe.mitre.org/dictionary/2.0}timestamp").text
        for item in root.iter("{http://cpe.mitre.org/dictionary/2.0}cpe-item"):
            name22 = item.attrib["name"]
            name23 = item.find(".//{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item").attrib["name"]
            deprecated = int(item.attrib.get("deprecated", "false") == "true")
            titles = {
                t.attrib["{http://www.w3.org/XML/1998/namespace}lang"]: t.text
                for t in item.iter("{http://cpe.mitre.org/dictionary/2.0}title")
            }
            cursor.execute(
                "INSERT INTO cpe VALUES (NULL, ?, ?, ?);",
                (name23, name22, deprecated)
            )
            rowid = cursor.lastrowid
            for lang, title in sorted(titles.items()):
                cursor.execute(
                    "INSERT INTO cpe_title VALUES (?, ?, ?);",
                    (rowid, lang, title)
                )
    except:
        db.rollback()
        raise
    else:
        db.commit()
except:
    db.close()
    os.unlink(db_file)
    raise
else:
    db.close()
