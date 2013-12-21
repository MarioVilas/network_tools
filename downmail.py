#!/usr/bin/env python
#-----------------------------------------------------------------------------#
# Copyright (c) 2011, Mario Vilas
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
#-----------------------------------------------------------------------------#
#
# KNOWN BUGS:
# * Fails to recognize new emails if some old emails were deleted
# * POP3 support is untested
# * May fail with Unicode filenames (not tested)
# * May fail with extremely large emails (not tested)
#
# TO DO:
# * Find a way to refer to emails other than the index, which seems to be
#   relative at least in IMAP. :(
# * Understand the different types of mailboxes in IMAP to know which ones we
#   can select and which we can't.
# * Detect duplicate emails by hashing the data (this would be useful for GMail
#   where tags are mapped as mailboxes and there tend to be many duplicates).
# * Add commands to list mailboxes and emails in the server instead of
#   downloading them, and to download the headers only.
# * Granular error handling (on error skip to next mail / mailbox / target).
# * Retry downloads N times on network errors for each host.
# * Add support to just specify the mail address, not the server or protocol,
#   and have it autodetect everything. The default URL scheme would change from
#   imaps:// to mailto:// and possibly a DNS library would be needed, although
#   it'd be useful to bruteforce the MX too, and/or have a predefined list for
#   the most common email providers.
# * Add support for configuration files.
# * Add support for URL fragments (to download a single email, or a range).
# * Maybe allow specifying multiple mailboxes in the same URL?
# * Implement own support for POP3 and IMAP so emails can be downloaded in
#   chunks rather than trying to store the entire content on memory.
# * Optimize the database?
# * Documentation!
#
#-----------------------------------------------------------------------------#

__all__ = [

    # Main class
    'Main',

    # Worker classes
    'MailDownloader',
    'POP3Downloader',
    'IMAPDownloader',

    # Database access classes
    'Database',
    'MailDao',

    # Helper classes
    'AutoCloseable',
    'Target',

    ]

import os
import sys
import errno
import socket
import imaplib
import poplib
import urlparse
import optparse
import getpass
import traceback

# Since we're not using the HTTP features of urllib,
# we can import either of the two versions
try:
    import urllib2 as urllib
except ImportError:
    import urllib

# Don't use sqlite 2, we need foreign key constraints.
# If we *absolutely* can't use sqlite 3 maybe we could
# emulate them using triggers, but it'd be a mess. :P
# Also sqlite 3 supports file locking and sqlite 2 doesn't.
import sqlite3

try:
    from psyco.classes import *
except ImportError:
    pass

###############################################################################

class AutoCloseable(object):

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        try:
            self.close()
        except Exception:
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def close(self):
        raise NotImplementedError

###############################################################################

class MailDownloader(AutoCloseable):
    "Base class for mail downloaders. Do not instance."

    def __init__(self, server, port=None, use_ssl=False, debuglevel=0):
        """
        @type server: str
        @type port: int
        @type use_ssl: bool
        @type debuglevel: int
        @param server: IP address or hostname for the server.
        @param port: Optional, port number for the server.
        @param use_ssl: True to use SSL, False for plain TCP connection.
        @param debuglevel: Debug log level.
        """
        raise NotImplementedError

    def login(self, user, password):
        """Login to the server.
        @type user: str
        @type password: str
        @param user: Username.
        @param password: Password.
        """
        raise NotImplementedError

    def get_list(self, mailbox=None):
        """Get list of available emails.
        @type mailbox: str
        @param mailbox: Optional, mailbox to enumerate.
        @rtype: list(int)
        @return: List of email numbers to pass to L{get_mail}.
        """
        raise NotImplementedError

    def get_mail(self, num):
        """Get the contents of an email given it's number.
        @type num: int
        @param num: Email number.
        @rtype: str
        @return: Email contents (MIME envelope).
        """
        raise NotImplementedError

    def close(self):
        "Close the connection."
        raise NotImplementedError

class POP3Downloader(MailDownloader):
    "POP3 email downloader."

    def __init__(self, server, port=None, use_ssl=False, debuglevel=0):
        if use_ssl:
            if not port:
                port = 995
            clazz = poplib.POP3_SSL
        else:
            if not port:
                port = 110
            clazz = poplib.POP3
        self.__pop = clazz(server, port)
        self.__pop.set_debuglevel(debuglevel)

    def login(self, user, password):
        self.__pop.user(user)
        self.__pop.pass_(password)

    def get_list(self, mailbox=None):
        if mailbox:
            raise NotImplementedError
        return [int(x.split(' ')[0]) for x in self.__pop.list()[1]]

    def get_mail(self, num):
        return '\n'.join(self.__pop.retr(str(num))[1])

    def close(self):
        self.__pop.quit()

class IMAPDownloader(MailDownloader):
    "IMAP email downloader."

    def __init__(self, server, port=None, use_ssl=False, debuglevel=0):
        if use_ssl:
            if not port:
                port = 993
            clazz = imaplib.IMAP4_SSL
        else:
            if not port:
                port = 143
            clazz = imaplib.IMAP4
        if debuglevel:
            prev = imaplib.Debug
            imaplib.Debug = debuglevel
        self.__imap = clazz(server, port)
        if debuglevel:
            imaplib.Debug = prev

    def login(self, user, password):
        self.__imap.login(user, password)

    def get_mailboxes(self):
        typ, data = self.__imap.list()
        mailboxes = []
        for item in data:
            q = item.rfind('"')
            p = item.rfind('"', 0, q - 1) + 1
            if p >= 0 and q >= 0:
                mailboxes.append(item[p:q])
        mailboxes.sort()
        return mailboxes

    def get_list(self, mailbox=None):
        if mailbox:
            typ, data = self.__imap.select(mailbox, readonly=True)
            if typ != 'OK':
                raise self.__imap.error("Mailbox not found: %r" % mailbox)
        typ, data = self.__imap.search(None, 'ALL')
        if typ != 'OK':
            msg = "Error fetching message list from mailbox: %r" % mailbox
            raise self.__imap.error(msg)
        return [int(x) for x in data[0].split()]

    def get_mail(self, num):
        typ, data = self.__imap.fetch(str(num), '(RFC822)')
        return data[0][1]

    def close(self):
        try:
            self.__imap.close()
        finally:
            self.__imap.shutdown()

###############################################################################

class Database(AutoCloseable):

    def __init__(self, dbfile):
        self.dbfile = dbfile
        self.db = None
        self.open()

    def open(self):
        self.close()
        self.db = sqlite3.connect(self.dbfile)

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

class MailDAO(object):

    class __Query(object):
        init_script = """

PRAGMA locking_mode = EXCLUSIVE;
PRAGMA synchronous = OFF;
PRAGMA auto_vacuum = NONE;

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS host (
    id INTEGER PRIMARY KEY NOT NULL,
    proto TEXT NOT NULL,
    user TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mailbox (
    id INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mail (
    id INTEGER PRIMARY KEY NOT NULL,
    host INTEGER NOT NULL,
    mailbox INTEGER DEFAULT NULL,
    idx INTEGER NOT NULL,
    file TEXT NOT NULL,
    FOREIGN KEY(host) REFERENCES host(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    FOREIGN KEY(mailbox) REFERENCES mailbox(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);
        """

        vacuum = "VACUUM;"
        integrity_check = "PRAGMA integrity_check;"
        quick_check = "PRAGMA quick_check;"

        add_host = "INSERT INTO host VALUES (NULL, ?, ?, ?, ?);"
        get_host_id = """
            SELECT id FROM host
            WHERE proto = ? AND user = ? AND host = ? AND port = ?;
            """

        add_mailbox = "INSERT INTO mailbox VALUES (NULL, ?);"
        get_mailbox_id = "SELECT id FROM mailbox WHERE name = ?;"

        add_mail = "INSERT INTO mail VALUES (NULL, ?, ?, ?, ?);"
        get_mail_id = """
            SELECT id FROM mail
            WHERE host = ? AND mailbox = ? AND idx = ? AND file = ?;
            """

        get_mail = """
            SELECT host.proto, host.user, host.host, host.port,
                   mailbox.name,
                   mail.idx, mail.file
            FROM host, mailbox, mail
            WHERE mail.host = host.id AND
                  mail.mailbox = mailbox.id AND
                  mail.id = ?;
        """

        del_mail = "DELETE FROM mail WHERE id = ?;"

        get_indexes = """
            SELECT idx FROM mail
            WHERE host = ? AND mailbox = ?;
        """

        list_all_mails = """
            SELECT mail.id,
                   host.proto, host.user, host.host, host.port,
                   mailbox.name,
                   mail.idx, mail.file
            FROM host, mailbox, mail
            WHERE mail.host = host.id AND mail.mailbox = mailbox.id
            ORDER BY host.host, host.user, mailbox.name, mail.idx;
        """

    def __init__(self, db):
        self._db = db
        self._db.executescript(self.__Query.init_script)
        self._db.commit()

    def get_indexes(self, target):
        indexes = []
        id_host = self.__get_host_id(target.proto, target.user,
                                     target.host, target.port)
        if id_host is not None:
            if target.mailbox is None:
                id_mailbox = None
            else:
                id_mailbox = self.__get_mailbox_id(target.mailbox)
            indexes = self.__get_indexes(id_host, id_mailbox)
        return indexes

    @staticmethod
    def __fetch_one_value(cursor):
        try:
            return cursor.fetchall()[0][0]
        except IndexError:
            return None
        except TypeError:
            return None

    def __get_indexes(self, id_host, id_mailbox):
        cursor = self._db.cursor()
        cursor.execute(self.__Query.get_indexes, (id_host, id_mailbox,))
        rows = cursor.fetchall()
        if rows:
            indexes = [x[0] for x in rows]
        else:
            indexes = []
        return indexes

    def __get_host_id(self, proto, user, host, port):
        cursor = self._db.cursor()
        cursor.execute(self.__Query.get_host_id, (proto, user, host, port))
        return self.__fetch_one_value(cursor)

    def __get_mailbox_id(self, mailbox):
        cursor = self._db.cursor()
        cursor.execute(self.__Query.get_mailbox_id, (mailbox,))
        return self.__fetch_one_value(cursor)

    def add(self, target, index, filename):
        cursor = self._db.cursor()
        try:
            id_host = self.__add_host(cursor,
                        target.proto, target.user, target.host, target.port)
            id_mailbox = self.__add_mailbox(cursor, target.mailbox)
            id_mail = self.__add_mail(cursor, id_host, id_mailbox,
                                      index, filename)
            self._db.commit()
            return id_mail
        except:
            self._db.rollback()
            raise

    def __add_host(self, cursor, proto, user, host, port):
        args = (proto, user, host, port)
        cursor.execute(self.__Query.get_host_id, args)
        id = self.__fetch_one_value(cursor)
        if id:
            return id
        cursor.execute(self.__Query.add_host, args)
        return cursor.lastrowid

    def __add_mailbox(self, cursor, mailbox):
        cursor.execute(self.__Query.get_mailbox_id, (mailbox,))
        id = self.__fetch_one_value(cursor)
        if id:
            return id
        cursor.execute(self.__Query.add_mailbox, (mailbox,))
        return cursor.lastrowid

    def __add_mail(self, cursor, id_host, id_mailbox, index, filename):
        args = (id_host, id_mailbox, index, filename)
        cursor.execute(self.__Query.get_mail_id, args)
        id = self.__fetch_one_value(cursor)
        if id:
            return id
        cursor.execute(self.__Query.add_mail, args)
        return cursor.lastrowid

    def items(self):
        cursor = self._db.cursor()
        cursor.execute(self.__Query.list_all_mails)
        return cursor.fetchall()

    def __iter__(self):
        cursor = self._db.cursor()
        cursor.execute(self.__Query.list_all_mails)
        while 1:
            row = cursor.fetchone()
            if row:
                yield row
            else:
                break

    def get(self, id):
        cursor = self._db.cursor()
        cursor.execute(self.__Query.get_mail, (id,))
        return cursor.fetchone()

    def delete(self, id):
        try:
            self._db.execute(self.__Query.del_mail, (id,))
            self._db.commit()
        except:
            self._db.rollback()
            raise

    def vacuum(self):
        try:
            self._db.execute(self.__Query.vacuum, ())
            self._db.commit()
        except:
            self._db.rollback()
            raise

###############################################################################

class Target(object):

    __proto = {
        'pop3'  : 110,
        'imap'  : 143,
        'pop3s' : 995,
        'imaps' : 993,
    }

    def __init__(self, proto, user, password, host, port, mailbox):
        self.proto    = proto
        self.user     = user
        self.password = password
        self.host     = host
        self.port     = port
        self.mailbox  = mailbox

    def __str__(self):
        if self.password:
            netloc = '%s:%s@%s:%s' % (
                urllib.quote(self.user),
                urllib.quote(self.password),
                urllib.quote(self.host),
                str(self.port),
            )
        else:
            netloc = '%s@%s:%s' % (
                urllib.quote(self.user),
                urllib.quote(self.host),
                str(self.port),
            )
        if self.mailbox:
            data = (
                urllib.quote(self.proto),
                netloc,
                urllib.quote(self.mailbox),
                '',
                '',
                ''
            )
        else:
            data = (
                urllib.quote(self.proto),
                netloc,
                '',
                '',
                '',
                ''
            )
        return urlparse.urlunparse(data)

    def __repr__(self):
        msg = \
         '<%s at 0x%x: proto %r, user %r, pass %r, host %r, port %r, mailbox %r>'
        return msg % (
            self.__class__.__name__, id(self),
            self.proto,
            self.user,
            self.password,
            self.host,
            self.port,
            self.mailbox
            )

    def toTuple(self):
        return (
            self.proto,
            self.user,
            self.password,
            self.host,
            self.port,
            self.mailbox
            )

    def __eq__(self, other):
        return self.toTuple() == other.toTuple()

    def __ne__(self, other):
        return not self == other

    def __gt__(self, other):
        return NotImplemented

    def __lt__(self, other):
        return NotImplemented

    def __ge__(self, other):
        #if self == other:
        #    return True
        return NotImplemented

    def __le__(self, other):
        #if self == other:
        #    return True
        return NotImplemented

    def __hash__(self):
        return hash(self.toTuple())

    @classmethod
    def parse(cls, token):
        if '://' not in token: # urllib can't handle a missing scheme
            token = 'imaps://%s' % token
        url = urlparse.urlparse(token, allow_fragments = False)
        if url.params:
            raise optparse.OptParseError("URL parameters not supported")
        if url.query:
            raise optparse.OptParseError("URL arguments not supported")
        if url.fragment:
            raise optparse.OptParseError("URL fragments not supported")
        proto = urllib.unquote(url.scheme).lower()
        if proto.endswith('://'):
            proto = proto[:-3]
        try:
            defport = cls.__proto[proto]
        except KeyError:
            raise optparse.OptParseError("Protocol not supported: %s" % proto)
        mailbox = urllib.unquote(url.path)
        if mailbox.startswith('/'):
            mailbox = mailbox[1:]
        if not mailbox:
            mailbox = None
        elif proto not in ('imap', 'imaps'):
            raise optparse.OptParseError("Mailbox names only supported for IMAP")
        netloc = url.netloc
        if '@' in netloc:
            userpass, hostport = netloc.split('@')
            if ':' in userpass:
                user, password = userpass.split(':')
                user = urllib.unquote(user)
                password = urllib.unquote(password)
            else:
                user = urllib.unquote(userpass)
                password = None
        else:
            user = getpass.getuser()
            password = None
            hostport = netloc
        if ':' in hostport:
            host, port = hostport.split(':')
            host = urllib.unquote(host)
            port = int(urllib.unquote(port))
        else:
            host = urllib.unquote(hostport)
            port = defport
        if not host:
            host = 'localhost'
        return Target(proto, user, password, host, port, mailbox)

class Main(object):

    # Characters not allowed in filenames
    _invalid_chars = '\\/:*?"<>|'

    # Safe character to replace invalid characters with
    _safe_char = '_'

    def run(self, argv=None):
        if argv is None:
            argv = sys.argv
        (parser, options, targets) = self._parse(argv)

        try:
            os.makedirs(options.repository)
        except OSError:
            pass
        if not os.path.isdir(options.repository):
            parser.error("No such directory: %s" % options.repository)

        dbfile = os.path.join(options.repository, 'sqlite.db')
        #try:
        #    open(dbfile, 'wb').close()  # "touch"
        #except Exception:
        #    parser.error("Can't access file: %s" % dbfile)

        if options.timeout is not None:
            prev_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(options.timeout)

        with Database(dbfile) as db:
            dao = MailDAO(db.db)
            try:
                if options.list:
                    self.list(dao, options)
                elif options.cleanup:
                    self.cleanup(dao, options)
                else:
                    self.download(targets, dao, options)
            finally:
                dao.vacuum()

        if options.timeout is not None:
            socket.setdefaulttimeout(prev_timeout)

    def list(self, dao, options):
        for id, proto, user, host, port, mailbox, index, filename in dao:
            self._print(proto, user, host, port, mailbox, index, filename)

    def _print(self, proto, user, host, port, mailbox, index, filename):
        target = Target(proto, user, None, host, port, mailbox)
        print
        print "URL:\t%s" % target
        print "Index:\t%d" % index
        print "File:\t%s\n" % filename

    def cleanup(self, dao, options):
        items = dao.items()
        for id, proto, user, host, port, mailbox, index, filename in items:
            if not os.path.exists(filename):
                if options.verbose:
                    self._print(
                            proto, user, host, port, mailbox, index, filename)
                dao.delete(id)

    def download(self, targets, dao, options):
        while targets:
            target = targets.pop()
            try:
                if options.verbose:
                    print "Connecting to %s:%d..." % (target.host, target.port)
                with self._get_downloader(target, options) as downloader:
                    self._login(downloader, target, options)
                    while 1:

                        if target.mailbox is not None:
                            list_of_mailboxes = [target.mailbox]
                        else:
                            try:
                                list_of_mailboxes = downloader.get_mailboxes()
                                if options.verbose:
                                    print "Found %d mailboxes:" % len(list_of_mailboxes)
                                    for mailbox in list_of_mailboxes:
                                        print "\t%s" % mailbox
                            except NotImplementedError:
                                list_of_mailboxes = [None]

                        for target.mailbox in list_of_mailboxes:
                            try:
                                self._download_mailbox(downloader, target, dao, options)
                            except Exception, e:
                                #raise                                           # XXX DEBUG
                                msg = "Error downloading mailbox %s: %s\n" % (target.mailbox, e)
                                sys.stderr.write(msg)

                        if targets:
                            next = targets[0]
                            if  (
                                next.host  == target.host  and
                                next.port  == target.port  and
                                next.proto == target.proto and
                                next.user  == target.user  and
                                (
                                    next.password == target.password or
                                    next.password is None
                                )
                            ):
                                target = next
                                continue
                        break

            except Exception, e:
                #raise                                                           # XXX DEBUG
                msg = "Error processing target %s: %s\n" % (target, str(e))
                sys.stderr.write(msg)

    def _download_mailbox(self, downloader, target, dao, options):
            if options.verbose:
                if target.mailbox is None:
                    msg = "Fetching list of emails..."
                else:
                    msg = "Listing mailbox %r..."
                    msg = msg % target.mailbox
                print msg
                del msg
            indexes = self._get_list(downloader, target, dao, options.verbose)
            total = len(indexes)
            count = 1
            for index in indexes:
                if options.verbose:
                    print "Fetching email #%d (%d of %d)..." % (index, count, total)
                count += 1
                data = downloader.get_mail(index)
                filename = self._calc_filename(target, index)
                try:
                    os.makedirs(os.path.dirname(filename))
                except OSError:
                    pass
                self._save(filename, data)
                del data
                dao.add(target, index, filename)

    @staticmethod
    def _get_downloader(target, options):
        debuglevel = options.debug
        if debuglevel is None:
            debuglevel = 0
        elif debuglevel < 0:
            debuglevel = 0
        proto, host, port = target.proto, target.host, target.port
        if proto == 'pop3':
            downloader = POP3Downloader(host, port, False, debuglevel)
        elif proto == 'pop3s':
            downloader = POP3Downloader(host, port, True, debuglevel)
        elif proto == 'imap':
            downloader = IMAPDownloader(host, port, False, debuglevel)
        elif proto == 'imaps':
            downloader = IMAPDownloader(host, port, True, debuglevel)
        else:
            raise AssertionError("Unknown protocol: %r" % proto)
        return downloader

    @staticmethod
    def _login(downloader, target, cache=True):
        password = target.password
        if password is None:
            #prompt = 'Password for %s: ' % target
            prompt = 'Password for %s at %s: ' % (target.user, target.host)
            password = getpass.getpass(prompt)
            if not password:
                password = None
        downloader.login(target.user, password)
        if cache:
            target.password = password

    @staticmethod
    def _get_list(downloader, target, dao, verbose):
        server_indexes = set(downloader.get_list(target.mailbox))
        total_count = len(server_indexes)
        local_indexes = set(dao.get_indexes(target))
        server_indexes.difference_update(local_indexes)
        del local_indexes
        indexes = list(server_indexes)
        indexes.sort()
        if verbose:
            msg = "Found %d new emails (from a total of %d)"
            print msg % (len(indexes), total_count)
        return indexes

    @classmethod
    def _calc_filename(cls, target, index):
        host = cls._sanitize(target.host)
        user = cls._sanitize(target.user)
        mailbox = cls._sanitize(target.mailbox)
        index = str(index)
        slash = os.path.sep
        dot = os.path.extsep
        ext = 'eml'
        if mailbox:
            items = (host, slash, user, slash, mailbox, slash, index, dot, ext)
        else:
            items = (host, slash, user, slash, index, dot, ext)
        return ''.join(items)

    @classmethod
    def _sanitize(cls, name):
        if name:
            s = cls._safe_char
            for c in cls._invalid_chars:
                name = name.replace(c, s)
            if name.strip() != name:
                name = urllib.quote(name)
        return name

    def _save(self, filename, data):
        index = 0
        path, name = os.path.split(filename)
        name, ext = os.path.splitext(name)
        fdst = None
        must_delete = False
        try:
            fdst = self._create_file_exclusive(filename, silent=True)
            while not fdst:
                index = index + 1
                new_name = '%s (%d)%s' % (name, index, ext)
                filename = os.path.join(path, new_name)
                fdst = self._create_file_exclusive(filename, silent=True)
            must_delete = True
            fdst.write(data)
            must_delete = False
        finally:
            if fdst:
                fdst.close()
            if must_delete:
                os.unlink(filename)
        return filename

    # Create a file if and only if it didn't exist previously
    def _create_file_exclusive(self, filename, silent=True):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            flags = flags | os.O_BINARY
        except AttributeError:
            pass
        fd = None
        try:
            try:
                fd = os.open(filename, flags, 0666)
            except OSError, e:
                if not silent or e.errno != errno.EEXIST:
                    raise
            if fd is not None:
                return os.fdopen(fd, 'wb')
        except:
            if fd is not None:
                try:
                    os.close(fd)
                finally:
                    os.unlink(filename)
            raise

    @staticmethod
    def _parse(argv):
        basedir = os.path.dirname(os.path.abspath(__file__))
        if not basedir:
            basedir = os.path.abspath(os.path.curdir)

        #name = os.path.split(os.path.basename(__file__))[0]
        #defconf = os.path.join(basedir, '%s.conf' % name)

        usage = "%prog [options] [servers...]"
        epilog = """Servers are specified in URL format:

    proto://user:pass@host:port/mailbox

Where all components are optional. Only the IMAP protocol supports mailboxes.
The default protocol is IMAP over SSL. The default username is the current
user and the default host is localhost. If no mailbox is specified for IMAP,
all mails in all mailboxes will be downloaded. If the username contains a "@"
you have to urlescape it as "%40".

This is an example of making a full backup of a Gmail account:
    %prog imaps://user%40gmail.com@imap.gmail.com

Note that for Gmail you'll probably want to enable the "Chat" label on IMAP,
otherwise chats won't be backed up. You may also want to disable your custom
labels, as they will be made redundant by the "All Mail" label. Also, labels in
Gmail are language-dependent, "All Mail" may be called something else.

Be careful when enabling the debug log, passwords will be shown on screen!
"""

        parser = optparse.OptionParser(
            usage=usage, epilog=epilog, formatter=CustomFormatter())
        parser.epilog = parser.epilog.replace("%prog", parser.get_prog_name())
        parser.add_option("-l", "--list", action="store_true",
                          help="list all downloaded mails and quit")
        parser.add_option("--cleanup", action="store_true",
                          help="clean up the database and quit")
        parser.add_option("-r", "--repository", metavar="FOLDER",
                          help="use FOLDER as local repository [default: %s]" % basedir)
        #parser.add_option("-c", "--config", metavar="FILE",
        #                  help="read settings from FILE [default: %s]" % defconfig)
        parser.add_option("-t", "--timeout", metavar="N", type="float",
                          help="set socket timeout to N seconds [default: %s]" % socket.getdefaulttimeout())
        parser.add_option("--no-timeout", dest="timeout", action="store_const", const=None,
                          help="disable the socket timeout")
        parser.add_option("--debug", action="count", default=0,
                          help="increment debug log level by 1 [default: 0]")
        parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=True,
                          help="verbose mode")
        parser.add_option("-q", "--quiet", dest="verbose", action="store_false",
                          help="quiet mode")
        (options, args) = parser.parse_args()

        if options.list and options.cleanup:
            parser.error("can't use --list and --cleanup at the same time")

        #if options.list and options.config:
        #    parser.error("can't use --list and --config at the same time")

        #if options.cleanup and options.config:
        #    parser.error("can't use --cleanup and --config at the same time")

        if options.list and args:
            parser.error("can't use --list and a list of servers at the same time")

        if options.cleanup and args:
            parser.error("can't use --cleanup and a list of servers at the same time")

        #if options.config and args:
        #    parser.error("can't use --config and a list of servers at the same time")

        if not options.repository:
            options.repository = basedir

        #if not args and not options.config:
        #    options.config = defconfig
        #    if not os.path.exists(options.config):
        #        parser.error("no targets")

        if not args and not options.list and not options.cleanup:
            parser.parse_args(['--help'])

        targets = set()
        for token in args:
            try:
                target = Target.parse(token)
                if target not in targets:
                    targets.add(target)
                elif options.verbose:
                    print "Skipped duplicate target: %s" % token
            except optparse.OptParseError, e:
                parser.error(e.msg)
            except Exception:
                parser.error("Error parsing token: %s" % token)

        return (parser, options, sorted(targets, key=lambda t: t.host))

###############################################################################

class CustomFormatter(optparse.IndentedHelpFormatter):
    def format_epilog(self, epilog):
        if epilog:
            return "\n" + epilog
        else:
            return ""

###############################################################################

if __name__ == '__main__':
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    try:
        Main().run()
    except KeyboardInterrupt:
        print "Operation interrupted by the user!"
