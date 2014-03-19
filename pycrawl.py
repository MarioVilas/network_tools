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
# * fails with UNC paths and symlinks
# * some issues with GMT and non GMT times need to be ironed out
#
# TO DO LIST:
# * add filter by domain name
# * add filter by applying regular expressions to the URLs
# * have Crawler obey robots.txt (with an option to disable this feature)
# * possibly divide code into submodules if it grows too much
# * documentation! as soon as code begins to be more or less stable
# * find a name for the project, it's so lame not to have one :D
#
# FUTURE WORK:
# * add support for libcurl
# * replace anydbm with sqlite, it may optimize speed (or it may not!)
#
#-----------------------------------------------------------------------------#

"""Download manager and web crawler by Mario Vilas (mvilas at gmail dot com)

Distributed under BSD licence.
"""

from __future__ import with_statement

__all__ = [
    
    # Simple downloader
    'Downloader',
    
    # Web crawler
    'Crawler',
    
    # History file
    'History',
    
    # Cookies file
    'Cookies',
    
    # Hooks for the downloader
    'Hook',             # Base hook (default, does nothing)
    'DomainFilterHook', # Filter URLs by domain
    'RegexpFilterHook', # Filter URLs using regular expressions
    'HistoryHook',      # History file support
    
    # HTTP resource
    'Resource',
    ]

# system and shell interaction
import os
import sys
import errno
import shutil
import posixpath

# string manipulation
import re
try:
    import cStringIO as StringIO
except ImportError:
    import StringIO
try:
    import BeautifulSoup
except ImportError:
    pass

# time and date manipulation
import time
import rfc822
import calendar

# HTTP protocol support
import httplib
import urllib2
import urlparse
import cookielib

# persistency
import anydbm
try:
    import cPickle as pickle
except ImportError:
    import pickle

# warnings and errors
import warnings
import traceback

# JIT compiler
try:
    import psyco
    from psyco.classes import *
except ImportError:
    pass

#-----------------------------------------------------------------------------#

class Resource(object):
    """
    Represents an HTTP resource.
    
    @type timestamp: int
    @ivar timestamp: Last modification timestamp, as a UNIX epoch
    
    @type url: str
    @ivar url: URL originally followed to reach the resource
    
    @type location: str
    @ivar location: URL of the resource (after following redirections)
    
    @type datafile: str
    @ivar datafile: Full pathname to the local file with the resource data
    
    @type referer: str
    @ivar referer: Optional, referrer URL (as in the C{"Referer:"} HTTP header)
    
    @type headers: str
    @ivar headers: HTTP headers received from the server (see L{parse_headers})
    """
    
    def __init__(self, timestamp, url, location, datafile, referer, headers):
        """
        @type timestamp: int
        @ivar timestamp: Last modification timestamp, as a UNIX epoch
        
        @type url: str
        @ivar url: URL originally followed to reach the resource
        
        @type location: str
        @ivar location: URL of the resource (after following redirections)
        
        @type datafile: str
        @ivar datafile: Full pathname to the local file with the resource data
        
        @type referer: str
        @ivar referer: Optional, referrer URL (as in the C{"Referer:"} HTTP header)
        
        @type headers: str
        @ivar headers: HTTP headers received from the server (see L{parse_headers})
        """
        self.timestamp  = timestamp
        self.url        = url
        self.location   = location
        self.datafile   = datafile
        self.referer    = referer
        self.headers    = headers

    def parse_headers(self):
        """
        @rtype: httplib.HTTPMessage
        @return: An HTTPMessage with the request headers.
        """
        return httplib.HTTPMessage(StringIO.StringIO(self.headers))
    
    def __repr__(self):
        ts = time.asctime(time.gmtime(self.timestamp))
        return '[%s] %s\r\n%s' % (ts, self.location, self.headers)

#-----------------------------------------------------------------------------#
    
class Hook(object):
    """
    Base class for hooks. To write your own hooks just create a new
    class that derives from this class, and reimplement the desired
    methods.
    
    Each method returns C{True} to allow the download to continue or
    C{False} to stop it.
    
    While it's possible to modify the request and response objects from
    the hooks code, things will probably work better if you don't... at
    the very least your code would become very dependant on the particular
    implementation of this version of the library. Do it at your own risk!
    """
    
    def filter_request(self, dwn, req, url):
        """
        Filter HTTP requests.
        
        @type  dwn: L{Downloader}
        @param dwn: Downloader that invoked this method.
        
        @type  req: urllib2.HTTPRequest
        @param req: The HTTP request about to be sent.
        
        @type  url: str
        @param url: The URL to open.
        
        @rtype: bool
        @return:
            C{True} to allow the download to continue
            or C{False} to stop it.
        """
        return True
    
    def filter_redirect(self, dwn, req, newurl):
        """
        Filter redirection requests.
        
        @type  dwn: L{Downloader}
        @param dwn: Downloader that invoked this method.
        
        @type  req: urllib2.HTTPRequest
        @param req: The HTTP request already sent.
        
        @type  new_url: str
        @param new_url: The new URL to redirect to.
        
        @rtype: bool
        @return:
            C{True} to allow the download to continue
            or C{False} to stop it.
        """
        return True
    
    def filter_response(self, dwn, fsrc, filename):
        """
        Filter HTTP responses.
        
        @type  dwn: L{Downloader}
        @param dwn: Downloader that invoked this method.
        
        @type  fsrc: file
        @param fsrc: File-like object returned by C{urllib2}.
        
        @type  filename: str
        @param filename: Full pathname to the proposed destination file.
        
        @rtype: bool
        @return:
            C{True} to allow the download to continue
            or C{False} to stop it.
        """
        return True
    
    def filter_resource(self, dwn, resource):
        """
        Filter new L{Resource} objects before
        they're returned by the L{Downloader}.
        
        @type  dwn: L{Downloader}
        @param dwn: Downloader that invoked this method.
        
        @type  resource: L{Resource}
        @param resource: The recently downloaded resource.
        
        @rtype: bool
        @return:
            C{True} to allow the download to continue
            or C{False} to stop it.
        """
        return True
    
    # Do not override!
    def __add__(self, other):
        chain = [self]
        if other is not None:
            if not isinstance(other, Hook):
                msg = "Can't chain a Hook with an object of type %r"
                raise ValueError(msg % type(other))
            if isinstance(other, HookChain):
                chain.extend(other._chain)
        return HookChain(chain)
    
    # Do not override!
    def __radd__(self, other):
        if other is None:
            return HookChain([self])
        msg = "Can't chain a Hook with an object of type %r"
        raise ValueError(msg % type(other))

#-----------------------------------------------------------------------------#

class PrintHook(Hook):
    """
    Hook that logs activity to standard output.
    
    This is meant to be used for debugging.
    """
    
    def filter_request(self, dwn, req, url):
        print
        print '%s %s' % (req.get_method(), url)
        for x in req.headers.iteritems():
            print '%s: %s' % x
        return True
    
    def filter_redirect(self, dwn, req, newurl):
        return self.filter_request(dwn, req, newurl)
    
    def filter_response(self, dwn, fsrc, filename):
        print
        print fsrc.geturl()
        print filename
        return True
    
    def filter_resource(self, dwn, resource):
        print
        print resource
        return True

#-----------------------------------------------------------------------------#

class DomainFilterHook(Hook):
    
    # TODO
    
    pass

#-----------------------------------------------------------------------------#

class RegexpFilterHook(Hook):
    
    # TODO
    
    pass

#-----------------------------------------------------------------------------#

class HookChain(object):
    """
    Chain of L{Hook}s to be executed in order. Each callback method returns
    C{True} if and only if the equivalent method from each hook in the chain
    also returns C{True}.
    """
    
    def __init__(self, chain=None):
        """
        @type  chain: list(L{Hook})
        @param chain: Hook chain.
            Defaults to an empty list, use L{append_hook} to add hooks to it.
        """
        if chain is None:
            chain = []
        self._chain = chain
        self._validate_chain()
    
    # Make sure the hook derives from the Hook class
    def _validate_hook(self, hook):
        if not isinstance(hook, Hook) or not (
                hasattr(hook, 'filter_request') and
                hasattr(hook, 'filter_redirect') and
                hasattr(hook, 'filter_response') and
                hasattr(hook, 'filter_resource')
            ):
            
            msg = "Expected a subclass of %r, got %r instead"
            raise ValueError(msg % (Hook, type(hook)))
    
    # Validate the entire hook chain
    def _validate_chain(self):
        for hook in self._chain:
            self._validate_hook(hook)
    
    def append_hook(self, hook):
        """
        Add a hook to the end of the hook chain.
        
        @see: L{prepend_hook}
        
        @type  hook: L{Hook}
        @param hook: Hook to add.
        """
        self._validate_hook(hook)
        self._chain.append(hook)
    
    def prepend_hook(self, hook):
        """
        Insert a hook to the beginning of the hook chain.
        
        @see: L{append_hook}
        
        @type  hook: L{Hook}
        @param hook: Hook to add.
        """
        self._validate_hook(hook)
        self._chain.append(hook)
    
    def remove_hook(self, hook):
        """
        Remove the hook from the hook chain.
        
        If the same hook was added more than once, multiple calls to this
        method may be needed.
        
        @type  hook: L{Hook}
        @param hook: Hook to remove.
        """
##        self._validate_hook(hook)
        self._chain.remove(hook)
    
    # not sure if the following code would ever work outside cPython...
    # but it'd be easy to "fix" with some copy&paste from _run_callbacks()
    
    def _run_callbacks(self, callbacks, arguments):
        allowed = True
        for method in callbacks:
            allowed = allowed and method(*arguments)
            if not allowed:
                break
        return allowed
    
    def _filter_request(self, dwn, req, url):
        callbacks = [hook.filter_request for hook in self._chain]
        return self._run_callbacks(callbacks, (dwn, req, url))
    
    def _filter_redirect(self, dwn, req, newurl):
        callbacks = [hook.filter_redirect for hook in self._chain]
        return self._run_callbacks(callbacks, (dwn, req, newurl))
    
    def _filter_response(self, dwn, fsrc, filename):
        callbacks = [hook.filter_response for hook in self._chain]
        return self._run_callbacks(callbacks, (dwn, fsrc, filename))
    
    def _filter_resource(self, dwn, resource):
        callbacks = [hook.filter_resource for hook in self._chain]
        return self._run_callbacks(callbacks, (dwn, resource))

#-----------------------------------------------------------------------------#

class Configurable(object):
    """
    Base class for configurable actions.
    """
    
    class _DefaultOptions(object):
        """
        Default options. Override this inner class.
        """
        
        def __init__(self):
            pass
    
    def __init__(self, options=None):
        """
        @type  options: Options
        @param options: Optional, configuration.
        """
        if not options:
            options = self.__class__._DefaultOptions()
        self.options = options

#-----------------------------------------------------------------------------#

class ShellUtils(object):
    """
    Static methods with shell utilities.
    """
    
    @staticmethod
    def get_home_folder():
        home = os.getenv('HOME', None)
        if not home:
            home = os.getenv('HOMEPATH', None)
        return home

#-----------------------------------------------------------------------------#

class FileUtils(object):
    """
    Static methods for file manipulation.
    """
    
    # Characters not allowed in filenames
    _invalid_chars = '\\/:*?"<>|'
    
    # Safe character to replace invalid characters with
    _safe_char = '_'
    
    # Make sure the directory structure exists
    @staticmethod
    def makedirs(path):
        try:
            os.makedirs(path, 0777)     # later masked with umask
        except OSError, e:
            if e.errno != errno.EEXIST:
                raise
    
    # Download method for ON_DUPLICATE_OVERWRITE
    @staticmethod
    def copy_overwriting(fsrc, filename):
        must_delete = False
        try:
            with open(filename, 'w+b') as fdst:
                must_delete = True
                shutil.copyfileobj(fsrc, fdst)
                must_delete = False
        finally:
            if must_delete:
                os.unlink(filename)
    
    # Download method for ON_DUPLICATE_FAIL
    @classmethod
    def copy_exclusive(self, fsrc, filename):
        must_delete = False
        try:
            with self.create_file_exclusive(filename, silent=False) as fdst:
                must_delete = True
                shutil.copyfileobj(fsrc, fdst)
                must_delete = False
        finally:
            if must_delete:
                os.unlink(filename)
    
    # Download method for ON_DUPLICATE_RENAME
    @classmethod
    def copy_renaming(self, fsrc, path, name):
        index = 0
        filename = os.path.join(path, name)
        name, ext = os.path.splitext(name)
        fdst = None
        must_delete = False
        try:
            fdst = self.create_file_exclusive(filename, silent=True)
            while not fdst:
                index = index + 1
                new_name = '%s (%d)%s' % (name, index, ext)
                filename = os.path.join(path, new_name)
                fdst = self.create_file_exclusive(filename, silent=True)
            must_delete = True
            shutil.copyfileobj(fsrc, fdst)
            must_delete = False
        finally:
            if fdst:
                fdst.close()
            if must_delete:
                os.unlink(filename)
        return filename
    
    # Create a file if and only if it didn't exist previously
    @classmethod
    def create_file_exclusive(self, filename, silent=True):
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
    def get_file_time(filename):
        """
        Retrieves the last modification date
        and time of a given file as a Unix epoch.
        
        @type  filename: str
        @param filename: Pathname to the file to examine.
        
        @rtype: int
        @return:
            Timestamp as a Unix epoch, or C{None} if the file doesn't exist.
        """
        try:
            st = os.stat(filename)
            mtime = int(st.st_mtime)
            return mtime
        except OSError, e:
            if e.errno != errno.ENOENT: # file not found
                raise
        return None
    
    @staticmethod
    def set_file_time(filename, timestamp):
        st = os.stat(filename)
        if os.stat_float_times():
            timestamp = float(timestamp)
        os.utime(filename, (timestamp, timestamp))
    
    @staticmethod
    def get_file_size(filename):
        st = os.stat(filename)
        return st.st_size
    
    # Sanitize a filename.
    @classmethod
    def sanitize_local_name(self, name):
        if name:
            s = self._safe_char
            for c in self._invalid_chars:
                name = name.replace(c, s)
        return name
    
    # Sanitize a pathname.
    @classmethod
    def sanitize_local_path(self, path):
        
        # Don't do anything when the path is empty
        if path:
            
            # Split the path in a list of components
            # COMPAT BUG: this will not work with UNC paths!
            parts = path.split(os.path.sep)
            
            # Sanitize each path component, discarding empty ones
            # COMPAT BUG: this will not work with UNC paths!
            parts = [self.sanitize_local_name(x) for x in parts if x]
            
            # Build the path again
            path = os.path.sep.join(parts)
            
            # Normalize the path (removes intermediate ".." components)
            # COMPAT BUG: this will not work with symlinks!
            path = os.path.normpath(path)
            
            # Remove any leading ".." components
            # XXX may not be needed, see the check at calc_local_name
            dotdot = '..' + os.path.sep
            while path.startswith(dotdot):
                path = path[len(dotdot):]
        
        # Return the sanitized path
        return path

#-----------------------------------------------------------------------------#

class HttpUtils(object):
    """
    Static methods with HTTP utilities.
    """
    
    # Regexp to extract the filename from the Content-Disposition header
    _name_from_content_disposition = re.compile('^attachment; filename=(.*)$')
    
    @staticmethod
    def get_last_modified(headers, local_date=None):
        """
        Retrieve the last modification date and time from the HTTP headers.
        If the server's clock has a different time than our clock, the time
        is automatically corrected.
        
        @type  headers: httplib.HTTPHeaders
        @param headers: HTTP headers returned by the server.
        
        @type  local_date: int
        @param local_date: Optional, current date and time as a Unix epoch.
            Used to correct the file time from the server.
        
        @rtype: int
        @return: Last modification date and time, corrected to our clock,
            as a Unix epoch.
        """
        
        # Get the current time if not given
        if not local_date:
            local_date = time.time()
        
        # Get the last modified time from the headers
        try:
            file_date = calendar.timegm(
                            rfc822.parsedate(
                                headers['Last-Modified'] ))
        
        # If not found return None
        except KeyError:
            return None
        
        # Get the server time from the headers
        try:
            server_date = calendar.timegm(
                            rfc822.parsedate(
                                headers['Date'] ))
        
        # If not found return the file time unchenged
        except KeyError:
            return file_date
        
        # Correct the file time to the local clock and return it
        return file_date - server_date + local_date
    
    # Check if the local file has the same size as the remote file
    @staticmethod
    def same_size(filename, headers):
        try:
            hsize = int(headers['Content-Length'])
            fsize = os.stat(filename).st_size
        except KeyError:
            return False
        except ValueError:
            return False
        except OSError:
            return False
        return hsize == fsize
    
    @classmethod
    def get_name_from_headers(self, headers):
        """
        Retrieve the file name from the Content-Disposition header.
        
        @type  headers: httplib.HTTPHeaders
        @param headers: HTTP headers returned by the server.
        
        @rtype: str
        @return: Filename given by the server, sanitized (bad characters are
            replaced by a safe character and path information is stripped).
        """
        
        # Get the Content-Disposition header value
        cont_disp = headers.getheader('Content-Disposition')
        if cont_disp:
            cont_disp = cont_disp.strip()
            
            # Extract the filename from the header value
            match = self._name_from_content_disposition.search(cont_disp)
            if match:
                new_name = match.groups()[0]
                
                # Remove enclosing double quotes, if any
                if new_name.startswith('"'):
                    new_name = new_name[1:]
                if new_name.endswith('"'):
                    new_name = new_name[:-1]
                
                # Strip path information, if any
                # (this check works because in Windows \ is a path separator
                # and / is not accepted in a valid filename anyway)
                if os.path.sep in new_name:
                    new_name = new_name[new_name.rfind(os.path.sep)+1:]
                
                # If the filename is not empty after all this parsing,
                # return the sanitized version
                if new_name:
                    return FileUtils.sanitize_local_name(new_name)
        return None
    
    @staticmethod
    def normalize_url(url):
        
        # TODO
        
        return url

#-----------------------------------------------------------------------------#

class Downloader(Configurable, HookChain):
    """
    Downloads any given URL to the desired target directory.
    Its behavior can be configured through a set of options at
    startup and through a L{Hook} on each download.
    
    @group Values for the C{onduplicate} option:
        ON_DUPLICATE_OVERWRITE, ON_DUPLICATE_RENAME,
        ON_DUPLICATE_FAIL, ON_DUPLICATE_SKIP
    
    @type ON_DUPLICATE_OVERWRITE: int
    @cvar ON_DUPLICATE_OVERWRITE: Always overwrite output files.
    
    @type ON_DUPLICATE_RENAME: int
    @cvar ON_DUPLICATE_RENAME: Rename output files automatically.
    
    @type ON_DUPLICATE_FAIL: int
    @cvar ON_DUPLICATE_FAIL: Raise exception if output file exists.
    
    @type ON_DUPLICATE_SKIP: int
    @cvar ON_DUPLICATE_SKIP: Skip download if local file exists.
    
    @type USER_AGENT: str
    @cvar USER_AGENT: User agent string.
    """
    
    # Values for --onduplicate
    ON_DUPLICATE_OVERWRITE  = 0     # always overwrite output files
    ON_DUPLICATE_RENAME     = 1     # rename output files automatically
    ON_DUPLICATE_FAIL       = 2     # raise exception if output file exists
    ON_DUPLICATE_SKIP       = 3     # skip download if local file exists
    
    # TODO: collection of user-agents
    USER_AGENT = 'PyCrawl 0.1'
    
    # Default hook that returns True to everything
    _default_hook = Hook()
    
    class _OptionsSiteMirrorMode(object):
        """
        Set of options for L{Downloader} to work in site mirror mode.
        """
        
        def __init__(self):
            self.targetdir = os.path.curdir
            self.flatten = False
            self.obeycontentdisposition = True
            self.usefstimes = True
            self.onduplicate = Downloader.ON_DUPLICATE_OVERWRITE
    
    class _OptionsDownloadManagerMode(object):
        """
        Set of options for L{Downloader} to work in download manager mode.
        """
        
        def __init__(self):
            self.targetdir = os.path.curdir
            self.flatten = True
            self.obeycontentdisposition = True
            self.usefstimes = False
            self.onduplicate = Downloader.ON_DUPLICATE_RENAME
    
    class _DefaultOptions(_OptionsDownloadManagerMode):
        """
        Default options for L{Downloader}.
        """
    
    class _RedirectHandler(urllib2.HTTPRedirectHandler):
        """
        Redirect handler for C{urllib2} to call the L{Hook} on redirection
        attempts and block them if desired.
        
        Since this sits on top of the default handler, circular redirections
        are already blocked by default.
        """
        
        def __init__(self, callback, param):
            """
            @type  callback: callable
            @param callback:
                Callback function to call on redirection attempts. It's assumed
                to have the same signature as L{Hook.filter_redirect}.
            @type  param: Downloader
            @param param:
                Arbitrary first parameter to the callback function.
                It's assumed to be the calling L{Downloader} instance.
            """
            self.__callback = callback
            self.__param    = param
        
        def http_error_302(self, req, fp, code, msg, headers):
            if 'location' in headers:
                newurl = headers.getheaders('location')[0]
            elif 'uri' in headers:
                newurl = headers.getheaders('uri')[0]
            else:
                return
            if req.has_header('Referer'):
                req.add_header('Referer', req.get_full_url())
            if not self.__callback(self.__param, req, newurl):
                raise urllib2.HTTPError(req.get_full_url(), code,
                                "Blocked redirect: \"%s\"" % newurl,
                                headers, fp)
            return urllib2.HTTPRedirectHandler.http_error_302(
                                            self, req, fp, code, msg, headers)
        
        http_error_301 = http_error_303 = http_error_307 = http_error_302
    
    def __init__(self, options=None, cookiejar=None, hooks=None):
        """
        @type  options: Options
        @param options: Optional, configuration.
        
        @type  cookiejar: cookielib.CookieJar
        @param cookiejar: Optional, HTTP cookie jar.
        
        @type  hooks: list(L{Hook})
        @param hooks: Hook chain in order of execution.
            All requests and responses will be filtered by these hooks in the
            given order.
        """
        
        # Configuration
        Configurable.__init__(self, options)
        
        # Hook chain
        HookChain.__init__(self, hooks)
        
        # Target directory
        self._targetdir = os.path.realpath(options.targetdir)
        if not self._targetdir.endswith(os.path.sep):
            self._targetdir = self._targetdir + os.path.sep
        
        # List of urllib2 handlers
        handlers = []
        
        # Cookie handler to use our cookie jar
        cookie_handler = urllib2.HTTPCookieProcessor(cookiejar)
        handlers.append(cookie_handler)
        
        # Redirect handler to pass redirections through the hook
        callback = self._filter_redirect
        redir_handler = self.__class__._RedirectHandler(callback, self)
        handlers.append(redir_handler)
        
        # Create the urllib2 opener using our handlers
        self._urlopener = urllib2.build_opener(*(tuple(handlers)))
    
    def download(self, url, referer=None):
        """
        Download the resource pointed to by the given URL.
        
        @type  url: str
        @param url: Resource URL. Only "http://" and "https://" are supported.
        
        @type  referer: str
        @param referer: Referer URL, as in the C{Referer} HTTP header.
        
        @rtype: Resource or None
        @return:
            If the download is successful, this method returns a L{Resource}
            instance describing it. If the download is skipped due to hooks or
            configuration settings, C{None} is returned instead.
        
        @raise urllib2.HTTPError: Protocol or network error.
        @raise os.OSError: System error while writing the downloaded data.
        """
        
        onduplicate = self.options.onduplicate
        usefstimes  = self.options.usefstimes
        lastupdated = None
        
        # Normalize the URL
        url = HttpUtils.normalize_url(url)
        
        # Calculate the local file name from the URL
        path, name = self.calc_local_name(url)
        
        # If a local file of the same name exists, skip it
        # (only if ON_DUPLICATE_SKIP is specified)
        if onduplicate == Downloader.ON_DUPLICATE_SKIP \
            and os.path.exists(os.path.join(path, name)):
                return None
        
        # Build the request
        headers = {'User-Agent':self.USER_AGENT}
        if referer:
            headers['Referer'] = referer
        if usefstimes:
            lastupdated = FileUtils.get_file_time(os.path.join(path, name))
            if lastupdated:
                headers['If-Modified-Since'] = rfc822.formatdate(lastupdated)
        req = urllib2.Request(url, headers=headers)
        
        # Pass the request through the hook filters
        if not self._filter_request(self, req, url):
            return None
        
        # Make the request to the server
        fsrc = None
        try:
            try:
                fsrc = self._urlopener.open(req)
            except urllib2.HTTPError, e:
                if int(e.code) == 304:  # if "304: Not Modified"
                    return None             # we have it in the cache
                raise                   # else an error occured
            resp_time = time.time()
            
            # Update our info from the response headers
            headers = fsrc.info()
            location = fsrc.geturl()
            path, name = self.calc_local_name(location)
            filechanged = False
            if location != url:
                filechanged = True
            if self.options.obeycontentdisposition:
                new_name = HttpUtils.get_name_from_headers(headers)
                if new_name and new_name != name:
                    name = new_name
                    filechanged = True
            filename = os.path.join(path, name)
            if filechanged:
                lastupdated = FileUtils.get_file_time(filename)
            timestamp = HttpUtils.get_last_modified(headers)
            
            # If a local file of the same name exists, skip it
            # (only if ON_DUPLICATE_SKIP is specified)
            if onduplicate == Downloader.ON_DUPLICATE_SKIP \
                and os.path.exists(filename):
                    return None
            
            # If we already have this file in the cache, skip it
            # (only if we trust filesystem timestamps)
            if usefstimes  and timestamp and lastupdated \
                           and lastupdated >= timestamp \
                           and HttpUtils.same_size(filename, headers):
                return None
            
            # Pass the response through the hook filters
            if not self._filter_response(self, fsrc, filename):
                return None
            
            # Download the file contents to disk
            if not timestamp:
                timestamp = resp_time
            filename = self._download_to_file(fsrc, path, name, timestamp)
            if not filename:
                return None     # skipped
            
            # Build the Resource object to be returned
            hdrs = ''.join(headers.headers)
            res = Resource(timestamp, url, location, filename, referer, hdrs)
            
            # Pass the Resource object through the hook filters
            if not self._filter_resource(self, res):
                return None
        
        # Close the request object
        finally:
            if fsrc:
                fsrc.close()
        
        # Return the Resource object
        return res
    
    # Save an open URL into a local file
    def _download_to_file(self, fsrc, path, name, timestamp=None):
        
        # Make sure the directory structure exists
        FileUtils.makedirs(path)
        
        # Download the file using the appropriate method...
        onduplicate = self.options.onduplicate
        
        # ON_DUPLICATE_RENAME: Rename the output file automatically
        if onduplicate == Downloader.ON_DUPLICATE_RENAME:
            filename = FileUtils.copy_renaming(fsrc, path, name)
        else:
            
            # Calculate the output filename
            filename = os.path.join(path, name)
            
            # ON_DUPLICATE_OVERWRITE: Always overwrite the output file
            if onduplicate == Downloader.ON_DUPLICATE_OVERWRITE:
                FileUtils.copy_overwriting(fsrc, filename)
        
            # ON_DUPLICATE_SKIP: Skip download if local file exists
            elif onduplicate == Downloader.ON_DUPLICATE_SKIP:
                try:
                    FileUtils.copy_exclusive(fsrc, filename)
                except OSError:
                    return None     # return None if skipping
            
            # ON_DUPLICATE_FAIL: Fail if output file doesn't exist
            elif onduplicate == Downloader.ON_DUPLICATE_FAIL:
                FileUtils.copy_exclusive(fsrc, filename)
            
            # This should never happen...
            else:
                msg = "Unknown ON_DUPLICATE flag: %d"
                msg = msg % onduplicate
                raise AssertionError(msg)
        
        # Fix the file last modification time
        if timestamp:
            try:
                FileUtils.set_file_time(filename, timestamp)
            except OSError, e:
                warning.warn(str(e), RuntimeWarning)
        
        # Return the filename on success
        return filename
    
    def calc_local_name(self, url):
        """
        Generate a local filename from the given URL.
        
        @type  url: str
        @param url: Resource URL.
        
        @rtype: str
        @return: Absolute pathname to the target local file.
        
        @raise IOError: The resulting pathname lies outside the configured
            target directory (probably because a symlink is pointing outside).
            This is forbidden for security reasons.
        """
        
        # Parse the URL into its components
        parts = urlparse.urlparse(url)
        
        # Get the path and name from the URL
        path = urllib2.unquote(parts.path)
        path, name = posixpath.split(path)
        
        # Sanitize the file name
        name = FileUtils.sanitize_local_name(name)
        if not name:
            name = 'index.html'
        
        # If --flatten was used, skip the path
        if self.options.flatten:
            path = self._targetdir
        
        # If not, build the local path from the remote path
        else:
            
            # Correct / to \ in Windows
            if os.path.sep != '/':
                path = path.replace(posixpath.sep, os.path.sep)
            
            # Sanitize the path part
            path = FileUtils.sanitize_local_path(path)
            
            # Prepend the hostname to the local path
            host = urllib2.unquote(parts.netloc)
            if ':' in host:
                host = host.split(':')[0].strip()
            host = FileUtils.sanitize_local_name(host)
            
            # Prepend the target directory to the local path
            path = os.path.join(self._targetdir, host, path)
            
            # Make it absolute, resolving symlinks
            path = os.path.realpath(path)
            
            # I want it to end with a / always (just in case)
            if not path.endswith(os.path.sep):
                path = path + os.path.sep
            
            # The resulting path can't be outside the target directory
            # TODO: an option to disable this security check?
            if not path.startswith(self._targetdir):
                msg = "Download path (%r) is outside the target path (%r)"
                msg = msg % (path, self._targetdir)
                raise IOError(msg)
        
        # Return the local path and filename
        return path, name

#-----------------------------------------------------------------------------#

class History(object):
    """
    Keeps a history of downloaded resources in a database.
    
    @type default_filename: str
    @cvar default_filename: Default filename to use if not provided at the
        constructor. This is the file part only, the directory part is taken
        from the current user's home directory.
    
    @type protocol: int
    @cvar protocol: Pickle protocol for serialization
    
    Example::
        with History() as history:
            if not history.contains(url):
                downloader = Downloader(options=options)
                resource = downloader.download(url)
                if resource:
                    history.add(resource)
    """
    
    # Pickle protocol for serialization
    protocol = pickle.HIGHEST_PROTOCOL
    
    # Default filename
    default_filename = '.pycrawl_history'
    
    def __init__(self, filename=None):
        """
        @type  filename: str
        @param filename:
            Optional history file name. If this argument is not set, the
            default filename is obtained from L{get_default_filename}.
        """
        self._filename = filename
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, type, value, traceback):
        self.close()
    
    def get_default_filename(self):
        """
        @rtype:  str
        @return: The default history filename.
            If not set in the constructor, the default filename depends on the
            user home directory and the class attribute L{default_filename}.
        """
        filename = self._filename
        if not filename:
            home = ShellUtils.get_home_folder()
            if not home:
                home = os.path.curdir
            filename = os.path.join(home, self.default_filename)
        return filename
    
    def open(self, filename=None):
        """
        Open the history file.
        
        @note: this closes the previously open file for this instance.
        
        @type  filename: str
        @param filename: Optional history file name.
            If this argument is not set, the default filename is used.
        """
        if not filename:
            filename = self.get_default_filename()
        db = anydbm.open(filename, 'c')
        try:
            if hasattr(self, '_db'):
                self.close()
        finally:
            self._last_filename = filename
            self._db = db
    
    def sync(self):
        """
        Persists database changes to disk.
        """
        self._db.sync()
    
    def revert(self):
        """
        Revert all changes to the history file back to the last saved version.
        """
        del self._db
        self.open(self._last_filename)
    
    def close(self):
        """
        Closes the history file. After calling this method, you are only
        allowed to call the L{open} method before using this instance again.
        This will automatically save all changes.
        """
        try:
            self.sync()
        finally:
            try:
                self._db.close()
            finally:
                del self._db
    
    def _serialize(self, object):
        return pickle.dumps(object, protocol=self.protocol)
    
    def _deserialize(self, serial):
        return pickle.loads(serial)
    
    def add(self, resource):
        """
        Save a downloaded HTTP resource to the history file.
        
        @type  resource: L{Resource}
        @param resource: HTTP resource.
        """
        try:
            res_set = self._deserialize(self._db[resource.location])
        except KeyError:
            res_set = set()
        res_set.add(resource)
        self._db[resource.location] = self._serialize(res_set)
    
    def contains(self, location):
        """
        Determine if at least one HTTP resource at the given URL was saved to
        the history file.
        
        @type  location: str
        @param location: URL of the HTTP resource to look for.
        
        @rtype: bool
        @return:
            C{True} if a resource at that URL was saved,
            C{False} otherwise.
        """
        return self._db.has_key(location)
    
    def get(self, location):
        """
        Get all resources for the given URL from the history file.
        
        @type  location: str
        @param location: URL of the HTTP resources to look for.
        
        @rtype: set(L{Resource})
        @return: Set of HTTP resources. Returns C{None} if no resource was
            found for that URL in the history file.
        """
        try:
            return self._deserialize(self._db[location])
        except KeyError:
            return None

#-----------------------------------------------------------------------------#

class HistoryHook(Hook):
    """
    Downloader hook to use a history file.
    
    This provides more accurate tracking of which resources were downloaded
    already and if they need to be downloaded again.
    
    Example::
        def my_download(url, options):
            with History() as history:
                hook = HistoryHook(history)
                downloader = Downloader(options=options, hook=hook)
                return downloader.download(url)
    """
    def __init__(self, history):
        self.__history = history
    
    def filter_request(self, dwn, req, url):
        
        # Fetch all matching resources for this URL
        # in the history file and skip if not found
        res_set = self.__history.get(url)
        if not res_set:
            return True
        
        # Calculate the target local filename
        targetfile = os.path.join(*dwn.calc_local_name(url))
        
        # Get the current value for the If-Modified-Since header if present,
        # or the local file time if not.
        currenthdr = req.get_header('If-Modified-Since')
        current = None
        if currenthdr:
            try:
                current = rfc822.parsedate_tz(currenthdr)
            except Exception:
                current = None
        if not current:
            currenthdr = None
            if os.path.exists(targetfile):
                current = FileUtils.get_file_time(targetfile)
                if current:
                    try:
                        currenthdr = rfc822.formatdate(current)
                    except Exception:
                        currenthdr = None
                    if not currenthdr:
                        current = None
        
        # Iterate through all past downloads with the same URL
        for resource in res_set:
            
            # Skip if the file was not successfully downloaded
            datafile = resource.datafile
            if not datafile:
                continue
            
            # Skip if the target local file does not match
            if datafile != targetfile:
                continue
            
            # Skip if the local file does not exist in the target location
            if not os.path.isfile(datafile):
                continue
            
            # Get the resource's last modification time
            lastmod = resource.parse_headers().get('Last-Modified', None)
            timestamp = None
            if lastmod:
                try:
                    timestamp = rfc822.parsedate_tz(lastmod)
                except Exception:
                    timestamp = None
            if not timestamp:
                lastmod = None
                timestamp = resource.timestamp
                if timestamp:
                    try:
                        lastmod = rfc822.formatdate(timestamp)
                    except Exception:
                        lastmod = None
                if not lastmod:
                    timestamp = None
            
            # If this timestamp is newer than the current timestamp,
            # update the If-Modified-Since header
            if timestamp and (not current or timestamp > current):
                current = timestamp
                currenthdr = lastmod
        
        # If we have an updated If-Modified-Since header, set it
        if currenthdr:
            req.add_header('If-Modified-Since', currenthdr)
        
        return True
    
    # Same processing as filter_request
    def filter_redirect(self, dwn, req, newurl):
        return self.filter_request(dwn, req, newurl)
    
    # Record downloaded resources into the history file
    def filter_resource(self, dwn, resource):
        self.__history.add(resource)
        return True

#-----------------------------------------------------------------------------#

class Cookies(cookielib.LWPCookieJar, Configurable):
    """
    Persistent cookie jar. Based on LWPCookieJar for persistence, with some
    minor tweaks (has a default filename and supports the C{with} clause).
    """
    
    default_filename = '.pycrawl_cookies'
    
    class _DefaultOptions(object):
        """
        Default options for L{Cookies}.
        """
        
        def __init__(self):
            self.cookie_file  = None
            self.load_cookies = True
            self.save_cookies = True
    
    def __init__(self, options=None):
        Configurable.__init__(self, options)
        filename = options.cookie_file
        if not filename:
            filename = self.get_default_filename()
        cookielib.LWPCookieJar.__init__(self, filename, False, None)
    
    def get_default_filename(self):
        """
        The default filename is calculated from the user's home directory and
        the L{default_filename} class attribute.
        """
        home = ShellUtils.get_home_folder()
        if not home:
            home = os.path.curdir
        return os.path.join(home, self.default_filename)
    
    def __enter__(self):
        """
        Upon entering a context the cookies are automatically loaded if the
        file exists.
        """
        if self.options.load_cookies and os.path.exists(self.filename):
            self.load()
        return self
    
    def __exit__(self, type, value, traceback):
        """
        Upon exiting a context the cookies are automatically saved to the file.
        """
        if self.options.save_cookies:
            self.save()

#-----------------------------------------------------------------------------#

class Crawler(Downloader):
    """
    Web crawler.
    """
    
    # Maximum size in bytes of files to be parsed in-memory.
    _max_in_mem_parse = 1024 * 1024
    
    # Regular expression to capture URLs in plaintext.
    tmp = "%(c)s((?:https?|ftp)://[^%(c)s]*[^%(c)s\\.])%(c)s"
    _reURL = re.compile("(?:%s|(?:%s|%s))" % (
                tmp % {'c' : '\\b'},
                tmp % {'c' : '"'},
                tmp % {'c' : "'"},
                ), re.IGNORECASE)
    del tmp
    
    class _DefaultOptions(Downloader._OptionsSiteMirrorMode):
        """
        Default options for L{Crawler}.
        """

    def __init__(self, options=None, cookiejar=None, hooks=None):
        
        # TODO
        
        Downloader.__init__(self, options, cookiejar, hooks)
    
    def crawl(self, url, referer=None):
        """
        Download the given resource and all linked resources.
        
        @type  url: str
        @param url: Resource URL. Only "http://" and "https://" are supported.
        
        @type  referer: str
        @param referer: Referer URL, as in the C{Referer} HTTP header.
        """
        self.targets = [(url, referer)]
        while self.targets:
            url, referer = self.targets.pop()
            res = self.download(url, referer)
            if res:
                self.parse(res)
    
    def add_targets(urls, referer):
        for url in urls:
            self.targets.append( (url, referer) )
    
    def parse(self, res):
        content_type = res.parse_headers().get('Content-Type')
        if content_type is not None:
            content_type = content_type.lower()
            if content_type == 'text/html':
                self.parse_html(res)
            elif content_type.startswith('text/'):
                self.parse_text(res)
    
    def parse_text(self, res):
        if FileUtils.get_file_size(res.datafile) <= self._max_in_mem_parse:
            with open(res.datafile, 'rb') as fd:
                data = fd.read()
            urls = self._reURL.findall(data)
            del data
            self.add_targets(urls, res.location)
            del urls
        
        
        else:
            
            # TODO
            
            pass
    
    def parse_html(self, res):
        try:
            BeautifulSoup
        except NameError:
            return parse_text(res)
        
        
        
        # TODO
        
        pass

#-----------------------------------------------------------------------------#

class Main(object):
    """
    Main class for the command line tool.
    """
    
    class _DefaultOptions(Crawler._DefaultOptions, Cookies._DefaultOptions):
        def __init__(self):
            Crawler._DefaultOptions.__init__(self)
            Cookies._DefaultOptions.__init__(self)
            self.keep_history = True
            self.history_file = None
            self.referer = None
            self.recursive = True
    
    # Parse the commandline
    def run(self, argv=None):
        if argv is None:
            argv = sys.argv
        
        
        
        # TODO
        
        
        
        # just testing...
        options = self.__class__._DefaultOptions()
        options.referer = 'http://www.example.com'
        args = ['http://www.google.com',
                'http://winappdbg.sourceforge.net/dist/winappdbg-1.0.zip']
        
        
        
        # Save the options and targets and run
        self.options = options
        self.targets = args
        self.__run()
    
    # Create the cookiejar
    def __run(self):
        if self.options.load_cookies or self.options.save_cookies:
            with Cookies(self.options) as cookiejar:
                self.__run_with_cookies(cookiejar)
        else:
                self.__run_with_cookies(None)
    
    # Create the history
    def __run_with_cookies(self, cookiejar):
        if self.options.keep_history:
            with History(self.options.history_file) as history:
                self.__run_with_cookies_and_history(cookiejar, history)
        else:
                self.__run_with_cookies_and_history(cookiejar, None)
    
    # Create the downloader and run it through every target
    def __run_with_cookies_and_history(self, cookiejar, history):
        options = self.options
        hooks = []
        if history is not None:
            hooks.append(HistoryHook(history))
        hooks.append(PrintHook())       # DEBUG
        if options.recursive:
            crawler = Crawler(options, cookiejar, hooks)
            action  = crawler.crawl
        else:
            downloader = Downloader(options, cookiejar, hooks)
            action     = downloader.download
        referer = options.referer
        for url in self.targets:
            action(url, referer)

#-----------------------------------------------------------------------------#

# TODO

#-----------------------------------------------------------------------------#

def main():
    # just testing...
    Main().run()

#-----------------------------------------------------------------------------#

if __name__ == '__main__':
    try:
        psyco.cannotcompile(re.compile)
        psyco.bind(main)
    except NameError:
        pass
    main()
