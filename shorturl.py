#!/usr/bin/env python

# URL shortener services (shorten and expand URLs).
# Copyright (c) 2009, Mario Vilas
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

"""URL shortener services (shorten and expand URLs).

@see: U{http://breakingcode.wordpress.com/2010/01/10/having-fun-with-url-shorteners/}

@type shorteners: set of str
@var  shorteners: Supported URL shortener services.
    See the sources for the full list.

@type verbose: bool
@var  verbose: Global verbose flag. Set to C{True} to print debug messages, or
    C{False} for the default behavior (don't print anything).
    This is a private variable and you shouldn't need to use it.

@type api: dict of str
@var  api: URL shortener API format strings.
    This is a private variable and you shouldn't need to use it.
"""

__all__ = ['shorturl', 'longurl', 'hideurl', 'besturl', 'is_short_url', 'shorteners']

import random
import urllib2
import urlparse
import optparse

#------------------------------------------------------------------------------

# Global verbose flag.
verbose = False

# Currently supported URL shortener services.
# All of them issue an HTTP GET request and expect a simple text response.
api = {

    'bit.ly'        :   'http://bit.ly/api?url=%s',
    'cli.gs'        :   'http://cli.gs/api/v1/cligs/create?appid=urlshorten.py&url=%s',
    'cru.ms'        :   'http://cru.ms/?module=ShortURL&file=Add&mode=API&url=%s',
    'easyuri.com'   :   'http://easyuri.com/api.php?link=%s',
    'is.gd'         :   'http://is.gd/api.php?longurl=%s',
    'ito.mx'        :   'http://ito.mx/?module=ShortURL&file=Add&mode=API&url=%s',
    'kl.am'         :   'http://kl.am/api/shorten/?url=%s&format=text',
    'migre.me'      :   'http://migre.me/api.txt?url=%s',
    'onodot.com'    :   'http://onodot.com/api.php?url=%s',
    'shrten.com'    :   'http://shrten.com/api?url=%s',
    'www.thisurl.com':  'http://www.thisurl.com/?module=ShortURL&file=Add&mode=API&url=%s',
    'thurly.net'    :   'http://thurly.net/api.php?id=%s',
    'tinyurl.com'   :   'http://tinyurl.com/api-create.php?url=%s',
    'tr.im'         :   'http://api.tr.im/v1/trim_simple?url=%s',
    'u.nu'          :   'http://u.nu/unu-api-simple?url=%s',
    'xrl.us'        :   'http://metamark.net/api/rest/simple?long_url=%s',
    'zi.ma'         :   'http://zi.ma/?module=ShortURL&file=Add&mode=API&url=%s',

# XXX TODO
# More sources for information on URL shorteners:
# http://en.wikipedia.org/wiki/URL_shortening
# http://lists.econsultant.com/top-10-url-redirection-services.html
# http://searchengineland.com/analysis-which-url-shortening-service-should-you-use-17204

#------------------------------------#
# Unsupported URL shortener services #
#------------------------------------#

# Works but it's painfully slow!
#    'snick.me'      :   'http://snick.me/api/create.text?url=%s',

# I don't support this response format yet (custom? haven't seen it before).
# May be easier to just switch it to JSON or whatever
#    'z.pe'          :   'http://api.z.pe/new.txt?href=%s',

# Uses unicode to shorten the urls and I don't support that yet.
#    'tinyarro.ws'   :   'http://tinyarro.ws/api-create.php?utfpure=1&url=%s',

# Forcefully places the target pages inside an iframe. I found more services
# using the exact same that API don't misbehave (cru.ms, ito.mx, zi.ma), so I
# guess someone made some ugly patches here. :P
#    'itshrunk.com'  :   'http://itshrunk.com/?module=ShortURL&file=Add&mode=API&url=%s',

# Bad sanity checks prevent urls outside of the USA to be shortened. >:(
#    'urlz.at'       :   'http://urlz.at/yourls-api.php?action=shorturl&format=simple&url=%s',
#    'pra.im'        :   'http://pra.im/api.php?url=%s',

# Bad sanity checks, won't work with urls outside of the USA,
# fails to understand what the "http://" part of the url means,
# and won't let you drop the "www" from "www.piurl.com" (why?!).
# There's only one way to describe this: EPIC FAIL.
#    'www.piurl.com' :   'http://www.piurl.com/api.php?url=%s',

}

# Exported the service names only and keep the API strings private.
shorteners = set( api.keys() )

#------------------------------------------------------------------------------

def is_short_url(url):
    """Determine if the given URL was shortened using one of the supported URL
    shortener services.

    >>> is_short_url('http://bit.ly/3hDSUb')
    True
    >>> is_short_url('http://www.example.com/')
    False

    @type  url: str
    @param url: URL to query.

    @rtype:  bool
    @return: C{True} if the URL was shortened, C{False} otherwise.
    """

    # This only checks the hostname belongs to one of the supported services.
    # It could be improved by checking the URL against a regular expression.
    return urlparse.urlparse(url)[1].lower() in shorteners

#------------------------------------------------------------------------------

def shorturl(url, service='bit.ly'):
    """Shorten a given URL.

    >>> shorturl('http://www.example.com')
    'http://bit.ly/3hDSUb'
    >>> shorturl('http://bit.ly/3hDSUb')
    'http://bit.ly/6wi02P'
    >>> shorturl('http://www.example.com', 'tinyurl.com')
    'http://tinyurl.com/7567'
    >>> shorturl('http://www.example.com', None)
    'http://www.example.com'

    @type  url: str
    @param url: URL to shorten.

    @type  service: str
    @param service: Hostname of the URL shortener service.

        See L{shorteners} for a list of supported services.

        Use C{None} or an empty string to disable URL shortening
        (returns the original URL).

    @rtype:  str
    @return: Shortened URL. May be the same as the original URL.

    @raise NotImplementedError: Unsupported or unknown URL shortener service.
    @raise RuntimeError: The URL shortener API returned an error message.
    @raise urllib2.HTTPError: A network error occured while accessing the URL
        shortener service.
    """

    # Null service, return the original URL.
    if not service:
        return url

    # Check the requested service is supported.
    service = service.lower()
    if service not in shorteners:
        raise NotImplementedError, "Unknown URL shortener service: %s" % service

    # Call the URL shortener API.
    response = urllib2.urlopen(api[service] % urllib2.quote(url))
    headers  = response.info()
    data     = response.read()

    # Fail if no data is returned.
    if not data:
        raise RuntimeError, "No data returned by URL shortener API"

    # Decode the data if needed.
    if headers['Content-Type'] == 'application/x-www-form-urlencoded':
        data = urllib2.unquote(data)
    data = data.strip() # some services add newlines and crap

    # The service may have decided the URL couldn't be shortened further.
    # I don't like this behavior but I can't help it.
    if data != url:

        # If it's neither a short URL nor the original URL, must be an error.
        if not is_short_url(data):
            raise RuntimeError, data

        # It may be tempting to check here if the resulting URL isn't
        # actually longer, but it's best to let the user decide that.
        url = data

    # Return the short URL, or the original URL if it couldn't be shortened.
    return url

#------------------------------------------------------------------------------

def longurl(url):
    """Expand a shortened URL.

    >>> longurl('http://bit.ly/3hDSUb')
    'http://www.example.com/'
    >>> longurl('http://www.example.com/')
    'http://www.example.com/'

    @type  url: str
    @param url: Shortened URL to expand.

    @rtype:  str
    @return: Expanded URL. May be the same as the original URL.

    @raise NotImplementedError: Unsupported or unknown URL shortener service.
    @raise urllib2.HTTPError: A network error occured while accessing the URL
        shortener service.
    """

    # Don't try to expand URLs for services we don't know.
    # An HTTP GET to an arbitrary location could have unwanted side effects.
    if is_short_url(url):

        # Build an opener with our customized redirect handler, then use it to
        # follow all redirections leading to known URL shortening services.
        opener = urllib2.build_opener( HTTPRedirectHandler() )
        try:
            opener.open(url)
        except urllib2.HTTPError, e:

            # Keep the relocation target.
            if e.headers.has_key('Location'):
                url = e.headers['Location']
            elif e.headers.has_key('URI'):
                url = e.headers['URI']

            # If no relocation target was given, it's a real error.
            else:
                raise

    # Return the URL as far as we could expand it.
    return url

class HTTPRedirectHandler(urllib2.HTTPRedirectHandler):
    """Modified redirect handler to prevent urllib2 from automatically
    following all redirection requests.

    We want to stop at the first redirection leading to a non-shortened URL,
    and so get the target URL. Making a request to the target itself is not
    only redundant but potentially harmful.

    Note that the original redirect handler provided by C{urllib2} already
    takes care of avoiding loops and excessively long redirection chains.

    This is a private class and you shouldn't need to use it.
    """
    def filter_shorturl_redirections(self, req, fp, code, msg, headers, method):
        if 'location' in headers:
            newurl = headers.getheaders('location')[0]
        elif 'uri' in headers:
            newurl = headers.getheaders('uri')[0]
        else:
            return

        global verbose
        if verbose:
            print "Found: %s" % newurl

        # This only checks the hostname belongs to one of the supported services.
        # If a malicious user finds a dangerous API call in one of them, we
        # could be tricked into executing it by following a redirection.
        # I can't think of any such dangerous call, though. :?
        if not is_short_url(newurl):
            return

        return method(self, req, fp, code, msg, headers)

    def http_error_301(self, req, fp, code, msg, headers):
        method = urllib2.HTTPRedirectHandler.http_error_301
        self.filter_shorturl_redirections(req, fp, code, msg, headers, method)

    def http_error_302(self, req, fp, code, msg, headers):
        method = urllib2.HTTPRedirectHandler.http_error_302
        self.filter_shorturl_redirections(req, fp, code, msg, headers, method)

    def http_error_303(self, req, fp, code, msg, headers):
        method = urllib2.HTTPRedirectHandler.http_error_303
        self.filter_shorturl_redirections(req, fp, code, msg, headers, method)

    def http_error_307(self, req, fp, code, msg, headers):
        method = urllib2.HTTPRedirectHandler.http_error_307
        self.filter_shorturl_redirections(req, fp, code, msg, headers, method)

#------------------------------------------------------------------------------

def besturl(url):
    """Shorten the URL with the service that produces the best result.

    >>> besturl('http://www.example.com/')
    'http://u.nu/63e'

    @type  url: str
    @param url: URL to shorten.

    @rtype:  str
    @return: Shortened URL. May be the same as the original URL.

    @raise urllib2.HTTPError: A network error occured while accessing the URL
        shortener service.
    """
    global verbose

    # Sort the list of shorteners by hostname length, to avoid trying services
    # which we know to be bad choices beforehand.
    best = url
    shorteners_list = [ (len(service), service) for service in shorteners ]
    shorteners_list.sort()
    for minlen, service in shorteners_list:
        if verbose:
            print "Service: %s" % service
        if len(best) < minlen + 8:      # +8 because it's "http://service/"
            break                   # it's sorted so no point in continuing
        current = shorturl(url, service)
        if len(best) > len(current):
            best = current
    return best

#------------------------------------------------------------------------------

def hideurl(url, hops = 2):
    """Hide an URL behind any given number of shorteners.
    The shorteners are chosen randomly and never repeated.

    This can defeat some URL expander browser plugins, however the L{longurl}
    function should still be able to retrieve the original URL.

    @type  url: str
    @param url: URL to shorten.

    @type  hops: int
    @param hops: How many times should the URL be shortened.
        Must be greater or equal than C{2}.

    @rtype:  str
    @return: Shortened URL.

    @raise ValueError: Too few or too many hops specified.
    @raise urllib2.HTTPError: A network error occured while accessing the URL
        shortener service.
    """
    global verbose

    # Since less than 2 hops don't hide, I flag this as an error.
    # That way I can make sure the returned URL is always hidden.
    if hops < 2:
        raise ValueError, "Too few hops: %i (min is 2)" % hops

    # Make a list of shorteners and shuffle it at random.
    shorteners_list = list( shorteners )
    random.shuffle(shorteners_list)

    # Iterate the list. Since it was shuffled iteration will be random.
    # Since it had no repetitions there's no way we can accidentally call
    # the API of the same service twice.
    index = 0
    total = len(shorteners_list)
    error = 0
    while hops > 0:
        service = shorteners_list[index]
        index = index + 1
        if index >= total:
            index = 0

        # Try to call a shortener for this hop.
        try:
            if verbose:
                print "Service: %s" % service
            new_url = shorturl(url, service)

        # Stop on network errors to avoid looping forever.
        except urllib2.HTTPError:
            raise

        # Ignore other errors, we can simply try another service.
        # If we went through the whole list failing every time,
        # then stop to avoid looping forever.
        except (NotImplementedError, RuntimeError):
            error = error + 1
            if error > total:
                raise ValueError, "Too many hops: %i" % hops
            continue

        # If the returned URL is the same as the one we had, try again.
        if url == new_url:
            error = error + 1
            if error > total:
                raise ValueError, "Too many hops: %i" % hops
            continue

        # Keep the returned URL and go to the next hop.
        url  = new_url
        hops = hops - 1

    # Return the last obtained URL.
    return url

#------------------------------------------------------------------------------

def test(url_list = None, shorteners_list = None):
    """Test this module.

    This is a private function and you shouldn't need to use it.

    >>> test()
    Testing bit.ly:
	    Short [1]: http://bit.ly/3hDSUb
	    Long  [0]: http://www.example.com/
    Testing cli.gs:
	    Short [1]: http://cli.gs/asA7h
	    Long  [0]: http://www.example.com/
    Testing cru.ms:
	    Short [1]: http://cru.ms/b250d
	    Long  [0]: http://www.example.com/
    Testing easyuri.com:
	    Short [1]: http://easyuri.com/65886
	    Long  [0]: http://www.example.com/
    Testing is.gd:
	    Short [1]: http://is.gd/61vFw
	    Long  [0]: http://www.example.com/
    Testing ito.mx:
	    Short [1]: http://ito.mx/NVt
	    Long  [0]: http://www.example.com/
    Testing kl.am:
	    Short [1]: http://kl.am/6exm
	    Long  [0]: http://www.example.com/
    Testing migre.me:
	    Short [1]: http://migre.me/g3i9
	    Long  [0]: http://www.example.com/
    Testing onodot.com:
	    Short [1]: http://onodot.com/mrxr
	    Long  [0]: http://www.example.com/
    Testing shrten.com:
	    Short [1]: http://shrten.com/bwd
	    Long  [0]: http://www.example.com/
    Testing thurly.net:
	    Short [1]: http://thurly.net//63h
	    Long  [0]: http://www.example.com/
    Testing tinyurl.com:
	    Short [1]: http://tinyurl.com/d9kp
	    Long  [0]: http://www.example.com/
    Testing tr.im:
	    Short [1]: http://tr.im/K0yJ
	    Long  [0]: http://www.example.com/
    Testing u.nu:
	    Short [1]: http://u.nu/63e
	    Long  [0]: http://www.example.com/
    Testing www.thisurl.com:
	    Short [1]: http://www.thisurl.com/186fd2
	    Long  [0]: http://www.example.com/
    Testing xrl.us:
	    Short [1]: http://xrl.us/bejo8g
	    Long  [0]: http://www.example.com/
    Testing zi.ma:
	    Short [1]: http://zi.ma/e59960
	    Long  [0]: http://www.example.com/
    """

    # Import the traceback module here rather than in the module itself.
    # This way we avoid an extra dependency that we'll only be needing
    # when testing and not during normal usage.
    import traceback

    # Process the parameters.
    if not url_list:
        url_list = ['http://www.example.com/']
    if not shorteners_list:
        shorteners_list = list(shorteners)
        shorteners_list.sort()

    # Test each service.
    # Use prints instead of returning text, to get instant feedback.
    for service in shorteners_list:
        print "Testing %s:" % service
        for url in url_list:
            try:
                short_url = shorturl(url, service)
                print "\tShort [%r]: %s" % (int(is_short_url(short_url)), short_url)
                long_url = longurl(short_url)
                print "\tLong  [%r]: %s" % (int(is_short_url(long_url)), long_url)
            except Exception:
                traceback.print_exc()

#------------------------------------------------------------------------------

def main(argv):
    """Called internally when the module is used like a command line script.

    This is a private function and you shouldn't need to use it.
    """

    # Help message and version string
    usage= "%prog [options] <URL> [more URLs...]"
    parser = optparse.OptionParser(usage=usage)

    # Commands
    commands = optparse.OptionGroup(parser, "Commands")
    commands.add_option("-s", "--short", action="store_true", dest="shorten",
                        help="get a short URL [default]")
    commands.add_option("-l", "--long", action="store_false", dest="shorten",
                        help="get a long URL")
    commands.add_option("-t", "--test", action="store_const", dest="shorten",
                        const=None, help="test supported URL shorteners")
    parser.add_option_group(commands)

    # Options
    options = optparse.OptionGroup(parser, "Options")
    options.add_option("-c", "--count", action="store", type="int", metavar="HOPS",
                       help="how many redirections to make [default: 1]")
    options.add_option("-u", "--use", action="store", metavar="NAME",
                       help="use this URL shortener [default: auto]")
    parser.add_option_group(options)

    # Output
    output = optparse.OptionGroup(parser, "Output")
    output.add_option("-q", "--quiet", action="store_false", dest="verbose",
                      help="only print the URL [default]")
    output.add_option("-v", "--verbose", action="store_true",
                      help="print log messages")
    parser.add_option_group(output)

    # Defaults
    parser.set_defaults(
        shorten = True,
        use     = "auto",
        verbose = False,
    )

    # Parse and validate the command line options
    if len(argv) == 1:
        argv = argv + [ '--help' ]
        print "URL shortener services (shorten and expand URLs)"
        print "by Mario Vilas (mvilas at gmail.com)"
        print
    (options, arguments) = parser.parse_args(argv)
    arguments = arguments[1:]

    # Process the --use switch
    options.use = options.use.strip().lower()
    if options.use == "auto":
        options.use = None
    elif options.use not in shorteners:
        msg  = "unknown URL shortener service: %s\n" % options.use
        msg += "\nThese are the currently supported URL shorteners:\n\n"
        sh_list = list(shorteners)
        sh_list.sort()
        for service in sh_list:
            msg += "\t%s\n" % service
        parser.error(msg)
    elif options.shorten is False:
        parser.error("the --use switch is NOT valid in conjunction with --long")

    # Process the --count switch
    if options.shorten is True:
        if options.count is None:
            options.count = 1
        elif options.count < 0:
            parser.error("invalid --count value: %i" % parser.count)
    elif options.count is not None:
        parser.error("the --count switch is only valid in conjunction with --short")
        # XXX TODO
        # Maybe we could test the same service multiple times with --count
        # Does that make sense?

    # Process the --verbose switch
    if options.verbose:
        global verbose
        verbose = True

    # Process and execute the command switches
    service = options.use
    count   = options.count
    if options.shorten is None:

        # Test the services
        if service is None:
            test(arguments)
        else:
            test(arguments, [service])

    elif not options.shorten:

        # Expand each URL
        for url in arguments:
            print longurl(url)

    else:
        if count == 0:

            # Output the original URLs
            for url in arguments:
                print url

        elif count == 1:

            # Shorten each URL once
            if service is None:
                for url in arguments:
                    print besturl(url)
            else:
                for url in arguments:
                    print shorturl(url, service)

        else:

            # Hide each URL using the given hop count
            if service is None:
                for url in arguments:
                    print hideurl(url, count)
            else:
                for url in arguments:
                    result = url
                    for hop in xrange(count):
                        result = shorturl(result, service)
                    print result

# Run the main() function when loaded as a command line script.
# If imported as a library module this code is ignored.
if __name__ == '__main__':
    import sys
    main(sys.argv)

#------------------------------------------------------------------------------

# XXX TODO
# Welcome to the huge list of things to be improved! :)
#
# Improvements:
#   * Cache the results.
#   * Use regular expressions in is_short_url() for more accuracy.
#   * Reuse the HTTP connection (maybe one per thread?) to reduce overhead.
#   * Use HEAD instead of GET to retrieve the long URLs (when possible).
#   * Use the longurl.com service to expand URLs when possible.
#   * Maybe multiple -u could be used instead of -c so it's not random.
#
# Features it'd be fun to have:
#   * Hide all URLs in a given email body (plaintext and/or html).
#     This can bypass some (most?) spam filters.
#   * Benchmark the speed of each URL shortener service.
#
# Features needed to support more services:
#   * More content encodings like utf-8, gzip (xav.cc)
#   * Multiple domains (shorturl.com, smrls.net, subdomaindirect.com)
#   * HTML scanning when there's no API to use (to., hugeurl.com, nsfw.in,
#     tiny.cc, urloo.com, lix.in, tnij.org, farturl.com, irt.me)
#   * POST based apis (doiop.com, tweetburner.com)
#   * XML responses (go2cut.com, xav.cc, longurl.com)
#   * JSON responses (icanhaz.com, urlenco.de, linkbee.com, rubyurl.com,
#     retwt.me, rep.ly, mtny.mobi, nd-url)
#   * AJAX based apis (lilurl.org, su.pr, fon.gs, twurl.cc)
#
# Perhaps add support for features that not all services have. Examples:
#   * Customized codes (bit.ly)
#   * Comments (l.pr)
#   * Miscellaneous metadata (cru.ms)
#   * Bulk operations (cru.ms)
#   * Authentication (clicky.me)
#   * API keys (l.pr, sni.pr)
#
# There should be two separate lists of shorteners and expanders, it's easy
#   to expand urls for many services that have no API or whose API is hard
#   to implement. See: http://userscripts.org/scripts/review/40582
#
# Some services are specific to target sites (fb.me, youtu.be, ff.im)
#   and can't be used to shorten generic urls, but may be easy to expand
#   with just a regexp. Also the shorteners and expanders for fb.me and
#   youtu.be can be trivially implemented offline. :)
#
# Put shortener code in classes, so the specifics of each service can be
#   customized - instead of having to always find a general algorithm for
#   all services (goo.gl). See: http://privatepaste.com/8ba361958b
#
# Reviewing more services I also found that some of them...
#   * need a particular HTTP header to be set (ax.ag)
#   * split the url from the anchor tag (idek.net)
#   * use unicode (tinyarro.ws)
#   * use https (urllib2 fails moronically with https behind a proxy) (apu.sh)
#   * put the code in the hostname (pra.im)
#   * force a subdirectory (beardown.ca/ts)
#   * forcefully frame the target pages (kissa.be, itshrunk.com)
#   * insert nag screens (lix.in)
#   * have cookies or similar (go2.st, bloat.me)
#   * are installable on other sites (yourls.org)
#   * password protect shortened urls (dwarfurl.com)
#   * group multiple urls together (multiurl.com)
#   * support DLC files (lix.in)
#   * hide email addresses only (tinymailto.com)
#   * only deal with pictures (pic.im)
#   * only deal with music (tra.kz)
#   * only deal with GPS coordinates (shortgps.com)
#   * allow subdirectories (piurl.com)
# Many other services share similar characteristics to the ones listed above.
