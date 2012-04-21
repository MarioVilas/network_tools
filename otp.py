#!/usr/bin/env python

# One-time pad example in Python
# Copyright (c) 2009-2011, Mario Vilas
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

from __future__ import with_statement

import sys
import os.path
import optparse

try:
    import psyco
    from psyco.classes import *
except ImportError:
    pass

class OneTimePad(object):
    """
This is a simple one-time pad cipher implementation in Python.
For more information on one-time pads:
  http://en.wikipedia.org/wiki/One-time_pad

A word of warning: while I made my best effort to avoid programming mistakes
and one time pads are not that hard to implement, I'm not a cryptographer. So
until a proper cryptographer can validate this code, use it at your own risk!

It's best to use /dev/random here, instead of the "random" module. The reason
for that is that the random module doesn't truly provide random numbers, but
pseudo-random numbers that are calculated from a seed number. So the entire
amount of information contained in a stream of pseudo-random numbers fits
into the seed number... using this would be no more secure than just picking
a single number, defeating the whole purpose of using a one-time pad.

It's also not a good idea to limit /dev/random to printable characters only,
so if the user wants printable files we'll have to proceed as usual and later
encode the results.

One-time pad generation only works on Unix systems, but it should be possible
to port it to Windows by deriving this class and reimplementing the check_dev()
and random() methods to use Win32 crypto API. Encryption and decryption should
work in all platforms.
    """

    # Buffer size for file access
    block_size = 65536

    # Paranoid mode (use /dev/random instead of the faster /dev/urandom)
    paranoid = False

    # Placeholder for random generator device (open file)
    dev = None

    # Check for the presence of the required random generator device
    def check_dev(self):
        if self.paranoid:
            return os.path.exists('/dev/random')
        return os.path.exists('/dev/urandom')

    # Generate a string of random bytes
    def random(self, size):
        if not self.dev:
            if self.paranoid:
                self.dev = open('/dev/random', 'r')
            else:
                self.dev = open('/dev/urandom', 'r')
        return self.dev.read(size)

    # Get the size of an open file
    def filesize(self, fd):
        fd.seek(0,2)
        n = fd.tell()
        fd.seek(0,0)
        return n

    # Generate a random one-time pad
    def generate(self, padfile, total_size):
        random = self.random
        block_size = self.block_size
        while total_size > 0:
            block = random( min(block_size, total_size) )
            padfile.write(block)
            total_size = total_size - len(block)

    # Encrypt or decrypt a file using a one-time pad
    def cipher(self, infile, outfile, padfile):
        block_size = self.block_size
        while 1:
            data = infile.read(block_size)
            if not data:
                break
            pad = padfile.read(len(data))
            encoded = ''.join([ chr(ord(a) ^ ord(b)) for a, b in zip(data, pad) ])
            outfile.write(encoded)

    # Main function (most of it is command line parsing stuff)
    def run(self):

        # Define a command line parser
        banner = (
            "One-time pad example in Python\n"
            "by Mario Vilas (mvilas at gmail dot com)\n"
            "http://breakingcode.wordpress.com/"
                        "2010/02/17/one-time-pad-encryption-in-python\n"
        )
        usage = (
            "\n\n"
            "Create a one-time pad:\n"
            "    ./%prog generate -k example.key -s size\n"
            "    ./%prog generate -k example.key -t example.txt\n"
            "Encrypt a file:\n"
            "    ./%prog encrypt -t example.txt -k example.key -c example.cipher\n"
            "Decrypt a file:\n"
            "    ./%prog decrypt -c example.cipher -k example.key -t example.txt"
        )
        formatter = MyHelpFormatter(banner, max_help_position=26)
        parser = optparse.OptionParser(usage=usage, formatter=formatter)
        parser.add_option("-t", "--text", action="store", type="string",
                          metavar="FILE", help="plaintext filename")
        parser.add_option("-c", "--cipher", action="store", type="string",
                          metavar="FILE", help="ciphertext filename")
        parser.add_option("-k", "--key", action="store", type="string",
                          metavar="FILE", help="one-time pad filename")
        parser.add_option("-s", "--size", action="store", type="int",
                          metavar="NUM", help="one-time pad size in bytes")
        parser.add_option("-f", "--force", action="store_true", default=False,
                          help="force overwriting of any output files")
        parser.add_option("-p", "--paranoid", action="store_true", default=False,
                          help="use /dev/random instead of /dev/urandom (slower!)")

        # Parse the command line
        args = list(sys.argv)
        if len(args) == 1:
            args = args + [ '--help' ]
        options, args = parser.parse_args(args)

        # Set paranoid mode if requested
        self.paranoid = options.paranoid

        # Check command is present
        if len(args) < 2:
            parser.error("missing command")
        command = args[1].strip().lower()[0:1]
        if not command:
            parser.error("missing command")

        # If more parameters are present, try to guess what they are
        if len(args) > 2:
            p = 2
            try:
                if command == 'g':
                    # g key size
                    # g key text
                    if not options.key:
                        options.key = args[p]
                        p = p + 1
                    try:
                        options.size = int(args[p])
                        p = p + 1
                    except ValueError:
                        options.text = args[p]
                        p = p + 1
                elif command == 'e':
                    # e text key cipher
                    if not options.text:
                        options.text = args[p]
                        p = p + 1
                    if not options.key:
                        options.key = args[p]
                        p = p + 1
                    if not options.cipher:
                        options.cipher = args[p]
                        p = p + 1
                elif command == 'd':
                    # d cipher key text
                    if not options.cipher:
                        options.cipher = args[p]
                        p = p + 1
                    if not options.key:
                        options.key = args[p]
                        p = p + 1
                    if not options.text:
                        options.text = args[p]
                        p = p + 1
                else:
                    parser.error("too many arguments")
            except IndexError:
                pass
            if p < len(args):
                parser.error("too many arguments")

        # The one-time pad filename is always required
        if not options.key:
            parser.error("missing one-time pad filename")

        # Plaintext and ciphertext files are required for "decrypt" and "encrypt"
        if command in ('d', 'e'):
            if not options.text:
                parser.error("missing plaintext filename")
            if not options.cipher:
                parser.error("missing ciphertext filename")

        # Generate a one-time pad file
        if command == 'g':
            if options.cipher:
                parser.error("unused argument: ciphertext filename")
            if not self.check_dev():
                parser.error("random generator not available")
            if not options.force and os.path.exists(options.key):
                parser.error("file already exists: %s" % options.key)
            if options.text:
                if not os.path.exists(options.text):
                    parser.error("can't find file: %s" % options.text)
                with open(options.text, 'r') as textfile:
                    size = self.filesize(textfile)
            elif options.size:
                size = options.size
            else:
                parser.error("either plaintext file or one-time pad size is required")
            with open(options.key, 'w') as padfile:
                self.generate(padfile, size)

        # Encrypt a file using a one-time pad
        elif command == 'e':
            if not os.path.exists(options.key):
                parser.error("can't find file: %s" % options.key)
            if not os.path.exists(options.text):
                parser.error("can't find file: %s" % options.text)
            if not options.force and os.path.exists(options.cipher):
                parser.error("file already exists: %s" % options.cipher)
            with open(options.key, 'r') as padfile:
                with open(options.text, 'r') as textfile:
                    if self.filesize(textfile) > self.filesize(padfile):
                        raise RuntimeError("Not enough bytes in the one-time pad for this file!")
                    with open(options.cipher, 'w') as cipherfile:
                        self.cipher(textfile, cipherfile, padfile)

        # Decrypt a file using a one-time pad
        elif command == 'd':
            if not os.path.exists(options.key):
                parser.error("can't find file: %s" % options.key)
            if not os.path.exists(options.cipher):
                parser.error("can't find file: %s" % options.cipher)
            if not options.force and os.path.exists(options.text):
                parser.error("file already exists: %s" % options.text)
            with open(options.key, 'r') as padfile:
                with open(options.cipher, 'r') as cipherfile:
                    if self.filesize(cipherfile) > self.filesize(padfile):
                        raise RuntimeError("Not enough bytes in the one-time pad for this file!")
                    with open(options.text, 'w') as textfile:
                        self.cipher(cipherfile, textfile, padfile)

        # Unknown command
        else:
            parser.error("unknown command: %s" % args[1])

# Just a small tweak to optparse to be able to print a banner.
# (Why is there an epilog but no prolog in optparse?)
class MyHelpFormatter(optparse.IndentedHelpFormatter):
    def __init__(self, banner, *argv, **argd):
        self.banner = banner
        optparse.IndentedHelpFormatter.__init__(self, *argv, **argd)
    def format_usage(self, usage):
        msg = optparse.IndentedHelpFormatter.format_usage(self, usage)
        return '%s\n%s' % (self.banner, msg)

# Run from the command line, try to use Psyco for acceleration
if __name__ == "__main__":
    try:
        psyco.full()
    except NameError:
        pass
    OneTimePad().run()
