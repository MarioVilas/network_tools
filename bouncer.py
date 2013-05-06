# Cross platform TCP bouncer in Python
# by Mario Vilas (mvilas at gmail.com)

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

import socket
import os
import thread
import traceback


class TCPBouncer:
    "Forward TCP connections on the given port"

    def run( self, port, target = ('localhost', 80), logging = True ):
        "Forward TCP connections on the given port"
        self.port       = int( port )
        self.target     = target
        self.logging    = logging

        # setup a listener socket
        self.listener = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.listener.bind( ( '0.0.0.0', self.port ) )
        self.listener.listen( 256 )
        self.log( "Listening on port %d" % self.port )

        # accept incoming connections
        try:
            while 1:
                s, addr = self.listener.accept()
                self.log( "Connection received from %s:%d" % addr )

                # connect to the target
                self.log( "Connecting to %s:%d" % self.target )
                try:
                    d = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
                    d.connect(self.target)
                    self.log( "Connected to %s:%d" % self.target )
                except socket.error, e:
                    self.log( "Error: %s" % str(e) )
                    self.close( s )
                    continue

                # launch two new threads
                thread.start_new_thread( self.forward, ( s, d ) )
                thread.start_new_thread( self.forward, ( d, s ) )

        # close the listening socket
        finally:
            self.log( "Shutting down listener at port %d..." % self.port )
            self.close( self.listener )
            self.log( "Done." )

    def log( self, text ):
        "Log text to standard output, if logging is enabled"
        if self.logging:
            print text

    def read( self, fd ):
        "Read data from a socket, file object or file descriptor"
        if hasattr( fd, 'recv' ):
            data = fd.recv( 0x1000 )
        elif hasattr( fd, 'read' ):
            data = fd.read()
        else:
            data = os.read( fd, 0x1000 )
        return data

    def write( self, fd , data ):
        "Write data to a socket, file object or file descriptor"
        if hasattr( fd, 'sendall' ):
            fd.sendall( data )
        elif hasattr( fd, 'write' ):
            fd.write( data )
            fd.flush()
        elif hasattr( fd, 'send' ):
            sent = 0
            while sent < len( data ):
                d = fd.send( data )
                if d == 0:
                    break
                sent += d
                data = data[ d: ]
        else:
            sent = 0
            while sent < len( data ):
                d = os.write( fd, data )
                if d == 0:
                    break
                sent += d
                data = data[ d: ]
            if isinstance( fd, int ):
                try:
                    os.fsync( fd )
                except OSError:
                    pass

    def close( self, fd ):
        "Close a socket, file object or file descriptor"
        if hasattr( fd, 'shutdown' ):
            try:
                fd.shutdown( 2 )
            except Exception:
                pass
        if hasattr( fd, 'close' ):
            try:
                fd.close()
            except Exception:
                pass
        else:
            os.close( fd )

    def forward( self, fd1, fd2 ):
        "Forward data from one file descriptor to the other"
        try:

            # forwarding loop
            while 1:

                # read data from file descriptor 1
                try:
                    data = self.read( fd1 )
                except socket.timeout:
                    continue
                except socket.error:
                    break
                except OSError:
                    break

                if not data:
                    self.log( "Connection closed" )
                    break
                else:
                    self.log( "Received %d bytes" % len( data ) )

                # write data into file descriptor 2
                try:
                    self.write( fd2, data )
                except socket.error:
                    break
                except OSError:
                    break

        # print the traceback if an exception occurs
        except Exception:
            if traceback is not None:
                traceback.print_exc()

        # close both fd's (will trigger an exception on the other thread)
        self.close( fd1 )
        self.close( fd2 )


# to run from the command line
if __name__ == '__main__':
    import sys
    if len( sys.argv ) < 2:
        print "./%s <source port> <target ip> <target port>" % os.path.basename( sys.argv[ 0 ] )
    else:
        source_port = sys.argv[ 1 ]
        target_ip   = sys.argv[ 2 ]
        target_port = int( sys.argv[ 3 ] )
        bouncer     = TCPBouncer()
        bouncer.run( source_port, (target_ip, target_port) )
