# Cross platform remote shell implementation in Python
# by Mario Vilas (mvilas at gmail.com)

# Copyright (c) 2008-2013, Mario Vilas
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

try:
    import traceback
except ImportError:
    traceback = None


class RemoteShell:
    "Run a remote command on the given port"

    def run( self, port, shell = '/bin/sh', logging = True ):
        "Run a remote command on the given port"
        self.port       = int( port )
        self.shell      = shell
        self.logging    = logging

        # setup a listener socket
        self.listener = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.listener.bind( ( '0.0.0.0', self.port ) )
        self.listener.listen( 256 )
        self.log( "Listening on port %d" % self.port )

        # accept incoming connections
        while 1:
            s, addr = self.listener.accept()
            self.log( "Connection received from %s:%d" % addr )

            # spawn the command
            self.log( "Spawning %s" % self.shell )
            pipes               = os.popen4( self.shell )
            stdin               = pipes[ 0 ].fileno()
            stdout_and_error    = pipes[ 1 ].fileno()

            # launch two new threads
            thread.start_new_thread( self.forward, ( s, stdin, pipes ) )
            thread.start_new_thread( self.forward, ( stdout_and_error, s, pipes ) )

    def log( self, text ):
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

    def forward( self, fd1, fd2, pipes = None ):
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
        print "./%s <port> [shell]" % os.path.basename( sys.argv[ 0 ] )
    else:
        port        = sys.argv[ 1 ]
        shell       = ' '.join( sys.argv[ 2 : ] )
        rsh         = RemoteShell()
        if not shell:
            shell   = os.getenv( 'SHELL' )
        if not shell:
            shell   = os.getenv( 'ComSpec' )
        if shell:
            rsh.run( port, shell )
        else:
            rsh.run( port )
