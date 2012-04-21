#!/usr/bin/env python

# Copyright (c) 2009-2010, Mario Vilas
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

from pcapy import findalldevs, open_live
from impacket import ImpactDecoder, ImpactPacket

def get_interface():

    # Get the list of interfaces we can listen on
    ifs = findalldevs()

    # No interfaces found
    if len(ifs) == 0:
        raise RuntimeError, "Error: no available network interfaces, or you don't have enough permissions on this system."

    # A single interface was found
    if len(ifs) == 1:
        interface = ifs[0]

    # Multiple interfaces found
    else:
        print "Available network interfaces:"
        for i in xrange(len(ifs)):
            print '\t%i - %s' % (i + 1, ifs[i])
        print
        while 1:
            choice = raw_input("Choose an interface [0 to quit]: ")
            try:
                i = int(choice)
                if i == 0:
                    interface = None
                    break
                interface = ifs[i-1]
                break
            except Exception:
                pass

    # Return the selected interface
    return interface

def sniff(interface):
    print "Listening on: %s" % interface

    # Open a live capture
    reader = open_live(interface, 1500, 0, 100)

    # Set a filter to be notified only for TCP packets
    reader.setfilter('ip proto \\tcp')

    # Run the packet capture loop
    reader.loop(0, callback)

def callback(hdr, data):

    # Parse the Ethernet packet
    decoder = ImpactDecoder.EthDecoder()
    ether = decoder.decode(data)

    # Parse the IP packet inside the Ethernet packet
    iphdr = ether.child()

    # Parse the TCP packet inside the IP packet
    tcphdr = iphdr.child()

    # Only process SYN packets
    if tcphdr.get_SYN() and not tcphdr.get_ACK():

        # Get the source and destination IP addresses
        src_ip = iphdr.get_ip_src()
        dst_ip = iphdr.get_ip_dst()

        # Print the results
        print "Connection attempt %s -> %s" % (src_ip, dst_ip)

def main():
    interface = get_interface()
    if interface:
        sniff(interface)

if __name__ == "__main__":
    main()
