#!/usr/bin/python3
#
# rickroute
# Transmit fake traceroute responses
# Version 0.1
# https://github.com/jprenken/rickroute
#
# Copyright (C) 2014-2016 James Renken <jrenken@sandwich.net>.
# Released under the terms of the GNU General Public License, version 2.
#
# Requirements:
#     Linux kernel >= 2.6.14 with nfnetlink_queue enabled
#     NetfilterQueue: https://github.com/kti/python-netfilterqueue
#     scapy-python3 (a.k.a. scapy3k): https://github.com/phaethon/scapy
#         dill: https://github.com/uqfoundation/dill
#
# Algorithm based on countertrace, which is Copyright (C) 2002 Michael C. Toren
#  <mct@toren.net> and also GPLv2.

import configparser
from netfilterqueue import NetfilterQueue
from scapy.all import *

config = configparser.ConfigParser()
config.read('/etc/rickroute.conf')

# The NFQUEUE queue number to watch. (Default: 1)
nfqueue_num = int(config['DEFAULT'].get('nfqueue', 1))

# The interface on which to send spoofed responses. (Default: eth0)
send_iface = config['DEFAULT'].get('iface', 'eth0')

# The list of fake hops: IP addresses from which to spoof responses.
fake_hops = list(filter(None, [x.strip() for x in config['DEFAULT'].get('hops').splitlines()]))

def handle_incoming_packet(nfq_packet):
    # Convert the NetfilterQueue packet to a Scapy-compatible string.
    packet = IP(nfq_packet.get_payload())
    hop = packet.ttl - 1

    # If the packet's TTL is smaller than the list of fake hops, spoof a response.
    if hop < len(fake_hops):
        spoofed_packet_ip = IP()
        spoofed_packet_ip.src = fake_hops[hop]
        spoofed_packet_ip.dst = packet.src
        spoofed_packet_ip.ttl = 255 - hop # pretend we're one hop further away

        spoofed_packet_icmp = ICMP()
        spoofed_packet_icmp.type = 11 # time exceeded
        spoofed_packet_icmp.code = 0 # TTL exceeded in transit

        # The spoofed packet's payload is 4 bytes of null padding; the request packet's IP
        # header; and the first 8 bytes of its payload.
        spoofed_packet_data = b'\x00\x00\x00\x00' + bytes(packet)[:packet.ihl] + bytes(packet.payload)[:8]

        sendp(Ether() / spoofed_packet_ip / spoofed_packet_icmp / spoofed_packet_data, iface=send_iface)
        nfq_packet.drop()
    else:
        nfq_packet.accept()

# Event loop: handle packets as they come through the netfilter queue.
nfqueue = NetfilterQueue()
nfqueue.bind(nfqueue_num, handle_incoming_packet)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()