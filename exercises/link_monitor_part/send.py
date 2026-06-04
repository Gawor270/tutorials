#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018 Nate Foster
#
# SPDX-License-Identifier: GPL-2.0-only

"""
send.py  –  Packet sender for the EIGRP UCMP exercise.

Usage (run on h1):
  ./send.py <destination_ip> "<message>" [count]

Examples:
  ./send.py 10.0.2.2 "hello h2"          # send one packet
  ./send.py 10.0.2.2 "hello h2" 10       # send 10 packets with varying source ports

Each packet uses a random source port, so the 5-tuple hash in the P4 switch
selects different EIGRP next-hop slots across packets.  With weights 3:1
(direct:indirect), roughly 75% of packets should take the direct path
(TTL=62 at h2) and 25% the indirect path (TTL=61 at h2).
"""

import random
import socket
import sys

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0 interface")
    exit(1)


def main():
    if len(sys.argv) < 3:
        print('Usage: ./send.py <destination> "<message>" [count]')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    msg = sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) >= 4 else 1
    iface = get_if()

    print(f"Sending {count} packet(s) from {iface} to {addr}")
    print(f"  Each packet uses a random source port to vary the 5-tuple hash.")
    print()

    for i in range(count):
        sport = random.randint(49152, 65535)
        pkt = (
            Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
            / IP(dst=addr)
            / TCP(dport=1234, sport=sport)
            / msg
        )
        sendp(pkt, iface=iface, verbose=False)
        print(f"  [{i + 1}/{count}]  sport={sport}  ->  {addr}:1234")

    print("\nDone. Check h2's receive.py output for TTL values.")
    print(
        "  TTL=62 means the packet took the DIRECT path   (s1->s2,    metric=10, 75%)"
    )
    print(
        "  TTL=61 means the packet took the INDIRECT path (s1->s3->s2, metric=30, 25%)"
    )


if __name__ == "__main__":
    main()

