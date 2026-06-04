#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018 Nate Foster
#
# SPDX-License-Identifier: GPL-2.0-only

"""
receive.py  –  Packet receiver for the EIGRP UCMP exercise.

Run this on h2.  It prints each arriving TCP packet along with its TTL value.
The TTL reveals which path the packet took from h1:

  Assuming h1 sends with TTL=64 and each switch decrements TTL by 1:

  TTL = 62  →  direct path    (s1 → s2 → h2,       2 hops)
  TTL = 61  →  indirect path  (s1 → s3 → s2 → h2,  3 hops)

With EIGRP weights 3:1 (fd=10, variance=4), approximately 75% of packets
should arrive with TTL=62 (direct) and 25% with TTL=61 (indirect).
"""

import os
import sys

from scapy.all import IP, TCP, Ether, get_if_list, sniff


def get_if():
    ifaces = get_if_list()
    for iface in ifaces:
        if "eth0" in iface:
            return iface
    print("Cannot find eth0 interface")
    exit(1)


def handle_pkt(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    hops = 64 - ip.ttl
    if hops == 2:
        path = "DIRECT   (s1 -> s2 -> h2)"
    elif hops == 3:
        path = "INDIRECT (s1 -> s3 -> s2 -> h2)"
    else:
        path = f"UNKNOWN  ({hops} hops from TTL=64)"

    payload = bytes(tcp.payload).decode(errors="replace").strip()
    print(
        f"[TTL={ip.ttl:3d}]  {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        f"  |  path: {path}" + (f"  |  msg: {payload!r}" if payload else "")
    )
    sys.stdout.flush()


def main():
    iface = get_if()
    print(f"Listening on {iface} for TCP packets ...")
    print(f"  TTL=62 -> direct path (s1->s2)")
    print(f"  TTL=61 -> indirect path (s1->s3->s2)")
    print()
    sys.stdout.flush()
    sniff(filter="tcp", iface=iface, prn=handle_pkt)


if __name__ == "__main__":
    main()

