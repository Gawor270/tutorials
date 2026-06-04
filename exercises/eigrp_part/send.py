#!/usr/bin/env python3

import random
import socket
import sys

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    sys.exit("Error: Cannot find eth0 interface")


def main():
    if len(sys.argv) < 3:
        sys.exit('Usage: ./send.py <destination_ip> "<message>" [count]')

    dst_ip = socket.gethostbyname(sys.argv[1])
    msg = sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) >= 4 else 1
    iface = get_if()
    src_mac = get_if_hwaddr(iface)

    # Send TCP packets with randomized source ports to exercise different UCMP slots.
    for i in range(count):
        sport = random.randint(49152, 65535)
        pkt = (
            Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(dst=dst_ip, id=0)
            / TCP(dport=1234, sport=sport)
            / msg
        )
        sendp(pkt, iface=iface, verbose=False)
        print(f"Sent packet {i + 1}/{count} to {dst_ip}:1234 with source port {sport}")


if __name__ == "__main__":
    main()
