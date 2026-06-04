#!/usr/bin/env python3

import sys
from collections import Counter

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sniff


def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    sys.exit("Error: Cannot find eth0 interface")


class Tracker:
    def __init__(self, iface):
        self.total_packets = 0
        self.path_counts = Counter()
        self.local_mac = get_if_hwaddr(iface).lower()

    def decode_path(self, path_id):
        if path_id == 0:
            return "unknown"

        switches = []
        while path_id:
            switches.append(f"s{path_id & 0xF}")
            path_id >>= 4
        return " -> ".join(reversed(switches))

    def print_summary(self):
        print(f"Total packets: {self.total_packets}")
        for path, count in sorted(self.path_counts.items()):
            percent = count * 100 / self.total_packets
            print(f"{path}: {count} ({percent:.1f}%)")
        print()

    def handle_packet(self, pkt):
        if Ether not in pkt or IP not in pkt or TCP not in pkt:
            return
        if pkt[Ether].src.lower() == self.local_mac:
            return

        path = self.decode_path(pkt[IP].id)
        self.total_packets += 1
        self.path_counts[path] += 1

        print(
            f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} path: {path}"
        )
        self.print_summary()
        sys.stdout.flush()


def main():
    iface = get_if()
    tracker = Tracker(iface)
    print(f"Listening on {iface}")
    sniff(filter="tcp", iface=iface, prn=tracker.handle_packet)


if __name__ == "__main__":
    main()
