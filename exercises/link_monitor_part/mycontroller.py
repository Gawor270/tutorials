#!/home/p4/src/p4dev-python-venv/bin/python3
"""
Part B: Active link monitor + dynamic ECMP P4Runtime controller.

  1. Installs initial forwarding rules (ecmp_select / ecmp_nhop / send_frame / swid)
  2. Sends probe packets: s1-eth1 → S1p3 → S3p3 → S2p2 → S1p1 → s1-eth1
  3. Sniffs returning probes, extracts per-link bandwidth telemetry
  4. Rebalances s1's ecmp_nhop slots for dst=h2 between port-2 (direct)
     and port-3 (via S3) using inverse-proportional weights.
"""
import json
import os
import sys
import threading
import time
from collections import defaultdict

import grpc
from scapy.all import sniff, sendp, Ether, Packet, ByteField, BitField, IntField, bind_layers

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../utils/"))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4.v1 import p4runtime_pb2

# ===========================================================================
# Scapy probe protocol
# ===========================================================================
TYPE_PROBE = 0x0812

class Probe(Packet):
    fields_desc = [ByteField("hop_cnt", 0)]

class ProbeData(Packet):
    fields_desc = [
        BitField("bos", 0, 1),
        BitField("swid", 0, 7),
        ByteField("port", 0),
        IntField("byte_cnt", 0),
        BitField("last_time", 0, 48),
        BitField("cur_time", 0, 48),
    ]

class ProbeFwd(Packet):
    fields_desc = [ByteField("egress_spec", 0)]

bind_layers(Ether,     Probe,     type=TYPE_PROBE)
bind_layers(Probe,     ProbeFwd,  hop_cnt=0)
bind_layers(Probe,     ProbeData)
bind_layers(ProbeData, ProbeData, bos=0)
bind_layers(ProbeData, ProbeFwd,  bos=1)
bind_layers(ProbeFwd,  ProbeFwd)

# ===========================================================================
# Topology constants
# ===========================================================================
PROBE_IFACE     = "s1-eth1"        # s1 port-1 facing h1 — inject and receive probes
PROBE_LOOP_PATH = [3, 3, 2, 1]    # S1p3 → S3p3 → S2p2 → S1p1

# s1 ECMP for h2: fixed slot budget so dynamic updates only rewrite, never resize
S1_H2_SLOTS = 10
S1_H2_NHOPS = {
    2: {"nhop_dmac": "08:00:00:00:02:02", "nhop_ipv4": "10.0.2.2", "port": 2},
    3: {"nhop_dmac": "08:00:00:00:02:02", "nhop_ipv4": "10.0.2.2", "port": 3},
}

# ===========================================================================
# Shared state
# ===========================================================================
_lock          = threading.Lock()
switch_metrics = {}      # {swid: {port: mbps}}
s1_sw          = None    # populated after connect
p4info_h       = None    # P4InfoHelper
s1_h2_base     = 0       # base slot index for s1's h2 ecmp_nhop block


# ===========================================================================
# Helpers
# ===========================================================================

def _inv_proportional(utilization, total_slots):
    """Allocate slots inversely proportional to utilisation (busier → fewer)."""
    ports = sorted(utilization)
    inv   = {p: 1.0 / max(u, 1e-6) for p, u in utilization.items()}
    w_sum = sum(inv.values())
    remaining = total_slots
    result = {}
    for i, p in enumerate(ports):
        if i == len(ports) - 1:
            result[p] = max(1, remaining)
        else:
            s = max(1, int(round(inv[p] / w_sum * total_slots)))
            result[p] = s
            remaining -= s
    return result


def _modify_ecmp_nhop(slot, nhop):
    """Write a single ecmp_nhop entry — MODIFY first, INSERT on failure."""
    entry = p4info_h.buildTableEntry(
        table_name="MyIngress.ecmp_nhop",
        match_fields={"meta.nhop_select": slot},
        action_name="MyIngress.set_nhop",
        action_params={"nhop_dmac": nhop["nhop_dmac"],
                       "nhop_ipv4": nhop["nhop_ipv4"],
                       "port":      nhop["port"]},
    )
    req = p4runtime_pb2.WriteRequest()
    req.device_id = s1_sw.device_id
    req.election_id.low = 1
    upd = req.updates.add()
    upd.type = p4runtime_pb2.Update.MODIFY
    upd.entity.table_entry.CopyFrom(entry)
    try:
        s1_sw.client_stub.Write(req)
    except Exception:
        s1_sw.WriteTableEntry(entry)   # fallback INSERT


# ===========================================================================
# Dynamic ECMP rebalance
# ===========================================================================

def rebalance_s1_h2(s1_p3_mbps):
    """Adjust s1 ECMP slots between port-2 (direct) and port-3 (via S3)."""
    # Port-2 utilisation is unmeasured; use a small baseline so the formula
    # always produces a valid inverse weight for it.
    util = {2: 0.01, 3: max(0.01, s1_p3_mbps)}
    slots = _inv_proportional(util, S1_H2_SLOTS)
    print(f"[rebalance] s1→h2  p2:{slots[2]} slots  p3:{slots[3]} slots"
          f"  (p3 util={s1_p3_mbps:.3f} Mbps)")
    slot = s1_h2_base
    for port in [2, 3]:
        nhop = S1_H2_NHOPS[port]
        for _ in range(slots[port]):
            _modify_ecmp_nhop(slot, nhop)
            slot += 1


# ===========================================================================
# Probe packet processing
# ===========================================================================

def _process_probe(pkt):
    if not pkt.haslayer(ProbeData):
        return
    layer = pkt[ProbeData]
    while isinstance(layer, ProbeData):
        swid     = layer.swid
        port     = layer.port
        dt       = layer.cur_time - layer.last_time
        mbps     = (layer.byte_cnt * 8) / float(dt) if dt > 0 else 0.0
        with _lock:
            switch_metrics.setdefault(swid, {})[port] = mbps
        print(f"  [probe] sw={swid} port={port}: {mbps:.3f} Mbps")
        nxt = layer.payload
        layer = nxt if isinstance(nxt, ProbeData) else None

    with _lock:
        p3 = switch_metrics.get(1, {}).get(3, 0.0)
    if s1_sw is not None:
        rebalance_s1_h2(p3)


def sniff_worker():
    print(f"[*] Sniffing on {PROBE_IFACE} (ethertype 0x{TYPE_PROBE:04x})…")
    sniff(iface=PROBE_IFACE,
          filter=f"ether proto 0x{TYPE_PROBE:04x}",
          prn=_process_probe,
          store=False)


def probe_worker():
    print(f"[*] Injecting probes on {PROBE_IFACE}…")
    while True:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:01:00", type=TYPE_PROBE)
        pkt /= Probe(hop_cnt=0)
        for port in PROBE_LOOP_PATH:
            pkt /= ProbeFwd(egress_spec=port)
        sendp(pkt, iface=PROBE_IFACE, verbose=False)
        time.sleep(1.5)


# ===========================================================================
# Initial rule installation
# ===========================================================================

def _install_rules(p4info_helper, sw, conf_path, swid):
    global s1_h2_base
    with open(conf_path) as f:
        conf = json.load(f)
    eigrp    = conf["eigrp"]
    variance = eigrp["variance"]
    paths    = eigrp["paths"]
    sframe   = eigrp.get("send_frame", {})

    # Default drop
    sw.WriteTableEntry(p4info_helper.buildTableEntry(
        table_name="MyIngress.ecmp_select",
        default_action=True,
        action_name="MyIngress.drop",
        action_params={},
    ))

    by_dest = defaultdict(list)
    for p in paths:
        by_dest[p["destination"]].append(p)

    next_base = 0
    for dest in sorted(by_dest):
        dest_paths = by_dest[dest]
        ip_str, pfx = dest.split("/")
        fd        = min(p["metric"] for p in dest_paths)
        threshold = variance * fd
        eligible  = [p for p in dest_paths if p["metric"] <= threshold]
        if not eligible:
            continue

        is_s1_h2     = (sw.name == "s1" and dest == "10.0.2.2/32")
        total_weight = S1_H2_SLOTS if is_s1_h2 else len(eligible)

        sw.WriteTableEntry(p4info_helper.buildTableEntry(
            table_name="MyIngress.ecmp_select",
            match_fields={"hdr.ipv4.dstAddr": (ip_str, int(pfx))},
            action_name="MyIngress.set_ecmp_select",
            action_params={"fd": fd, "variance": variance,
                           "base": next_base, "total_weight": total_weight},
        ))

        if is_s1_h2:
            s1_h2_base   = next_base
            slots_each   = S1_H2_SLOTS // len(eligible)
            slot         = next_base
            for path in eligible:
                for _ in range(slots_each):
                    sw.WriteTableEntry(p4info_helper.buildTableEntry(
                        table_name="MyIngress.ecmp_nhop",
                        match_fields={"meta.nhop_select": slot},
                        action_name="MyIngress.set_nhop",
                        action_params={"nhop_dmac": path["nhop_dmac"],
                                       "nhop_ipv4": path["nhop_ipv4"],
                                       "port":      path["port"]},
                    ))
                    slot += 1
            next_base += S1_H2_SLOTS
        else:
            slot = next_base
            for path in eligible:
                sw.WriteTableEntry(p4info_helper.buildTableEntry(
                    table_name="MyIngress.ecmp_nhop",
                    match_fields={"meta.nhop_select": slot},
                    action_name="MyIngress.set_nhop",
                    action_params={"nhop_dmac": path["nhop_dmac"],
                                   "nhop_ipv4": path["nhop_ipv4"],
                                   "port":      path["port"]},
                ))
                slot += 1
            next_base = slot

    for port_str, smac in sframe.items():
        sw.WriteTableEntry(p4info_helper.buildTableEntry(
            table_name="MyEgress.send_frame",
            match_fields={"standard_metadata.egress_port": int(port_str)},
            action_name="MyEgress.rewrite_mac",
            action_params={"srcAddr": smac},
        ))

    sw.WriteTableEntry(p4info_helper.buildTableEntry(
        table_name="MyEgress.swid",
        default_action=True,
        action_name="MyEgress.set_swid",
        action_params={"swid": swid},
    ))

    print(f"[+] Rules installed on {sw.name}")


# ===========================================================================
# Entry point
# ===========================================================================

def main():
    global s1_sw, p4info_h

    p4info_file = "./build/load_balance.p4.p4info.txtpb"
    bmv2_file   = "./build/load_balance.json"

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file)
    p4info_h      = p4info_helper

    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name="s1", address="127.0.0.1:50051", device_id=0,
            proto_dump_file="logs/s1-p4runtime-requests.txt")
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name="s2", address="127.0.0.1:50052", device_id=1,
            proto_dump_file="logs/s2-p4runtime-requests.txt")
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name="s3", address="127.0.0.1:50053", device_id=2,
            proto_dump_file="logs/s3-p4runtime-requests.txt")

        for sw in [s1, s2, s3]:
            sw.MasterArbitrationUpdate()
            sw.SetForwardingPipelineConfig(
                p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file)
            print(f"[+] Loaded P4 pipeline on {sw.name}")

        _install_rules(p4info_helper, s1, "s1-runtime.json", swid=1)
        _install_rules(p4info_helper, s2, "s2-runtime.json", swid=2)
        _install_rules(p4info_helper, s3, "s3-runtime.json", swid=3)

        s1_sw = s1

        threading.Thread(target=sniff_worker, daemon=True).start()
        probe_worker()

    except KeyboardInterrupt:
        print("\n[!] Stopping.")
    except grpc.RpcError as e:
        printGrpcError(e)
    finally:
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    main()
