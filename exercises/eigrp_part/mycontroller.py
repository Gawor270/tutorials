#!/usr/bin/env python3

import json
import os
import sys
from argparse import ArgumentParser
from collections import deque

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../utils/")
)

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections


def compute_weights(paths, max_total_slots=10):
    if not paths:
        return []

    inv_metrics = [1.0 / path["metric"] for path in paths]
    total = sum(inv_metrics)
    return [
        max(1, int(round((metric / total) * max_total_slots))) for metric in inv_metrics
    ]


def build_network_graph(topo):
    graph = {}
    for link in topo.get("link_metrics", []):
        graph.setdefault(link["from"], []).append(
            {
                "to": link["to"],
                "port": int(link["from_port"]),
                "metric": int(link["metric"]),
                "nhop_mac": link["next_hop_mac"],
            }
        )
    return graph


def find_all_paths(graph, start, end):
    """Return all loop-free paths between two switches, using BFS."""
    paths = []
    queue = deque([(start, [])])

    while queue:
        node, path = queue.popleft()
        if node == end:
            paths.append(path)
            continue

        visited = {start, *(edge["to"] for edge in path)}
        for edge in graph.get(node, []):
            if edge["to"] not in visited:
                queue.append((edge["to"], path + [edge]))

    return paths


def best_paths_by_port(paths, start):
    candidates = {}
    for path in paths:
        metric = sum(edge["metric"] for edge in path)
        first_hop = path[0]
        port = first_hop["port"]
        candidate = {
            "path": [start] + [edge["to"] for edge in path],
            "port": port,
            "metric": metric,
            "nhop_dmac": first_hop["nhop_mac"],
        }
        if port not in candidates or metric < candidates[port]["metric"]:
            candidates[port] = candidate
    return list(candidates.values())


def program_local_routes(p4info_helper, sw, sw_name, topo, switch_id):
    for host_ip, host_info in topo.get("hosts", {}).items():
        conn = host_info.get("connected_to", {})
        if conn.get("switch") != sw_name:
            continue

        ip_addr, prefix = host_ip.split("/")
        port = int(conn["port"])

        # Route directly attached host traffic to the local next-hop slot.
        sw.WriteTableEntry(
            p4info_helper.buildTableEntry(
                table_name="MyIngress.ucmp_select",
                match_fields={"hdr.ipv4.dstAddr": (ip_addr, int(prefix))},
                action_name="MyIngress.set_ucmp_select",
                action_params={"base": 0, "total_weight": 1},
            )
        )

        # Forward the local next-hop slot out the host-facing port.
        sw.WriteTableEntry(
            p4info_helper.buildTableEntry(
                table_name="MyIngress.ucmp_nhop",
                match_fields={"meta.nhop_select": 0},
                action_name="MyIngress.set_nhop",
                action_params={
                    "nhop_dmac": host_info["mac"],
                    "port": port,
                    "switch_id": switch_id,
                },
            )
        )


def program_remote_routes(p4info_helper, sw, sw_name, topo, graph, switch_id):
    for dest in sorted(topo.get("hosts", {})):
        dest_switch = topo["hosts"][dest]["connected_to"]["switch"]
        if dest_switch == sw_name:
            continue

        dest_ip, prefix_len = dest.split("/")
        base_slot = int(dest_ip.split(".")[2]) * 30
        paths = best_paths_by_port(find_all_paths(graph, sw_name, dest_switch), sw_name)
        if not paths:
            continue

        variance = topo.get("switches", {}).get(sw_name, {}).get("variance", 1)
        feasible_distance = min(path["metric"] for path in paths)
        eligible = [
            path for path in paths if path["metric"] <= variance * feasible_distance
        ]
        weights = compute_weights(eligible)
        total_weight = sum(weights)
        if total_weight == 0:
            continue

        for path, weight in zip(eligible, weights):
            share = weight * 100 / total_weight
            print(
                f"{sw_name} to {dest}: {' -> '.join(path['path'])} gets "
                f"{weight}/{total_weight} slots ({share:.1f}%)"
            )

        # Select the weighted next-hop slot range for the destination subnet.
        sw.WriteTableEntry(
            p4info_helper.buildTableEntry(
                table_name="MyIngress.ucmp_select",
                match_fields={"hdr.ipv4.dstAddr": (dest_ip, int(prefix_len))},
                action_name="MyIngress.set_ucmp_select",
                action_params={"base": base_slot, "total_weight": total_weight},
            )
        )

        slot = base_slot
        for path, weight in zip(eligible, weights):
            for _ in range(weight):
                # Map each weighted slot to its selected next hop.
                sw.WriteTableEntry(
                    p4info_helper.buildTableEntry(
                        table_name="MyIngress.ucmp_nhop",
                        match_fields={"meta.nhop_select": slot},
                        action_name="MyIngress.set_nhop",
                        action_params={
                            "nhop_dmac": path["nhop_dmac"],
                            "port": int(path["port"]),
                            "switch_id": switch_id,
                        },
                    )
                )
                slot += 1


def program_mac_rewrites(p4info_helper, sw, port_macs):
    for port, src_mac in port_macs.items():
        # Rewrite the source MAC for frames leaving each switch port.
        sw.WriteTableEntry(
            p4info_helper.buildTableEntry(
                table_name="MyEgress.send_frame",
                match_fields={"standard_metadata.egress_port": int(port)},
                action_name="MyEgress.rewrite_mac",
                action_params={"smac": src_mac},
            )
        )


def program_switch(p4info_helper, sw, sw_name, topo, graph):
    switch_config = topo.get("switches", {}).get(sw_name, {})
    switch_id = int(sw_name[1:])

    # Drop traffic that does not match a UCMP route.
    sw.WriteTableEntry(
        p4info_helper.buildTableEntry(
            table_name="MyIngress.ucmp_select",
            default_action=True,
            action_name="MyIngress.drop",
            action_params={},
        )
    )

    program_local_routes(p4info_helper, sw, sw_name, topo, switch_id)
    program_remote_routes(p4info_helper, sw, sw_name, topo, graph, switch_id)
    program_mac_rewrites(p4info_helper, sw, switch_config.get("macs", {}))


def main(topo_metrics_file):
    with open(topo_metrics_file) as f:
        topo = json.load(f)

    graph = build_network_graph(topo)
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(
        "./build/load_balance.p4.p4info.txtpb"
    )
    bmv2_json = "./build/load_balance.json"

    try:
        switch_names = sorted(topo.get("switches", {}), key=lambda name: int(name[1:]))
        for name in switch_names:
            switch_id = int(name[1:])
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name, f"127.0.0.1:{50050 + switch_id}", switch_id - 1
            )
            sw.MasterArbitrationUpdate()
            sw.SetForwardingPipelineConfig(
                p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_json
            )
            program_switch(p4info_helper, sw, name, topo, graph)
    finally:
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("metrics_file_name")
    args = parser.parse_args()
    main(args.metrics_file_name)
