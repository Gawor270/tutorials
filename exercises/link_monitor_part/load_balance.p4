// SPDX-License-Identifier: Apache-2.0
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x0800;
const bit<16> TYPE_PROBE = 0x0812;

#define MAX_HOPS 10
#define MAX_PORTS 8

/*************************************************************************
*********************** H E A D E R S ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<6>  res;
    bit<6>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header probe_t {
    bit<8> hop_cnt;
}

header probe_data_t {
    bit<1>    bos;
    bit<7>    swid;
    bit<8>    port;
    bit<32>   byte_cnt;
    time_t    last_time;
    time_t    cur_time;
}

header probe_fwd_t {
    bit<8>    egress_spec;
}

struct parser_metadata_t {
    bit<8>    remaining;
}

struct metadata {
    bit<8>             egress_spec;
    bit<16>            nhop_select;
    bit<32>            fd;
    bit<32>            variance;
    parser_metadata_t  parser_metadata;
}

struct headers {
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    probe_t                 probe;
    probe_data_t[MAX_HOPS]  probe_data;
    probe_fwd_t[MAX_HOPS]   probe_fwd;
}

/*************************************************************************
*********************** P A R S E R *************************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_PROBE: parse_probe;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_probe {
        packet.extract(hdr.probe);
        meta.parser_metadata.remaining = hdr.probe.hop_cnt + 1;
        transition select(hdr.probe.hop_cnt) {
            0: parse_probe_fwd;
            default: parse_probe_data;
        }
    }

    state parse_probe_data {
        packet.extract(hdr.probe_data.next);
        transition select(hdr.probe_data.last.bos) {
            1: parse_probe_fwd;
            default: parse_probe_data;
        }
    }

    state parse_probe_fwd {
        packet.extract(hdr.probe_fwd.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        meta.egress_spec = (bit<8>)hdr.probe_fwd.last.egress_spec;
        transition select(meta.parser_metadata.remaining) {
            0: accept;
            default: parse_probe_fwd;
        }
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G ***********************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_ecmp_select(bit<32> fd, bit<32> variance, bit<16> base, bit<16> total_weight) {
        meta.fd = fd;
        meta.variance = variance;

        hash(meta.nhop_select,
             HashAlgorithm.crc16,
             (bit<32>)base,
             { hdr.ipv4.srcAddr,
               hdr.ipv4.dstAddr,
               hdr.ipv4.protocol,
               hdr.tcp.srcPort,
               hdr.tcp.dstPort },
             (bit<32>)total_weight);
    }

    action set_nhop(bit<48> nhop_dmac, bit<32> nhop_ipv4, bit<9> port) {
        hdr.ethernet.dstAddr = nhop_dmac;
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ecmp_select {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
        }
        size = 1024;
        default_action = drop();
    }

    table ecmp_nhop {
        key = {
            meta.nhop_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 256;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if (ecmp_select.apply().hit) {
                ecmp_nhop.apply();
            }
        }
        else if (hdr.probe.isValid()) {
            standard_metadata.egress_spec = (bit<9>)meta.egress_spec;
            hdr.probe.hop_cnt = hdr.probe.hop_cnt + 1;
        }
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<32>>(MAX_PORTS) byte_cnt_reg;
    register<time_t>(MAX_PORTS) last_time_reg;

    action set_swid(bit<7> swid) {
        hdr.probe_data[0].swid = swid;
    }

    action rewrite_mac(macAddr_t srcAddr) {
        hdr.ethernet.srcAddr = srcAddr;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table swid {
        actions = {
            set_swid;
            NoAction;
        }
        default_action = NoAction();
    }

    table send_frame {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
        size = 256;
    }

    apply {
        bit<32> byte_cnt;
        bit<32> new_byte_cnt;
        time_t last_time;
        time_t cur_time = (time_t)standard_metadata.egress_global_timestamp;

        byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
        byte_cnt = byte_cnt + (bit<32>)standard_metadata.packet_length;
        
        new_byte_cnt = (hdr.probe.isValid()) ? 0 : byte_cnt;
        byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);

        if (hdr.ipv4.isValid()) {
            send_frame.apply();
        } else if (hdr.probe.isValid()) {
            hdr.probe_data.push_front(1);
            hdr.probe_data[0].setValid();
            
            if (hdr.probe.hop_cnt == 1) {
                hdr.probe_data[0].bos = 1;
            } else {
                hdr.probe_data[0].bos = 0;
            }
            
            swid.apply();
            hdr.probe_data[0].port = (bit<8>)standard_metadata.egress_port;
            hdr.probe_data[0].byte_cnt = byte_cnt;
            
            last_time_reg.read(last_time, (bit<32>)standard_metadata.egress_port);
            last_time_reg.write((bit<32>)standard_metadata.egress_port, cur_time);
            
            hdr.probe_data[0].last_time = last_time;
            hdr.probe_data[0].cur_time = cur_time;
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.probe);
        packet.emit(hdr.probe_data);
        packet.emit(hdr.probe_fwd);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
