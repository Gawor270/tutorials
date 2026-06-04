#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

struct metadata {
    bit<14> nhop_select;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    icmp_t     icmp;
    tcp_t      tcp;
}

/*************************************************************************
*********************** P A R S E R  *************************************
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
            0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            1: parse_icmp;
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************ C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
************** I N G R E S S    P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Select the index of the next-hop in the routing table
    // There are `total_weight` indices and we want to choose one at random
    // using a hash modulo fuction
    action set_ucmp_select(bit<14> base, bit<14> total_weight) {
        if (hdr.tcp.isValid()) {
            hash(meta.nhop_select,
                 HashAlgorithm.crc16,
                 base,
                 { hdr.ipv4.srcAddr,
                   hdr.ipv4.dstAddr,
                   hdr.ipv4.protocol,
                   hdr.ipv4.ttl,
                   hdr.tcp.srcPort,
                   hdr.tcp.dstPort,
                   hdr.tcp.seqNo,
                   hdr.tcp.ackNo },
                 total_weight);
        } else {
            hash(meta.nhop_select,
                 HashAlgorithm.crc16,
                 base,
                 { hdr.ipv4.srcAddr,
                   hdr.ipv4.dstAddr,
                   hdr.ipv4.protocol,
                   hdr.ipv4.ttl,
                   (bit<32>)hdr.ipv4.identification },
                 total_weight);
        }
    }

    action set_nhop(bit<48> nhop_dmac, bit<9> port, bit<4> switch_id) {
        hdr.ethernet.dstAddr = nhop_dmac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        if (hdr.ipv4.protocol != 1) {
            // Add a way to differentiate paths taken by switched packets
            // We use identification field in ipv4 header to store switch_ids
            // Since there won't be many switches in our demo, this works
            if (hdr.ipv4.identification == 0) {
                hdr.ipv4.identification = (bit<16>)switch_id;
            } else {
                hdr.ipv4.identification = (hdr.ipv4.identification << 4) | (bit<16>)switch_id;
            }
        }
    }

    table ucmp_select {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ucmp_select;
        }
        size = 1024;
        default_action = drop;
    }

    table ucmp_nhop {
        key = {
            meta.nhop_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 256;
        default_action = drop;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if (ucmp_select.apply().hit) {
                ucmp_nhop.apply();
            }
        }
    }
}

/*************************************************************************
**************** E G R E S S    P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }

    action drop() {
        mark_to_drop(standard_metadata);
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
        send_frame.apply();
    }
}

/*************************************************************************
************* C H E C K S U M    C O M P U T A T I O N  **************
*************************************************************************/

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

/*************************************************************************
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
*********************** S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
