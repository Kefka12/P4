/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

//定义ARP所需各类常量
const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

//定义ARP包头字段
header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    mac_addr_t  sha;
    ipv4_addr_t spa;
    mac_addr_t  tha;
    ipv4_addr_t tpa;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
 ***********************  M E T A D A T A  *******************************
 *************************************************************************/
        /*  定义项目的全局metadata */

struct my_metadata_t {
    ipv4_addr_t dst_ipv4;
    mac_addr_t  mac_da;
    mac_addr_t  mac_sa;
    port_id_t   egress_port;
    mac_addr_t  my_mac;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    //parse开始状态,默认进入
    state start {
        /* TODO: add parser logic */
         transition parse_ethernet; 
         //进入开始状态，使用transition切换parse的状态，使其进入自定义的parse_ethernet等待下一步操作
    }
    //建立ARP解析器
   state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }       

    state parse_ethernet {
        packet.extract(hdr.ethernet);//使用extract进行抽取报文操作，并将报文指针前移。
        //根据当前data的值切换不同状态
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;//如果data为IPV4类型，切换进入ipv4parser过程
            default: accept;//缺省默认接受
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);//使用extract进行抽取IPV4报文操作，并将报文指针前移。
        transition accept;//操作结束，转为接受状态
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
   action set_dst_info(mac_addr_t mac_da,
                        mac_addr_t mac_sa,
                        port_id_t  egress_port)
    {
        meta.mac_da      = mac_da;
        meta.mac_sa      = mac_sa;
        meta.egress_port = egress_port;
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
        //接下来分四个步骤编写action动作体已完成ipv4_forward()动作
        standard_metadata.egress_spec = port;//设置下一跳的出口端口
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;//用下一跳的地址更新以太网目标地址
        hdr.ethernet.dstAddr = dstAddr;//用交换机的地址更新以太网源地址
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;//递减TTL
    }
    //arp回复动作
    action send_arp_reply() {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;
        hdr.ethernet.srcAddr = meta.mac_da;
        
        hdr.arp.oper         = ARP_OPER_REPLY;
        
        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;
        hdr.arp_ipv4.sha     = meta.mac_da;
        hdr.arp_ipv4.spa     = meta.dst_ipv4;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    //arp动作表
   table forward {
        key = {
            hdr.arp.isValid()      : exact;
            hdr.arp.oper           : ternary;
            hdr.arp_ipv4.isValid() : exact;
            hdr.ipv4.isValid()     : exact;
        }
        actions = {
            forward_ipv4;
            send_arp_reply;
            send_icmp_reply;
            drop;
        }
        const default_action = drop();
        const entries = {
            ( true, ARP_OPER_REQUEST, true, false ) :
                                                         send_arp_reply();
            ( false, _,               false, true) :
                                                         forward_ipv4();
            
        }
    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        /* TODO: fix ingress control logic
         *  - ipv4_lpm should be applied only when IPv4 header is valid
         */
        if(hdr.ipv4.isValid())//根据提示和后续代码，保证IPV4头指针有效时进入下一步
        {meta.my_mac = 0x000102030405;
        ipv4_lpm.apply();
        forward.apply();
         update();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
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
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
        //增加反解析器以决定将字段插入传出数据包的顺序
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ethernet);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
