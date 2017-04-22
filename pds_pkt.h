//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#ifndef PDS_PKT_H
#define PDS_PKT_H

#include "pds_addr.h"

#define HDR_ETH_LEN 14 // Ethernet header length
#define HDR_IPV4_LEN 20 // IPv4 header length
#define HDR_IPV6_LEN 40 // IPv6 header length
#define HDR_ARP_LEN 28 // ARP header length
#define HDR_ICMPV6_ECHOREQ_LEN 8 // ICMPv6 echo request header length
#define HDR_ICMPV6_ADVERT_LEN 32 // ICMPv6 echo request header length

#define PKT_ARP_LEN HDR_ETH_LEN + HDR_ARP_LEN
#define PKT_ICMPV6_ECHOREQ_LEN HDR_ETH_LEN + HDR_IPV6_LEN + HDR_ICMPV6_ECHOREQ_LEN
#define PKT_ICMPV6_ADVERT_LEN HDR_ETH_LEN + HDR_IPV6_LEN + HDR_ICMPV6_ADVERT_LEN

// ETH --------------------------------------------------
typedef struct {
	mac_t dst_mac;
	mac_t src_mac;
	uint16_t type;
} ethhdr_t;
//-------------------------------------------------------

// ARP --------------------------------------------------
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2
typedef struct { 
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t oper; 
	mac_t src_mac;
	ipv4_t src_ip;
	mac_t dst_mac;
	ipv4_t dst_ip;
} arphdr_t;

void arp_print(arphdr_t *arpheader);
void arp_pkt_build(uint8_t* pkt_frame, ipv4_t src_ip, ipv4_t dst_ip, mac_t src_mac, mac_t dst_mac, uint16_t oper);
//-------------------------------------------------------


// IPV6 -------------------------------------------------
typedef struct {
	uint32_t first;
	uint16_t paylen;
	uint8_t nexthdr;
	uint8_t hoplimit;
	ipv6_t src_ip;
	ipv6_t dst_ip;
} ipv6hdr_t;
//-------------------------------------------------------

// ICMPV6 -----------------------------------------------
typedef struct {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t offset;
	
	ipv6_t target_addr_adv; //for advertisement only, 0x00 otherwise
	uint8_t type_adv; //for advertisement only, 0x00 otherwise
	uint8_t length; //for advertisement only, 0x00 otherwise
	mac_t ll_addr; //for advertisement only, 0x00 otherwise
} icmpv6hdr_t;

typedef struct { //structure for computing checksum
	ipv6_t src_ip;
	ipv6_t dst_ip;
	uint32_t icmpv6len;
	uint32_t nexthdr; //always 58 (nexthdr==icmpv6)
	icmpv6hdr_t icmpv6hdr;
} chksumdata_t;

uint16_t icmpv6_checksum(uint16_t *checksum_data, int len);
uint8_t* icmpv6_pkt_echoreq_build(uint8_t* pkt_frame, mac_t ifmac, ipv6_t ifip6);
uint8_t* icmpv6_pkt_advert_build(mac_t src_mac, mac_t dst_mac, ipv6_t src_ip, ipv6_t dst_ip);
//-------------------------------------------------------

#endif