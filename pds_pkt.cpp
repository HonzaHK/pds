//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include "pds_pkt.h"


// ARP --------------------------------------------------
void arp_print(arphdr_t *arpheader){
	printf("src MAC: "); mac_print(arpheader->src_mac);printf("\n");
	printf("src IP : "); ipv4_print(arpheader->src_ip);printf("\n");
	printf("dst MAC: "); mac_print(arpheader->dst_mac);printf("\n");
	printf("dst IP : "); ipv4_print(arpheader->dst_ip);printf("\n");
	printf("ptype  : "); printf("%04x\n", ntohs(arpheader->ptype) );
	printf("\n");

	return;
}

uint8_t* arp_pkt_build(ipv4_t src_ip, ipv4_t dst_ip, mac_t src_mac, mac_t dst_mac, uint16_t oper){
	
	ethhdr_t ethhdr;
	memcpy(ethhdr.dst_mac, dst_mac, MAC_LEN);
	memcpy(ethhdr.src_mac, src_mac, MAC_LEN);
	ethhdr.type = htons(0x0806);
	
	arphdr_t arphdr;
	arphdr.htype = htons(1);
	arphdr.ptype = htons(0x0800);
	arphdr.hlen = MAC_LEN;
	arphdr.plen = IP4_LEN;
	arphdr.oper = htons(oper);
	memcpy(&arphdr.src_mac, src_mac, MAC_LEN);
	memcpy(&arphdr.src_ip, src_ip, IP4_LEN);
	memcpy(&arphdr.dst_mac, dst_mac, MAC_LEN); //when broadcast in eth_header (when doing scan), this is DONT_CARE
	memcpy(&arphdr.dst_ip, dst_ip, IP4_LEN);

	uint8_t* ether_frame= (uint8_t*) malloc(PKT_ARP_LEN);
	memcpy(ether_frame,&ethhdr,HDR_ETH_LEN);
	memcpy(ether_frame+HDR_ETH_LEN,&arphdr,HDR_ARP_LEN);

	return ether_frame;
}
//-------------------------------------------------------


// ICMPV6 -----------------------------------------------
uint16_t icmpv6_checksum(uint16_t *checksum_data, int len){

	uint32_t sum = 0;
	uint16_t odd_byte;
	
	while (len > 1) {
		sum += *checksum_data++;
		len -= 2;
	}
	
	if (len == 1) {
		*(uint8_t*)(&odd_byte) = * (uint8_t*)checksum_data;
		sum += odd_byte;
	}
	
	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	sum = ~sum;
	
	return sum; 
}

uint8_t* icmpv6_pkt_advert_build(mac_t src_mac, mac_t dst_mac, ipv6_t src_ip, ipv6_t dst_ip){

	ethhdr_t ethhdr;

	memcpy(ethhdr.dst_mac, dst_mac, MAC_LEN);
	memcpy(ethhdr.src_mac, src_mac, MAC_LEN);
	ethhdr.type = htons(0x86dd);

	ipv6hdr_t ipv6hdr;
	ipv6hdr.first= (6<<4);
	ipv6hdr.paylen=htons(HDR_ICMPV6_ADVERT_LEN);
	ipv6hdr.nexthdr= 0x3a;
	ipv6hdr.hoplimit=255;
	memcpy(ipv6hdr.src_ip,src_ip,IP6_LEN);
	memcpy(ipv6hdr.dst_ip,dst_ip,IP6_LEN);


	icmpv6hdr_t icmpv6hdr;
	icmpv6hdr.type=0x88;
	icmpv6hdr.code=0x00;
	icmpv6hdr.checksum=0x00;
	icmpv6hdr.offset=0x20; // flags: R|S|O|+29 zero bits
	memcpy(icmpv6hdr.target_addr_adv,src_ip,IP6_LEN);
	icmpv6hdr.type_adv=0x02;
	icmpv6hdr.length=0x01;
	memcpy(icmpv6hdr.ll_addr,src_mac,MAC_LEN);

	chksumdata_t csd;
	memcpy(csd.src_ip,ipv6hdr.src_ip,16);
	memcpy(csd.dst_ip,ipv6hdr.dst_ip,16);
	csd.icmpv6len = htonl(HDR_ICMPV6_ADVERT_LEN);
	csd.nexthdr = htonl(0x3a);
	memcpy(&csd.icmpv6hdr,&icmpv6hdr,sizeof(icmpv6hdr_t));

	icmpv6hdr.checksum=icmpv6_checksum((uint16_t *)&csd,sizeof(chksumdata_t));

	uint8_t* ether_frame= (uint8_t*) malloc(PKT_ICMPV6_ADVERT_LEN);
	memcpy(ether_frame,&ethhdr,HDR_ETH_LEN);
	memcpy(ether_frame+HDR_ETH_LEN,&ipv6hdr,HDR_IPV6_LEN);
	memcpy(ether_frame+HDR_ETH_LEN+HDR_IPV6_LEN,&icmpv6hdr,HDR_ICMPV6_ADVERT_LEN);

	return ether_frame;
}

uint8_t* icmpv6_pkt_build(mac_t ifmac, ipv6_t ifip6){
	ethhdr_t ethhdr;

	mac_t ipv6_mac_mcast;
	ipv6_mac_mcast[0] = 0x33;
	ipv6_mac_mcast[1] = 0x33;
	ipv6_mac_mcast[2] = 0x00;
	ipv6_mac_mcast[3] = 0x00;
	ipv6_mac_mcast[4] = 0x00;
	ipv6_mac_mcast[5] = 0x01;

	ipv6_t ipv6_ip_mcast;
	ipv6_ip_mcast[0]=0xff;
	ipv6_ip_mcast[1]=0x02;
	ipv6_ip_mcast[2]=ipv6_ip_mcast[3]=ipv6_ip_mcast[4]=ipv6_ip_mcast[5]=ipv6_ip_mcast[6]=ipv6_ip_mcast[7]=ipv6_ip_mcast[8]=ipv6_ip_mcast[9]=ipv6_ip_mcast[10]=ipv6_ip_mcast[11]=ipv6_ip_mcast[12]=ipv6_ip_mcast[13]=ipv6_ip_mcast[14]=0x00;
	ipv6_ip_mcast[15]=0x01;

	memcpy(ethhdr.dst_mac, &ipv6_mac_mcast, MAC_LEN);
	memcpy(ethhdr.src_mac, ifmac, MAC_LEN);
	ethhdr.type = htons(0x86dd);

	ipv6hdr_t ipv6hdr;
	ipv6hdr.first= (6<<4);
	ipv6hdr.paylen=htons(HDR_ICMPV6_ECHOREQ_LEN);
	ipv6hdr.nexthdr= 0x3a;
	ipv6hdr.hoplimit=1;
	memcpy(ipv6hdr.src_ip,ifip6,IP6_LEN);
	memcpy(ipv6hdr.dst_ip,ipv6_ip_mcast,IP6_LEN);


	icmpv6hdr_t icmpv6hdr;
	icmpv6hdr.type=0x80;
	icmpv6hdr.code=0x00;
	icmpv6hdr.checksum=0x00;
	icmpv6hdr.offset=0x00;
	//set next fields to 0x00 - only for checksum - we wont even send them
	memset(icmpv6hdr.target_addr_adv,0x00,IP6_LEN);
	icmpv6hdr.type_adv=0x00;
	icmpv6hdr.length=0x00;
	memset(icmpv6hdr.ll_addr,0x00,MAC_LEN);

	chksumdata_t csd;
	memcpy(csd.src_ip,ipv6hdr.src_ip,16);
	memcpy(csd.dst_ip,ipv6hdr.dst_ip,16);
	csd.icmpv6len = htonl(HDR_ICMPV6_ECHOREQ_LEN);
	csd.nexthdr = htonl(0x3a);
	memcpy(&csd.icmpv6hdr,&icmpv6hdr,sizeof(icmpv6hdr_t));

	icmpv6hdr.checksum=icmpv6_checksum((uint16_t *)&csd,sizeof(chksumdata_t));

	uint8_t* ether_frame= (uint8_t*) malloc(PKT_ICMPV6_ECHOREQ_LEN);
	memcpy(ether_frame,&ethhdr,HDR_ETH_LEN);
	memcpy(ether_frame+HDR_ETH_LEN,&ipv6hdr,HDR_IPV6_LEN);
	memcpy(ether_frame+HDR_ETH_LEN+HDR_IPV6_LEN,&icmpv6hdr,HDR_ICMPV6_ECHOREQ_LEN);

	return ether_frame;
}
//-------------------------------------------------------