//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include <arpa/inet.h>

#include "pds_addr.h"
#include "pds_pkt.h"
#include "pds_host.h"

typedef struct {
	char* ifName;
	char* fileName;
} clargs_t;

host_t hosts[HOST_MAX_CNT];
int host_cnt=0;

int parseArgs(int argc, char* argv[], clargs_t *clargs){

	if(argc!=5){return 1;}

	for(int i=1;i<argc;i++){
		if(strcmp(argv[i],"-i")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			clargs->ifName=argv[i];
		}
		else if(strcmp(argv[i],"-f")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			clargs->fileName=argv[i];
		}
		else{
			return 1;
		}
	}

	return 0;
}

void my_callback(u_char *params,const struct pcap_pkthdr* pkthdr,const u_char* pkt){
	UNUSED(params);UNUSED(pkthdr);
	
	ethhdr_t* ethhdr = (ethhdr_t*) pkt;
	arphdr_t* arphdr = (arphdr_t*)(pkt+HDR_ETH_LEN);
	ipv6hdr_t* ipv6hdr = (ipv6hdr_t*)(pkt+HDR_ETH_LEN);
	if (ntohs(arphdr->htype)==1 && ntohs(arphdr->ptype)==0x0800){
		//printf("arp---------------------------------\n");
		host_t *h = host_lookup(hosts,host_cnt,arphdr->src_mac);
		if(h==NULL){ //add new host
			h = host_add(hosts,host_cnt,arphdr->src_mac);
			host_cnt++;
		}
		host_add_ipv4(h,arphdr->src_ip);

	}
	else if (ipv6hdr->nexthdr==0x3a){
		//printf("icmpv6------------------------------\n");
		host_t *h = host_lookup(hosts,host_cnt,ethhdr->src_mac);
		if(h==NULL){ //add new host
			h = host_add(hosts,host_cnt,ethhdr->src_mac);
			host_cnt++;
		}
		host_add_ipv6(h,ipv6hdr->src_ip);

	}
}

void ipv6_scan(pcap_t* ifHandle,mac_t ifmac, ipv6_t ifip6){

	uint8_t pkt[PKT_ICMPV6_ECHOREQ_LEN];
	icmpv6_pkt_echoreq_build(pkt,ifmac,ifip6);
	int bytes_wr=pcap_inject(ifHandle,pkt,PKT_ICMPV6_ECHOREQ_LEN);
	//printf("%d\n", bytes_wr);
}

void ipv4_scan(in_addr netw, in_addr mask, mac_t src_mac, ipv4_t src_ip, pcap_t* ifHandle){

	char netw_str[13];
	char mask_str[13];

	strcpy(netw_str, inet_ntoa(netw));
	if (netw_str == NULL){ perror("inet_ntoa"); return; }
	strcpy(mask_str, inet_ntoa(mask));
	if (mask_str == NULL){ perror("inet_ntoa"); return; }

	in_addr mask_full;
	inet_aton("255.255.255.255",&(mask_full));
	int devcnt = ntohl(mask_full.s_addr-mask.s_addr);

	mac_t ipv4_mac_bcast;
	memset(ipv4_mac_bcast,0xff,MAC_LEN);

	for (int i=0;i<(devcnt-1);i++){
		in_addr tmp;
		tmp.s_addr = htonl(ntohl(netw.s_addr) + (i+1));
		uint8_t pkt[PKT_ARP_LEN];
		arp_pkt_build(pkt,src_ip, *((ipv4_t*)&tmp.s_addr), src_mac, ipv4_mac_bcast, ARP_OP_REQUEST);
		int bytes_written = pcap_inject(ifHandle, pkt, PKT_ARP_LEN);
		//printf("%d< ",bytes_written );
		//pcap_dispatch(ifHandle,0,my_callback,NULL);
		//usleep(50000);
		//free(pkt);
	}
	return;
}

int main(int argc, char* argv[]){

	clargs_t clargs;
	iface_t iface;
	for(int i=0;i<HOST_MAX_CNT;i++){
	hosts[i].cnt_ipv6=0;
}

	if(parseArgs(argc,argv,&clargs)!=0){
		return 0;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	if ((iface.handle=pcap_create(clargs.ifName,errbuf))==NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", clargs.ifName, errbuf);
		return 0;
	}
	iface.name=clargs.ifName;

	struct in_addr netw;
	struct in_addr mask;
	int lookup_return_code = pcap_lookupnet(
		clargs.ifName,
		&netw.s_addr,
		&mask.s_addr,
		errbuf
	);
	if(lookup_return_code!=0){ printf("lookup err\n"); return 0;}

	get_if_addrs(iface.name,&iface);

	pcap_activate(iface.handle);
	ipv4_scan(netw,mask,iface.mac,iface.ipv4,iface.handle);
	ipv6_scan(iface.handle,iface.mac,iface.ipv6);
	sleep(5);
	pcap_dispatch(iface.handle,0,my_callback,NULL);
	
	pcap_close(iface.handle);
	hostsToXml(hosts,host_cnt,clargs.fileName);

	return 0;
}