//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <unistd.h>
#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h> // ETH_P_ARP = 0x0806
// #include <sys/socket.h>
// #include <netdb.h>
// #include <ifaddrs.h>
// #include <linux/if_link.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
//#include <netinet/if_ether.h>
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

typedef struct {
	char* ifName;
	char *ifPtr;
	pcap_t *ifHandle;

	char* fileName;
	FILE* filePtr;

	ipv4_t ifip4; //current interface ip addr
	mac_t ifmac; //current interface mac addr
} clargs_t;

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
	
	
typedef struct host {
	u_char mac[6];
	ipv4_t ipv4;
} host_t;

host_t hosts[64];
int host_cnt=0;


int parseArgs(int argc, char* argv[], clargs_t *clargs){

	int arg;
	while ((arg = getopt (argc, argv, "i:f:")) != -1)
	switch (arg){
		case 'i':
			clargs->ifName = optarg;
			break;
		case 'f':
			clargs->fileName = optarg;
			break;
		case '?':
			if (optopt == 'i' || optopt == 'f'){
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			} 
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
			return 1;
		default:
			//abort ();
			return 1;
	}


	for (int index = optind; index < argc; index++){
		printf ("Non-option argument %s\n", argv[index]);
	}

	return 0;
}

void mac_print(u_char mac[6]){
	printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void ipv4_print(u_char ip[4]){
	printf("%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
}

void hosts_print(host_t* hosts, int host_cnt){
	printf("<devices>\n");
	for(int i=0;i<host_cnt;i++){
		host_t tmp = hosts[i];
		printf("\t<host mac=\"");mac_print(tmp.mac);printf("\">\n");
		printf("\t\t<ipv4>");ipv4_print(tmp.ipv4);printf("</ipv4>\n");
		printf("\t</host>\n");
	}
	printf("</devices>\n");
}

host_t* host_lookup(host_t* hosts, int host_cnt, u_char mac[6]){
	host_t* h = NULL;

	for(int i=0;i<host_cnt;i++){
		host_t tmp = hosts[i];

		if(memcmp(tmp.mac, mac, 6)==0){
			h=&tmp;
			break;
		}
	}

	return h;
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

uint8_t* arp_pkt_build(ipv4_t src_ip, ipv4_t dst_ip, mac_t src_mac){
	struct ether_header ethhdr;
	uint8_t* ether_frame= (uint8_t*) malloc(ARPPKT_LEN);
	
	memset(ethhdr.ether_dhost, 0xff, MAC_LEN);
	memcpy(ethhdr.ether_shost, src_mac, MAC_LEN);
	ethhdr.ether_type = htons(0x0806);
	// memcpy(ether_frame, bcast_mac,MAC_LEN); //ether dst mac broadcast
	// memcpy(ether_frame+MAC_LEN, src_mac,MAC_LEN); //ether src mac
	// ether_frame[12] = htons(ETH_P_ARP);
	arphdr_t arphdr;
	arphdr.htype = htons(1);
	arphdr.ptype = htons(0x0800);
	arphdr.hlen = 6;
	arphdr.plen = 4;
	arphdr.oper = htons(ARP_OP_REQUEST);
	memcpy(&arphdr.src_mac, src_mac, MAC_LEN);
	memcpy(&arphdr.src_ip, src_ip, IP4_LEN);
	memset(&arphdr.dst_mac, 0x00, MAC_LEN);
	memcpy(&arphdr.dst_ip, dst_ip, IP4_LEN);

	memcpy(ether_frame,&ethhdr,sizeof(struct ether_header));
	memcpy(ether_frame+ETHHDR_LEN,&arphdr,ARPHDR_LEN*sizeof(uint8_t));

	return ether_frame;
}

void my_callback(u_char *params,const struct pcap_pkthdr* pkthdr,const u_char* pkt){
	UNUSED(params);UNUSED(pkthdr);

	arphdr_t* arphdr = (struct arphdr *)(pkt+14);

	if (ntohs(arphdr->htype) == 1 && ntohs(arphdr->ptype) == 0x0800){ 
		printf("------------------------------------\n");
		bool is_hosts_modified = false;

		host_t *h_src = host_lookup(hosts,host_cnt,arphdr->src_mac);
		if(h_src==NULL){ //process new host
			memcpy(hosts[host_cnt].mac,arphdr->src_mac,sizeof(arphdr->src_mac));
			memcpy(hosts[host_cnt].ipv4,arphdr->src_ip,sizeof(arphdr->src_ip));
			host_cnt++;
			is_hosts_modified = true;
		}
		else{ //process known host

		}

		if(is_hosts_modified){
			hosts_print(hosts,host_cnt);
		}
	}
}

void ipv4_scan(in_addr netw, in_addr mask, mac_t src_mac, ipv4_t src_ip, pcap_t* ifHandle){

	char netw_str[13];
	char mask_str[13];

	strcpy(netw_str, inet_ntoa(netw));
	if (netw_str == NULL){ perror("inet_ntoa"); return; }
	strcpy(mask_str, inet_ntoa(mask));
	if (mask_str == NULL){ perror("inet_ntoa"); return; }

	printf("netw: %s\n", netw_str);
	printf("mask: %s\n", mask_str);

	in_addr mask_full;
	inet_aton("255.255.255.255",&(mask_full));
	int devcnt = ntohl(mask_full.s_addr-mask.s_addr);

	for (int i=0;i<(devcnt-1);i++){
		in_addr tmp;
		tmp.s_addr = htonl(ntohl(netw.s_addr) + (i+1));
		uint8_t* pkt = arp_pkt_build(src_ip, *((ipv4_t*)&tmp.s_addr), src_mac);
		//arp_print((struct arphdr *)(pkt+ETHHDR_LEN)); /* Point to the ARP header */ 
		int bytes_written = pcap_inject(ifHandle, pkt, ARPPKT_LEN);	
		//printf("%d< ",bytes_written );
		pcap_dispatch(ifHandle,0,my_callback,NULL);
		//usleep(50000);
	}
	printf("\n");
	

	return;
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

void getifip4(char* ifName, ipv4_t ifip4) {
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

int main(int argc, char* argv[]){

	clargs_t clargs;
	if(parseArgs(argc,argv,&clargs)!=0){
		return 0;
	}

	// if((clargs.filePtr = fopen(clargs.fileName,"w"))==NULL){
	// 	fprintf(stderr,"fopen() failed\n");
	// 	return 0;
	// }
	
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((clargs.ifPtr=pcap_lookupdev(errbuf))==NULL) {
		fprintf(stderr,"Couldn't find default device: %s\n", errbuf);
		return(0);
	}
	printf("Device: %s\n", clargs.ifPtr);

	if ((clargs.ifHandle=pcap_create(clargs.ifPtr,errbuf))==NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", clargs.ifPtr, errbuf);
		return(0);
	}

	struct in_addr netw;
	struct in_addr mask;
	int lookup_return_code = pcap_lookupnet(
		clargs.ifPtr,
		&netw.s_addr,
		&mask.s_addr,
		errbuf
	);
	if(lookup_return_code!=0){ printf("lookup err\n"); return 0;}

	getifmac(clargs.ifPtr,clargs.ifmac);
	getifip4(clargs.ifPtr,clargs.ifip4);



	if ((pcap_set_snaplen(clargs.ifHandle, 2000)) < 0)
		printf("pcap_set_snaplen: %s", pcap_geterr(clargs.ifHandle));
	if ((pcap_set_promisc(clargs.ifHandle, 1)) < 0)
		printf("pcap_set_promisc: %s", pcap_geterr(clargs.ifHandle));
	if ((pcap_set_timeout(clargs.ifHandle, 0)) < 0)
		printf("pcap_set_timeout: %s", pcap_geterr(clargs.ifHandle));

	pcap_activate(clargs.ifHandle);

	ipv4_scan(netw,mask,clargs.ifmac,clargs.ifip4,clargs.ifHandle);
	sleep(5);
	pcap_dispatch(clargs.ifHandle,0,my_callback,NULL);
	
	pcap_close(clargs.ifHandle);
	return 0;
}