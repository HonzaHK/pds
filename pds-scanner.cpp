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

using namespace std;

typedef struct {
	char* ifName;
	char *ifPtr;
	pcap_t *ifHandle;

	char* fileName;
	FILE* filePtr;
} clargs_t;

#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char src_mac[6];      /* Sender hardware address */ 
    u_char src_ip[4];      /* Sender IP address       */ 
    u_char dst_mac[6];      /* Target hardware address */ 
    u_char dst_ip[4];      /* Target IP address       */ 
} arphdr_t;
#define MAXBYTES2CAPTURE 2048

typedef struct host {
	u_char mac[6];
	u_char ip[4];
} host_t;

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
		printf("\t\t<ipv4>");ipv4_print(tmp.ip);printf("</ipv4>\n");
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
	printf("\n");

	return;
}

void ipv4_scan(in_addr netw, in_addr mask, host_t* hosts, int* host_cnt, pcap_t* ifHandle){

	char netw_str[13];
	char mask_str[13];

	strcpy(netw_str, inet_ntoa(netw));
	if (netw_str == NULL){ perror("inet_ntoa"); return; }
	strcpy(mask_str, inet_ntoa(mask));
	if (mask_str == NULL){ perror("inet_ntoa"); return; }

	printf("netw: %s\n", netw_str);
	printf("mask: %s\n", mask_str);

	// for (int i=0;i<255;i++){
	// 	in_addr tmp;
	// 	tmp.s_addr = htonl(ntohl(netw.s_addr) + (i+1));
	// 	cout << inet_ntoa(tmp) << endl;
	// }


	struct pcap_pkthdr *pkthdr = NULL;
	const unsigned char *packet=NULL;
	arphdr_t *arpheader = NULL;

	int res=0,i=0;
	while ( (res = pcap_next_ex(ifHandle,&pkthdr,&packet)) >= 0){  /* Get one packet */ 
		i++;
		if(res==0){continue;}
		arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */ 

		// printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len); 
		// printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
		// printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"); 
		// printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 

		/* If is Ethernet and IPv4, print packet contents */ 
		if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 
			printf("------------------------------------\n");
			//arp_print(arpheader);
			bool is_hosts_modified = false;

			host_t *h_src = host_lookup(hosts,*host_cnt,arpheader->src_mac);
			if(h_src==NULL){ //process new host
				memcpy(hosts[*host_cnt].mac,arpheader->src_mac,sizeof(arpheader->src_mac));
				memcpy(hosts[*host_cnt].ip,arpheader->src_ip,sizeof(arpheader->src_ip));
				(*host_cnt)++;
				is_hosts_modified = true;
			}
			else{ //process known host

			}

			if(is_hosts_modified){
				hosts_print(hosts,*host_cnt);
			}

		}
	}

	return;
}

int main(int argc, char* argv[]){

	clargs_t clargs;
	if(parseArgs(argc,argv,&clargs)!=0){
		return 0;
	}

	if((clargs.filePtr = fopen(clargs.fileName,"w"))==NULL){
		fprintf(stderr,"fopen() failed\n");
		return 0;
	}
	
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((clargs.ifPtr=pcap_lookupdev(errbuf))==NULL) {
		fprintf(stderr,"Couldn't find default device: %s\n", errbuf);
		return(0);
	}
	printf("Device: %s\n", clargs.ifPtr);

	if ((clargs.ifHandle=pcap_open_live(clargs.ifPtr, BUFSIZ, 1, 1000, errbuf))==NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", clargs.ifPtr, errbuf);
		return(0);
	}

	host_t hosts[64];
	int host_cnt=0;

	struct in_addr netw;
	struct in_addr mask;
	int lookup_return_code = pcap_lookupnet(
		clargs.ifPtr,
		&netw.s_addr,
		&mask.s_addr,
		errbuf
	);
	if(lookup_return_code!=0){ printf("lookup err\n"); return 0;}

	ipv4_scan(netw,mask,hosts,&host_cnt,clargs.ifHandle);
	
	return 0;
}