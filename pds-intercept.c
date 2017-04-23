//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include "pdslib/pds_addr.h"
#include "pdslib/pds_host.h"
#include "pdslib/pds_pkt.h"

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

void intercept(iface_t iface, host_t hosts[HOST_MAX_CNT]){
	struct pcap_pkthdr *pkthdr;
	const unsigned char *pkt=NULL;

	int res;
	while ( (res = pcap_next_ex(iface.handle,&pkthdr,&pkt)) >= 0){  /* Get one packet */ 
		if(res==0){continue;}
		ethhdr_t* ethhdr = (ethhdr_t*) pkt;
		host_t* h_src=host_lookup(hosts,host_cnt,ethhdr->src_mac);
		if(h_src==NULL){ continue;} //not one of our hosts
		host_t* h_dst=host_paired_lookup(h_src,hosts,host_cnt);
		if(h_dst==NULL){ continue;} //noone other in the same group
		memcpy(&ethhdr->dst_mac,h_dst->mac,MAC_LEN);
		memcpy(&ethhdr->src_mac,iface.mac,MAC_LEN);
		pcap_inject(iface.handle,pkt,pkthdr->len);
	}
}


int main(int argc, char* argv[]){

	clargs_t clargs;
	iface_t iface;

	if(parseArgs(argc,argv,&clargs)!=0){
		return 0;
	}

	xmlToHosts(clargs.fileName,hosts,&host_cnt);

	char errbuf[PCAP_ERRBUF_SIZE];
	if ((iface.handle=pcap_open_live(clargs.ifName, BUFSIZ, 1, 1000, errbuf))==NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", clargs.ifName, errbuf);
		return 0;
	}
	iface.name=clargs.ifName;
	get_if_addrs(iface.name,&iface);


	pcap_activate(iface.handle);
	
	intercept(iface,hosts);
	
	pcap_close(iface.handle);


	return 0;
}