#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <unistd.h>

#include <pcap.h>
#include <arpa/inet.h>

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
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
} arphdr_t;
#define MAXBYTES2CAPTURE 2048

typedef struct host {
	u_char mac[6];
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

void printAllDevs(){
	
	pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(d= alldevs; d != NULL; d= d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
}

bool isSaved(host_t **hostlist, int dev_cnt, u_char mac[6]){
	bool found = false;
	int a[6] = {1,2,3,4,5,6};
	int b[6] = {1,2,3,4,5,6};
	for(int i=0;i<dev_cnt;i++){
		host_t *host = hostlist[i];

		if(memcmp(host->mac, mac, 6)==0){
			found=true;
			break;
		}
	}

	return found;
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

	//printAllDevs();
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

	struct pcap_pkthdr *pkthdr;
	const unsigned char *packet=NULL;
	arphdr_t *arpheader = NULL;

	host_t **devlist;

	int i=0;
	int res=0;
	int dev_cnt=0;
	while ( (res = pcap_next_ex(clargs.ifHandle,&pkthdr,&packet)) >= 0){  /* Get one packet */ 
		i++;
		// printf("attempt %d: ", i);
		//if(res==0){printf("timeout\n");}
		if(res==0){continue;}
		// printf("%d\n", res);

		arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */ 

		// printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len); 
		// printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
		// printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"); 
		// printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 

		/* If is Ethernet and IPv4, print packet contents */ 
		if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 

			printf("Sender MAC: "); 
			for(i=0; i<6;i++)
			printf("%02X:", arpheader->sha[i]); 

			printf("\nSender IP: "); 
			for(i=0; i<4;i++)
			printf("%d.", arpheader->spa[i]); 

			printf("\nTarget MAC: "); 
			for(i=0; i<6;i++)
			printf("%02X:", arpheader->tha[i]); 

			printf("\nTarget IP: "); 
			for(i=0; i<4; i++)
			printf("%d.", arpheader->tpa[i]);
			printf("\n");
			printf("\n");

			bool iss = isSaved(devlist,dev_cnt,arpheader->sha);
			printf("iss: %s\n", iss?"true":"false" );
			devlist[dev_cnt] = (host_t *)malloc(sizeof(host_t));
			memcpy(devlist[dev_cnt]->mac,arpheader->sha,sizeof(arpheader->sha));
			dev_cnt++;
			// printf("devlist: ----------------\n");
			// for(int j=0;j<=cnt;j++){
			// 	for(int x=0;x<6;x++){
			// 		printf("%02X:", devlist[j]->mac[x]); 
			// 	}
			// 	printf("\n");
			// }
			printf("\n");
			printf("\n");
		}
	}
	
	return 0;
}