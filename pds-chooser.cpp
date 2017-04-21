//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include <stdio.h>
#include <stdlib.h>

#include "pds_addr.h"
#include "pds_host.h"

#define PAIR_MAX_CNT HOST_MAX_CNT / 2

typedef struct {
	char *infile;
	char *outfile;
} clargs_t;

host_t hosts[HOST_MAX_CNT];
int host_cnt=0;

typedef int pair_t[2];
pair_t pairs[PAIR_MAX_CNT];
int pair_cnt=0;

void printHelp(){
	printf("Usage: ./pds-chooser -f IN_FILE -o OUT_FILE");
}

int parseArgs(int argc, char* argv[], clargs_t *clargs){

	if(argc!=5){return 1;}

	for(int i=1;i<argc;i++){
		if(strcmp(argv[i],"-f")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			clargs->infile=argv[i];
		}
		else if(strcmp(argv[i],"-o")==0){
			if(argv[i++]==NULL){return 1;} //move to arg value && check value missing
			clargs->outfile=argv[i];
		}
		else{
			return 1;
		}
	}

	return 0;
}

int main(int argc, char* argv[]){
	clargs_t clargs;
	if(parseArgs(argc,argv,&clargs)!=0){
		printHelp();
		return 1;
	};

	char input[512];
	xmlToHosts(clargs.infile,hosts,&host_cnt);
	char mac_str[MAC_ADDRSTRLEN];
	for(int i=0;i<host_cnt;i++){
		macttop(hosts[i].mac,mac_str);
		printf("%d: [%s]\n", i, mac_str);
	}
	printf("Sample usage: \"(0,2)(1,3)(4,5)\"\n");
	read(fileno(stdin),input,sizeof(input));
	input[strlen(input)-1]='\0'; //remove newline	
	char* curr_pos = input;
	while(true){
		int bytes_read = 0;
		int r = sscanf(curr_pos,"(%d,%d)%n",&pairs[pair_cnt][0],&pairs[pair_cnt][1],&bytes_read);
		if(r!=2 || (pair_cnt+1)*2 > host_cnt){ //no more input OR count of pairs would exceed host count
			break;
		}
		pair_cnt++;
		curr_pos+=bytes_read; //move pointer by chars read out
	}
	//todo: check pairs here (out of index, reflexive relation etc)
	for(int i=0;i<pair_cnt;i++){
		int a = pairs[i][0];
		int b = pairs[i][1];
		hosts[a].is_paired = true;
		hosts[a].pair_id = i;
		hosts[b].is_paired = true;
		hosts[b].pair_id = i;
	}

	hosts_print(hosts,host_cnt);

	return 0;
}