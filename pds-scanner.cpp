#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
	char* ifName;
	char* fileName;
	FILE* filePtr;
} clargs_t;

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

int main(int argc, char* argv[]){

	clargs_t clargs;
	if(parseArgs(argc,argv,&clargs)!=0){
		return 0;
	}

	if((clargs.filePtr = fopen(clargs.fileName,"w"))==NULL){
		printf("fopen() failed\n");
		return 0;
	} 
	

	return 0;
}