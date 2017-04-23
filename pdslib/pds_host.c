//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include "pds_host.h"

void hosts_print(host_t* hosts, int host_cnt){
	printf("<devices>\n");
	for(int i=0;i<host_cnt;i++){
		host_t h_tmp = hosts[i];
		printf("\t<host mac=\"");mac_print(h_tmp.mac);if(h_tmp.is_paired){printf(" group=\"victim-pair-%d\"", h_tmp.pair_id);}printf("\">\n");
		for(int j=0;j<h_tmp.cnt_ipv4;j++){
			printf("\t\t<ipv4>");ipv4_print(h_tmp.ipv4[j]);printf("</ipv4>\n");
		}
		for(int j=0;j<h_tmp.cnt_ipv6;j++){
			printf("\t\t<ipv6>");ipv6_print(h_tmp.ipv6[j]);printf("</ipv6>\n");
		}
		printf("\t</host>\n");
	}
	printf("</devices>\n");
}

//returns ptr to host struct with corresponding mac, NULL when not found
host_t* host_lookup(host_t* hosts, int host_cnt, mac_t mac){
	host_t* h = NULL;

	for(int i=0;i<host_cnt;i++){
		host_t* tmp = &hosts[i];

		if(memcmp(tmp->mac, mac, 6)==0){
			h=tmp;
			break;
		}
	}

	return h;
}

//returns ptr to host which is in the same group as h, NULL when not found
host_t* host_paired_lookup(host_t* h, host_t* hosts, int host_cnt){
	host_t* h_paired = NULL;

	for(int i=0;i<host_cnt;i++){
		host_t* tmp = &hosts[i];

		if(tmp->pair_id==h->pair_id && (memcmp(tmp->mac, h->mac, 6)!=0)){ //if same group && different mac
			h_paired=tmp;
			break;
		}
	}

	return h_paired;
}

host_t* host_add(host_t hosts[HOST_MAX_CNT], int index, mac_t mac){
	host_t* h = &hosts[index];
	memcpy(h->mac,mac,MAC_LEN);
	
	return h;
}

void host_add_ipv4(host_t* h, ipv4_t ip){
	for(int i=0;i<h->cnt_ipv4;i++){
		if(memcmp(h->ipv4[i],ip,IP4_LEN)==0){return;} //ip already stored
	}
	memcpy(h->ipv4[h->cnt_ipv4],ip,IP4_LEN);
	h->cnt_ipv4++;
}

void host_add_ipv6(host_t* h, ipv6_t ip){
	for(int i=0;i<h->cnt_ipv6;i++){
		if(memcmp(h->ipv6[i],ip,IP6_LEN)==0){return;} //ip already stored
	}
	memcpy(h->ipv6[h->cnt_ipv6],ip,IP6_LEN);
	h->cnt_ipv6++;
}

void hostsToXml(host_t hosts[HOST_MAX_CNT], int host_cnt, char* filename){
	
	FILE* fd;
	if((fd = fopen(filename,"w"))==NULL){
		return;
	}

	char str_mac[MAC_ADDRSTRLEN];
	char str_ip4[INET_ADDRSTRLEN];
	char str_ip6[INET6_ADDRSTRLEN];

	fprintf(fd,"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fprintf(fd,"<devices>\n");
	for(int i=0;i<host_cnt;i++){
		host_t h_tmp = hosts[i];
		macttop(h_tmp.mac,str_mac);
		fprintf(fd,"\t<host mac=");fprintf(fd, "\"%s\"",str_mac);if(h_tmp.is_paired){fprintf(fd," group=\"victim-pair-%d\"", h_tmp.pair_id);}fprintf(fd,">\n");
		for(int j=0;j<h_tmp.cnt_ipv4;j++){
			ipv4ttop(h_tmp.ipv4[j],str_ip4);
			fprintf(fd,"\t\t<ipv4>");fprintf(fd, "%s",str_ip4);fprintf(fd,"</ipv4>\n");
		}
		for(int j=0;j<h_tmp.cnt_ipv6;j++){
			ipv6ttop(h_tmp.ipv6[j],str_ip6);
			fprintf(fd,"\t\t<ipv6>");fprintf(fd, "%s",str_ip6);fprintf(fd,"</ipv6>\n");
		}
		fprintf(fd,"\t</host>\n");
	}
	fprintf(fd,"</devices>\n");

	fclose(fd);
}

void xmlToHosts(const char* filename, host_t hosts[HOST_MAX_CNT],int* host_cnt){
	LIBXML_TEST_VERSION
	xmlDoc* doc = xmlReadFile(filename,NULL,0);
	if (doc == NULL) {
		fprintf(stderr, "Failed to parse document\n");
		return;
	}

	xmlNode* devices_node = xmlDocGetRootElement(doc);
	xmlNode* host_node = NULL;
	xmlAttr* attr = NULL;
	xmlNode* addr_node = NULL;

	for(host_node = devices_node->children; host_node; host_node = host_node->next) {
		if (host_node->type != XML_ELEMENT_NODE) { continue;}
		host_t* h = &hosts[*host_cnt];
		attr = host_node->properties; //mac attribute
		char* mac_str = (char*)xmlNodeGetContent(attr->children);
		ptomact(mac_str,h->mac);
		free(mac_str);
		if((attr = host_node->properties->next)!=NULL){ //group attribute
			char* gr_id_str = (char *)xmlNodeGetContent(attr->children);
			h->is_paired=true;
			sscanf(gr_id_str,"victim-pair-%d",&h->pair_id);
			free(gr_id_str);
		}
		for(addr_node=host_node->children;addr_node;addr_node=addr_node->next){
			if (addr_node->type != XML_ELEMENT_NODE) { continue;}
			if(strcmp((char*)addr_node->name,"ipv4")==0){ //ipv4 field
				char* ipv4_str = (char*)xmlNodeGetContent(addr_node);
				ptoipv4t(ipv4_str,h->ipv4[h->cnt_ipv4]);
				free(ipv4_str);
				h->cnt_ipv4++;
			}
			else{ //ipv6 field
				char* ipv6_str = (char*)xmlNodeGetContent(addr_node);
				ptoipv6t(ipv6_str,h->ipv6[h->cnt_ipv6]);
				free(ipv6_str);
				h->cnt_ipv6++;
			}
		}
		(*host_cnt)++;
	}

	xmlFreeDoc(doc);

	xmlCleanupParser();
	xmlMemoryDump();
}