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
		host_t tmp = hosts[i];

		if(memcmp(tmp.mac, mac, 6)==0){
			h=&tmp;
			break;
		}
	}

	return h;
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
		attr = host_node->properties;
		ptomact((char*)xmlNodeGetContent(attr->children),h->mac);
		//attr->name [mac]
		//printf("%s / %s\n",attr->name,xmlNodeGetContent(attr->children));
		for(addr_node=host_node->children;addr_node;addr_node=addr_node->next){
			if (addr_node->type != XML_ELEMENT_NODE) { continue;}
			if(strcmp((char*)addr_node->name,"ipv4")==0){ //ipv4 field
				memcpy(h->ipv4[h->cnt_ipv4],xmlNodeGetContent(addr_node),IP4_LEN);
				ptoipv4t((char*)xmlNodeGetContent(addr_node),h->ipv4[h->cnt_ipv4]);

				h->cnt_ipv4++;
			}
			else{ //ipv6 field
				ptoipv6t((char*)xmlNodeGetContent(addr_node),h->ipv6[h->cnt_ipv6]);
				h->cnt_ipv6++;
			}
		}
		(*host_cnt)++;
	}

	xmlFreeDoc(doc);

	xmlCleanupParser();
	xmlMemoryDump();
}