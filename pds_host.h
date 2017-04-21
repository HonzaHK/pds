//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/tree.h>

#include "pds_addr.h"

#define HOST_MAX_CNT 64
#define HOST_MAX_IPV4_CNT 10 //maximum addresses assigned to one MAC
#define HOST_MAX_IPV6_CNT 10 //maximum addresses assigned to one MAC

typedef struct host {
	mac_t mac;
	ipv4_t ipv4[HOST_MAX_IPV4_CNT];
	int cnt_ipv4;
	ipv6_t ipv6[HOST_MAX_IPV6_CNT];
	int cnt_ipv6;

	bool is_paired;
	int pair_id;
} host_t;

void hosts_print(host_t* hosts, int host_cnt);
host_t* host_lookup(host_t* hosts, int host_cnt, mac_t mac);
void xmlToHosts(const char* filename, host_t hosts[HOST_MAX_CNT],int* host_cnt);