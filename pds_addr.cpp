//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include "pds_addr.h"

void mac_print(mac_t mac){
	printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void ipv4_print(ipv4_t ip){
	printf("%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
}

void ipv6_print(ipv6_t ip){
	printf("%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X"
			,ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7],ip[8],ip[9],ip[10],ip[11],ip[12],ip[13],ip[14],ip[15]);
}


void getifmac(char* ifName, mac_t ifmac) {
	struct ifreq ifr;
	int sock=0;

	sock=socket(AF_INET,SOCK_DGRAM,0);
	strncpy( ifr.ifr_name, ifName, strlen(ifName) );
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) {
		return;
	}
	close(sock);

	memcpy(ifmac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
	return ;
}

void getifipv4(char* ifName, ipv4_t ifip4) {
	struct ifreq ifr;
	int sock = 0;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, ifName, strlen(ifName));
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		return;
	}
	close(sock);

	memcpy(ifip4, &(((struct sockaddr_in *) &(ifr.ifr_addr))->sin_addr), IP4_LEN);
	return ;
}

void getifipv6(char *ifName, ipv6_t ifip6){
	struct ifaddrs *ifa, *ifa_tmp;
	char addr[50];

	if (getifaddrs(&ifa) == -1) {
		perror("getifaddrs failed");
		exit(1);
	}

	ifa_tmp = ifa;
	while (ifa_tmp) {
		if (ifa_tmp->ifa_addr){
			if ( (ifa_tmp->ifa_addr->sa_family == AF_INET) || (ifa_tmp->ifa_addr->sa_family == AF_INET6) ) {
				if (ifa_tmp->ifa_addr->sa_family == AF_INET) { // IPv4
					struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
				}
				else { // IPv6
					struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
					memcpy(ifip6, &in6->sin6_addr, IP6_LEN);
				}
				// printf("name = %s\n", ifa_tmp->ifa_name);
				// printf("addr = %s\n", addr);
			}
		}
		ifa_tmp = ifa_tmp->ifa_next;
	}
}