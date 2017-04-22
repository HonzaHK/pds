//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#include "pds_addr.h"

void mac_print(mac_t mac){
	char str[MAC_ADDRSTRLEN];
	macttop(mac,str);
	printf("%s",str);
}

void ipv4_print(ipv4_t ip){
	char str[INET_ADDRSTRLEN];
	ipv4ttop(ip,str);
	printf("%s",str);
}

void ipv6_print(ipv6_t ip){
	char str[INET6_ADDRSTRLEN];
	ipv6ttop(ip,str);
	printf("%s",str);
}
// ADDR CONVERSION -------------------------------------
void ptomact(char* str, mac_t mac){
	sscanf(str, "%02hhx%02hhx.%02hhx%02hhx.%02hhx%02hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
}

void ptoipv4t(char* str, ipv4_t ip){
	struct sockaddr_in sa;
	inet_pton(AF_INET,str,&(sa.sin_addr));
	memcpy(ip,&(sa.sin_addr),sizeof(sa.sin_addr));
}

void ptoipv6t(char* str, ipv6_t ip){
	struct sockaddr_in6 sa;
	inet_pton(AF_INET6,str,&(sa.sin6_addr));
	memcpy(ip,&(sa.sin6_addr),sizeof(sa.sin6_addr));
}

void macttop(mac_t mac, char str[MAC_ADDRSTRLEN]){
	sprintf(str,"%02hhx%02hhx.%02hhx%02hhx.%02hhx%02hhx", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void ipv4ttop(ipv4_t ip, char str[INET_ADDRSTRLEN]){
	struct sockaddr_in sa;
	memcpy(&(sa.sin_addr),ip,sizeof(sa.sin_addr));
	inet_ntop(AF_INET,&(sa.sin_addr),str,INET_ADDRSTRLEN);
}

void ipv6ttop(ipv6_t ip, char str[INET6_ADDRSTRLEN]){
	struct sockaddr_in6 sa;
	memcpy(&(sa.sin6_addr),ip,sizeof(sa.sin6_addr));
	inet_ntop(AF_INET6,&(sa.sin6_addr),str,INET6_ADDRSTRLEN);
}
//------------------------------------------------------

//gets iface mac && ipv4 && ipv6
void get_if_addrs(char *ifName, iface_t* iface){
	struct ifaddrs *ifa, *ifa_tmp;

	if (getifaddrs(&ifa) == -1) {
		perror("getifaddrs failed");
		exit(1);
	}

	for(ifa_tmp = ifa; ifa_tmp!=NULL; ifa_tmp = ifa_tmp->ifa_next){

		if(strcmp(ifa_tmp->ifa_name,ifName)!=0){continue;} //another interface
		if (ifa_tmp->ifa_addr){
			if (ifa_tmp->ifa_addr->sa_family == AF_PACKET){ // MAC
				struct sockaddr_ll *ll = (struct sockaddr_ll*) ifa_tmp->ifa_addr;
				memcpy(iface->mac, &ll->sll_addr, MAC_LEN);
			}
			else if (ifa_tmp->ifa_addr->sa_family == AF_INET){ // IPv4
				struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
				memcpy(iface->ipv4, &in->sin_addr, IP4_LEN);
			}
			else if(ifa_tmp->ifa_addr->sa_family == AF_INET6){ // IPv6
				struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
				memcpy(iface->ipv6, &in6->sin6_addr, IP6_LEN);
			}
		}
	}

	freeifaddrs(ifa);
}