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



// void ptoipv4t(char* str, ipv4_t ip){
// 	struct sockaddr_in sa;
// 	inet_pton(AF_INET,str,&(sa.sin_addr));
// 	memcpy(ip,&(sa.sin_addr),sizeof(sa.sin_addr));
// }

// void ptoipv6t(char* str, ipv6_t ip){
// 	struct sockaddr_in6 sa;
// 	inet_pton(AF_INET6,str,&(sa.sin6_addr));
// 	memcpy(ip,&(sa.sin6_addr),sizeof(sa.sin6_addr));
// }


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