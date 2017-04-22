//VUTBR - FIT - PDS project MitM
//Author: Jan Kubis / xkubis13
#ifndef PDS_ADDR_H
#define PDS_ADDR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <unistd.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>

#define UNUSED(x) (void)(x) //suppress w-unused-parameter warnings

#define MAC_ADDRSTRLEN 15//mac string length

#define MAC_LEN 6
#define IP4_LEN 4
#define IP6_LEN 16

typedef uint8_t mac_t[MAC_LEN];
typedef uint8_t ipv4_t[IP4_LEN];
typedef uint8_t ipv6_t[IP6_LEN];

typedef struct {
	char* name;
	pcap_t* handle;

	mac_t mac;
	ipv4_t ipv4;
	ipv6_t ipv6;
} iface_t;

void mac_print(mac_t mac);
void ipv4_print(ipv4_t ip);
void ipv6_print(ipv6_t ip);

void ptomact(char* str, mac_t mac);
void ptoipv4t(char* str, ipv4_t ip);
void ptoipv6t(char* str, ipv6_t ip);
void macttop(mac_t mac, char str[MAC_ADDRSTRLEN]);
void ipv4ttop(ipv4_t ip, char str[INET_ADDRSTRLEN]);
void ipv6ttop(ipv6_t ip, char str[INET6_ADDRSTRLEN]);

void get_if_addrs(char *ifName, iface_t* iface);


#endif