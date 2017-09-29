#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <ctype.h>
#include <unistd.h>

struct dns{
	u_int16_t id;
	unsigned int qr:1;
	unsigned int op:4;
	unsigned int Aa:1;
	unsigned int Tc:1;
	unsigned int Rd:1;
	unsigned int Ra:1;
	unsigned int Z:3;
	unsigned int Rcode:4;
};

u_char* handle_DNS(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite,int tcp);
