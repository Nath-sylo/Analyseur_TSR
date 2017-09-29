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

#define START (u_char)250
#define STOP (u_char)240
#define	WILL (u_char)251
#define WONT (u_char)252
#define DO (u_char)253
#define DONT (u_char)254

#define BT (u_char)0
#define ECHO (u_char)1
#define SUPPGO (u_char)3
#define TTYPE (u_char)24
#define TLMODE (u_char)31
#define WS (u_char)32
#define TSPEED (u_char)34
#define ENVVAR (u_char)36
#define NEWEV (u_char)39


u_char* handle_TELNET(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite);