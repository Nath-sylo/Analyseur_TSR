#include "handle_imap.h"
#include "handle_tcp.h"
#include "handle_ip.h"
#include "handle_ether.h"
#include "appli.h"

u_char* handle_IMAP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite){

	const u_char* imap;
    u_int length = pkthdr->len;

    /* jump past the ethernet, ip and tcp headers */
    imap = (const u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    length = length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr);

    /* Depending on the verbosity we print the packet differently */
    switch(verbosite)
    {
    	case 3:
    		printf("\t\t\t----\n");
    		printf("\t\t\tIMAP\n");
            print_ascii(imap,length);
    		break;
    	case 2:
    		printf("\t\t\t(IMAP)\n");
    		break;
    	case 1:
    		printf(" | (IMAP)\n");
    		break;
    	default:
    		break;
    }
	return NULL;
}