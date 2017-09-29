#include "handle_igmp.h"
#include "handle_ether.h"
#include "handle_ip.h"
#include "appli.h"

/* Function that handles a packet used by the IGMP protocol */
u_char* handle_IGMP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite) {
    const struct igmp *igmp;
    /* We jump past the ethernet and ip headers */
    igmp = (struct igmp*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
	u_int length = pkthdr->len;
    length = length - sizeof(struct ether_header) - sizeof(struct ip);
	
	/* Depending on the verbosity we print the packet differently */
	switch (verbosite)
	{
		case 3:
			printf("\t\t----\n");    
			printf("\t\tIGMP\n");
			printf("\t\t| Type : %hu |",igmp->igmp_type);
			printf(" Code : %hu |",igmp->igmp_code);
			printf(" Checksum : %hu |\n",igmp->igmp_cksum);
			printf("\t\t| Group Address : %s |\n",inet_ntoa(igmp->igmp_group));
			break;
		case 2:
			printf("\t\t(IGMP) Type : %hu  Code : %hu  Group : %s\n",igmp->igmp_type,igmp->igmp_code,inet_ntoa(igmp->igmp_group));
			break;
		case 1:
			printf(" | (IGMP) Group : %s\n",inet_ntoa(igmp->igmp_group));
			break;
		default:
			break;
	}
    return NULL;
}
