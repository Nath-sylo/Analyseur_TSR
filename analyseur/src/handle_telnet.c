#include "handle_tcp.h"
#include "handle_ip.h"
#include "handle_ether.h"
#include "handle_telnet.h"

/* Function handling telnet packets */
u_char* handle_TELNET(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite) {

	const u_char* telnet;
    u_int length = pkthdr->len;

    /* jump past the ethernet, ip and tcp headers */
    telnet = (const u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    length = length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr);

	int i = 0;

	/* Depending on the verbosity we print the packet differently */
	switch(verbosite)
	{
		case 3:
			printf("\t\t\t----\n");
			printf("\t\t\tTELNET\n");
			while (i<length)
			{

				switch(telnet[i])
				{
					case  START:
						printf("\t\t\tSTART Negociations\n");
						break;

					case  STOP:
						printf("\t\t\tEND Negociations\n");
						break;

					case  WILL:
						printf("\t\t\tWILL ");
						i++;
						switch(telnet[i])
						{
							case BT:
								printf("\t\t\tBinary Transmission\n");
								break;
							case ECHO:
								printf("\t\t\tEcho\n");
								break;
							case SUPPGO:
								printf("\t\t\tSuppress Go Ahead\n");
								break;
							case TTYPE:
								printf("\t\t\tTerminal Type\n");
								break;
							case TLMODE:
								printf("\t\t\tTerminal Line Mode\n");
								break;
							case WS:
								printf("\t\t\tWindow Size\n");
								break;
							case TSPEED:
								printf("\t\t\tTerminal Speed\n");
								break;
							case ENVVAR:
								printf("\t\t\tEnvironment Variables\n");
								break;
							case NEWEV:
								printf("\t\t\tNew Environment Variables\n");
								break;
							default:
								printf("\t\t\tOption non supportée\n");
								break;
						}
						break;

					case  WONT:
						printf("\t\t\tWON'T ");
						i++;
						break;

					case  DO:
						printf("\t\t\tDO ");
						i++;
						break;

					case  DONT:
						printf("\t\t\tDON'T ");
						i++;
						break;

					default :
						break;
				}
				i++;
			}
			break;
		case 2:
			printf("(TELNET)\n");
			break;
		case 1:
			printf(" | (TELNET)\n");
			break;
	}
	return NULL;
}