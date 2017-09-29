#include "handle_ether.h"
#include "handle_ip.h"
#include "handle_udp.h"
#include "handle_tcp.h"
#include "handle_dns.h"
#include "appli.h"

/* Function handling the dns packets */
u_char* handle_DNS(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite,int tcp){

	const struct dns *dnshdr;
	const u_char *data;
    u_int length = pkthdr->len;

    /* jump past the headers */
    if(tcp){
    	dnshdr = (struct dns*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    	length = length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr) - sizeof(struct dns);
    	data =  (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct dns));
    }
    else{
    	dnshdr = (struct dns*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        length = length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct udphdr) - sizeof(struct dns);
        data =  (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dns));
    }
    /* Depending on the verbosity we print the packet differently */
    switch(verbosite)
    {
    	case 3:
    		printf("\t\t\t----\n");
            printf("\t\t\tDNS\n");
            printf("\t\t\tIdentifier : %d\n",dnshdr->id);
            if(dnshdr->qr & (1 << 0)){
            	printf("\t\t\tResponse\n");
            }else{printf("\t\t\tRequest\n");}
            
            if(!dnshdr->op){
            	printf("\t\t\tQuery\n");
            }else if(dnshdr->op & (1 << 0)){
            	printf("\t\t\tInverse Query\n");
            }else if(dnshdr->op & (1 << 1)){
            	printf("\t\t\tStatus\n");
            }else{printf("\t\t\tFutur Use\n");}
            
            if(dnshdr->Aa & (1 << 0)){
            	printf("\t\t\tAuthoritative Answer\n");
            }else{printf("\t\t\tNon Authoritative Answer\n");}
            
            if(dnshdr->Tc & (1 << 0)){
            	printf("\t\t\tTruncated\n");
            }else{printf("\t\t\tNon Truncated\n");}
            
            if(dnshdr->Rd & (1 << 0)){
            	printf("\t\t\tRecursivity Asked\n");
            }else{printf("\t\t\tRecursivity Not Asked\n");}

            if(dnshdr->Ra & (1 << 0)){
            	printf("\t\t\tRecursivity Authorized\n");
            }else{printf("\t\t\tRecursivity Unauthorized\n");}
            
            printf("\t\t\t");
            if(!dnshdr->Rcode){
            	printf("No Error ");
            }else if(dnshdr->Rcode & (1 << 0)){
            	printf("Request Format Error ");
            }else if(dnshdr->Rcode & (1 << 1)){
            	printf("Server Problem ");
            }else if((dnshdr->Rcode & (1 << 0)) && (dnshdr->Rcode & (1 << 1))){
            	printf("Name Inexistant ");
            }else if(dnshdr->Rcode & (1 << 2)){
            	printf("Not Implemented ");
            }else if((dnshdr->Rcode & (1 << 0)) && (dnshdr->Rcode & (1 << 2))){
            	printf("Refused ");
            }else{
            	printf("Reserved ");
            }
            printf("\n");

            print_ascii(data,length);
    		break;

    	case 2:
    		printf("\t\t\t(DNS)");
    		printf(" Identifier : %d",dnshdr->id);
            if(dnshdr->qr & (1 << 0)){
            	printf(" Response");
            }else{printf(" Request");}
            
            if(!dnshdr->op){
            	printf(" Query\n");
            }else if(dnshdr->op & (1 << 0)){
            	printf(" Inverse Query\n");
            }else if(dnshdr->op & (1 << 1)){
            	printf(" Status\n");
            }else{printf(" Futur Use\n");}
    		break;

    	case 1:
    		printf(" | (DNS) \n");
    		break;

    	default:
    		break;
    }
    return NULL;
}
