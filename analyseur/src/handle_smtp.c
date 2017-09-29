#include "handle_smtp.h"
#include "handle_tcp.h"
#include "handle_ip.h"
#include "handle_ether.h"
#include "appli.h"

/* Function handling packets used with the smtp protocol */
char* handle_SMTP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite){

	const u_char* smtp;
    u_int length = pkthdr->len;

    /* jump past the ethernet, ip and tcp headers */
    smtp = (const u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    length = length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr);

    const char mail[] = MAIL;
    const char rcpt[] = RCPT;
    const char data[] = DATA;
    const char ehlo[] = EHLO;
    const char auth[] = AUTH;
    const char quit[] = QUIT;
    const char start[] = STARTTLS;

    int i=0;
    int j,compm,compr,compd,compe,compa,compq,comps;

    /* Depending on the verbosity we print the packet differently */
    switch(verbosite)
    {
        case 3:
            printf("\t\t\t----\n");
            printf("\t\t\tSMTP\n");

            while (i < length-4)
            {
                compm=0;
                compr=0;
                compd=0;
                compe=0;
                compa=0;
                compq=0;
                comps=0;
                for (j=0;j<4;j++){
                    if(mail[j] == smtp[i+j])
                        compm++;
                    if(rcpt[j] == smtp[i+j])
                        compr++;
                    if(data[j] == smtp[i+j])
                        compd++;
                    if(ehlo[j] == smtp[i+j])
                        compe++;
                    if(auth[j] == smtp[i+j])
                        compa++;
                    if(quit[j] == smtp[i+j])
                        compq++;
                    if(start[j] == smtp[i+j])
                        comps++;
                }
                if(compm==4) printf("\t\t\tEmitted by ");
                if(compr==4) printf("\t\t\tReceived by ");
                if(compd==4) printf("\t\t\tContent ");
                if(compe==4) printf("\t\t\tEHLO Request");
                if(compa==4) printf("\t\t\tAuthentication ");
                if(compq==4) printf("\t\t\tEnd ");
                
                if((comps==4) && (i<length-8)){
                	for(j=4;j<8;j++){
                		if(start[j] == smtp[i+j])
                        comps++;
                	}
                	if(comps==8) printf("\t\t\tTLS Exchange ");
                }

                i++;
            }
            print_ascii(smtp,length);
            break;
        case 2:
            printf("\t\t\t(SMTP)");
            while (i < length-4)
            {
                compm=0;
                compr=0;
                compd=0;
                compe=0;
                compa=0;
                compq=0;
                comps=0;
                for (j=0;j<4;j++){
                    if(mail[j] == smtp[i+j])
                        compm++;
                    if(rcpt[j] == smtp[i+j])
                        compr++;
                    if(data[j] == smtp[i+j])
                        compd++;
                    if(ehlo[j] == smtp[i+j])
                        compe++;
                    if(auth[j] == smtp[i+j])
                        compa++;
                    if(quit[j] == smtp[i+j])
                        compq++;
                    if(start[j] == smtp[i+j])
                        comps++;
                }
                if(compm==4) printf(" Emission ");
                if(compr==4) printf(" Reception ");
                if(compd==4) printf(" Content ");
                if(compe==4) printf(" EHLO Request");
                if(compa==4) printf(" Authentication ");
                if(compq==4) printf(" End ");
                
                if((comps==4) && (i<length-8)){
                	for(j=4;j<8;j++){
                		if(start[j] == smtp[i+j])
                        comps++;
                	}
                	if(comps==8) printf(" TLS Exchange ");
                }

                i++;
            }
            printf("\n");
            break;
        case 1:
            printf(" | (SMTP) \n");
            break;
    }

	return NULL;
}