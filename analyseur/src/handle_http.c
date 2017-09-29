#include "handle_http.h"
#include "handle_tcp.h"
#include "handle_ip.h"
#include "handle_ether.h"
#include "appli.h"

/* Function handling http packets */
char* handle_HTTP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite){

	const u_char* http;
    u_int length = pkthdr->len;

    /* jump past the ethernet, ip and tcp headers */
    http = (const u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    length = length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr);

    const char get[] = GET;
    const char put[] = PUT;
    const char head[] = HEAD;
    const char post[] = POST;

    int i = 0;
    int j,compget,compput,comphead,comppost;
    /* Depending on the verbosity we print the packet differently */

    switch(verbosite)
    {
        case 3:
            printf("\t\t\t----\n");
            printf("\t\t\tHTTP\n");
            while (i < length-4)
            {
                comppost=0;
                compget=0;
                compput=0;
                comphead=0;
                for (j=0;j<3;j++){
                    if(get[j] == http[i+j])
                        compget++;
                    if(put[j] == http[i+j])
                        compput++;
                    if(head[j] == http[i+j])
                        comphead++;
                    if(post[j] == http[i+j])
                        comppost++;
                }
                if(compget==3) printf("\t\t\tGET");
                if(compput==3) printf("\t\t\tPUT");
                if(comphead==3 && head[j]==http[i+j]) printf("\t\t\tHEAD");
                if(comppost==3 && post[j]==http[i+j]) printf("\t\t\tPOST");
                i++;
            }
            print_ascii(http,length);
            break;
        case 2:
            printf("\t\t\t(HTTP)");
            while (i < length-4)
            {
                comppost=0;
                compget=0;
                compput=0;
                comphead=0;
                for (j=0;j<3;j++){
                    if(get[j] == http[i+j])
                        compget++;
                    if(put[j] == http[i+j])
                        compput++;
                    if(head[j] == http[i+j])
                        comphead++;
                    if(post[j] == http[i+j])
                        comppost++;
                }
                if(compget==3) printf(" GET");
                if(compput==3) printf(" PUT");
                if(comphead==3 && head[j]==http[i+j]) printf(" HEAD");
                if(comppost==3 && post[j]==http[i+j]) printf(" POST");
                i++;
            }
            printf("\n");
            break;
        case 1:
            printf(" | (HTTP) \n");
            break;
    }
    return NULL;
}