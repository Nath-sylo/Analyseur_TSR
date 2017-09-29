#include "handle_pop.h"
#include "handle_tcp.h"
#include "handle_ip.h"
#include "handle_ether.h"
#include "appli.h"


/* Function handling packets using the POP protocol */
u_char* handle_POP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite){

	const u_char* pop;
    u_int length = pkthdr->len;

    /* jump past the ethernet, ip and tcp headers */
    pop = (const u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    length = length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr);

    const char user[] = USER;
    const char pass[] = PASS;
    const char quit[] = QUIT;
    const char retr[] = RETR;
    const char rset[] = RSET;
    const char dele[] = DELE;
    const char list[] = LIST;
    const char stat[] = STAT;
    const char noop[] = NOOP;
    const char uidl[] = UIDL;
    const char top[] = TOP;
    const char last[] = LAST;

    int i=0,j;
    int cuser,cpass,cquit,cretr,crset,cdele,clist;
    int cstat,cnoop,cuidl,ctop,clast;

    /* Depending on the verbosity we print the packet differently */
    switch(verbosite)
    {
    	case 3:
    		printf("\t\t\t----\n");
    		printf("\t\t\tPOP\n");

            while(i < length-4){
                cuser = 0;
                cpass = 0;
                cquit = 0;
                cretr = 0;
                crset = 0;
                cdele = 0;
                clist = 0;
                cstat = 0;
                cnoop = 0;
                cuidl = 0;
                ctop = 0;
                clast = 0;
                for (j=0;j<4;j++){
                    if((top[j] == pop[i+j]) && (j<3))
                        ctop++;
                    if(user[j] == pop[i+j])
                        cuser++;
                    if(pass[j] == pop[i+j])
                        cpass++;
                    if(quit[j] == pop[i+j])
                        cquit++;
                    if(retr[j] == pop[i+j])
                        cretr++;
                    if(rset[j] == pop[i+j])
                        crset++;
                    if(dele[j] == pop[i+j])
                        cdele++;
                    if(list[j] == pop[i+j])
                        clist++;
                    if(stat[j] == pop[i+j])
                        cstat++;
                    if(noop[j] == pop[i+j])
                        cnoop++;
                    if(uidl[j] == pop[i+j])
                        cuidl++;
                    if(last[j] == pop[i+j])
                        clast++;
                }
                if(ctop==3) printf("\t\t\tTOP\n");
                if(cuser==4) printf("\t\t\tUSER\n");
                if(cpass==4) printf("\t\t\tPASS\n");
                if(cquit==4) printf("\t\t\tQUIT\n");
                if(cretr==4) printf("\t\t\tRETR\n");
                if(crset==4) printf("\t\t\tRSET\n");
                if(cdele==4) printf("\t\t\tDELE\n");
                if(clist==4) printf("\t\t\tLIST\n");
                if(cstat==4) printf("\t\t\tSTAT\n");
                if(cnoop==4) printf("\t\t\tNOOP\n");
                if(cuidl==4) printf("\t\t\tUIDL\n");
                if(clast==4) printf("\t\t\tLAST\n");

                i++;
            }
            print_ascii(pop,length);
    		break;
    	case 2:
    		printf("\t\t\t(POP)");
            while(i < length-4){
                cuser = 0;
                cpass = 0;
                cquit = 0;
                cretr = 0;
                crset = 0;
                cdele = 0;
                clist = 0;
                cstat = 0;
                cnoop = 0;
                cuidl = 0;
                ctop = 0;
                clast = 0;
                for (j=0;j<4;j++){
                    if((top[j] == pop[i+j]) && (j<3))
                        ctop++;
                    if(user[j] == pop[i+j])
                        cuser++;
                    if(pass[j] == pop[i+j])
                        cpass++;
                    if(quit[j] == pop[i+j])
                        cquit++;
                    if(retr[j] == pop[i+j])
                        cretr++;
                    if(rset[j] == pop[i+j])
                        crset++;
                    if(dele[j] == pop[i+j])
                        cdele++;
                    if(list[j] == pop[i+j])
                        clist++;
                    if(stat[j] == pop[i+j])
                        cstat++;
                    if(noop[j] == pop[i+j])
                        cnoop++;
                    if(uidl[j] == pop[i+j])
                        cuidl++;
                    if(last[j] == pop[i+j])
                        clast++;
                }
                if(ctop==3) printf(" TOP");
                if(cuser==4) printf(" USER");
                if(cpass==4) printf(" PASS");
                if(cquit==4) printf(" QUIT");
                if(cretr==4) printf(" RETR");
                if(crset==4) printf(" RSET");
                if(cdele==4) printf(" DELE");
                if(clist==4) printf(" LIST");
                if(cstat==4) printf(" STAT");
                if(cnoop==4) printf(" NOOP");
                if(cuidl==4) printf(" UIDL");
                if(clast==4) printf(" LAST");

                i++;
            }
            printf("\n");
    		break;
    	case 1:
    		printf(" | (POP)\n");
    		break;
    	default:
    		break;
    }
	return NULL;
}