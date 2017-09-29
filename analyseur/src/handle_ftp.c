#include "handle_ftp.h"
#include "handle_tcp.h"
#include "handle_ip.h"
#include "handle_ether.h"
#include "appli.h"

/* Function handling the packets using the ftp protocol */
u_char* handle_FTP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite){

	const u_char* ftp;
    u_int length = pkthdr->len;

    /* jump past the ethernet, ip and tcp headers */
    ftp = (const u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    length = length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct tcphdr);

    const char user[] = USER;
    const char pass[] = PASS;
    const char acct[] = ACCT;
    const char cwd[] = CWD;
    const char cdup[] = CDUP;
    const char quit[] = QUIT;
    const char port[] = PORT;
    const char pasv[] = PASV;
    const char type[] = TYPE;
    const char retr[] = RETR;
    const char stor[] = STOR;
    const char appe[] = APPE;
    const char rest[] = REST;
    const char rnfr[] = RNFR;
    const char rnto[] = RNTO;
    const char abor[] = ABOR;
    const char dele[] = DELE;
    const char rmd[] = RMD;
    const char mkd[] = MKD;
    const char pwd[] = PWD;
    const char list[] = LIST;
    const char site[] = SITE;
    const char syst[] = SYST;
    const char stat[] = STAT;
    const char help[] = HELP;
    const char noop[] = NOOP;

    int i=0,j;
    int cuser,cpass,cacct,ccwd,ccdup,cquit,cport,cpasv,ctype,cretr,cstor,cappe,crest;
    int crnfr,crnto,cabor,cdele,crmd,cmkd,cpwd,clist,csite,csyst,cstat,chelp,cnoop;
    
    /* Depending on the verbosity we print the packet differently */
    switch(verbosite)
    {
        case 3:
            printf("\t\t\t----\n");
            printf("\t\t\tFTP\n");

            while (i < length-4)
            {
                cuser=0;
                cpass=0;
                cacct=0;
                ccwd=0;
                ccdup=0;
                cquit=0;
                cport=0;
                cpasv=0;
                ctype=0;
                cretr=0;
                cstor=0;
                cappe=0;
                crest=0;
                crnfr=0;
                crnto=0;
                cabor=0;
                cdele=0;
                crmd=0;
                cmkd=0;
                cpwd=0;
                clist=0;
                csite=0;
                csyst=0;
                cstat=0;
                chelp=0;
                cnoop=0;
                for (j=0;j<4;j++){
                    if((cwd[j] == ftp[i+j]) && (j<3))
                        ccwd++;
                    if((rmd[j] == ftp[i+j]) && (j<3))
                        crmd++;
                    if((mkd[j] == ftp[i+j]) && (j<3))
                        cmkd++;
                    if((pwd[j] == ftp[i+j]) && (j<3))
                        cpwd++;
                    if(user[j] == ftp[i+j])
                        cuser++;
                    if(quit[j] == ftp[i+j])
                        cquit++;
                    if(pass[j] == ftp[i+j])
                        cpass++;
                    if(acct[j] == ftp[i+j])
                        cacct++;
                    if(cdup[j] == ftp[i+j])
                        ccdup++;
                    if(port[j] == ftp[i+j])
                        cport++;
                    if(pasv[j] == ftp[i+j])
                        cpasv++;
                    if(type[j] == ftp[i+j])
                        ctype++;
                    if(retr[j] == ftp[i+j])
                        cretr++;
                    if(stor[j] == ftp[i+j])
                        cstor++;
                    if(appe[j] == ftp[i+j])
                        cappe++;
                    if(rest[j] == ftp[i+j])
                        crest++;
                    if(rnfr[j] == ftp[i+j])
                        crnfr++;
                    if(rnto[j] == ftp[i+j])
                        crnto++;
                    if(abor[j] == ftp[i+j])
                        cabor++;
                    if(dele[j] == ftp[i+j])
                        cdele++;
                    if(list[j] == ftp[i+j])
                        clist++;
                    if(site[j] == ftp[i+j])
                        csite++;
                    if(syst[j] == ftp[i+j])
                        csyst++;
                    if(stat[j] == ftp[i+j])
                        cstat++;
                    if(help[j] == ftp[i+j])
                        chelp++;
                    if(noop[j] == ftp[i+j])
                        cnoop++;
                }
                if(ccwd==3) printf("\t\t\tCWD\n");
                if(crmd==3) printf("\t\t\tRMD\n");
                if(cpwd==3) printf("\t\t\tCPWD\n");
                if(cmkd==3) printf("\t\t\tMKD\n");
                if(cuser==4) printf("\t\t\tUSER\n");
                if(cpass==4) printf("\t\t\tPASS\n");
                if(cacct==4) printf("\t\t\tACCT\n");
                if(ccdup==4) printf("\t\t\tCDUP\n");
                if(cport==4) printf("\t\t\tPORT\n");
                if(cpasv==4) printf("\t\t\tPASV\n");
                if(ctype==4) printf("\t\t\tTYPE\n");
                if(cretr==4) printf("\t\t\tRETR\n");
                if(cstor==4) printf("\t\t\tSTOR\n");
                if(cappe==4) printf("\t\t\tAPPE\n");
                if(crest==4) printf("\t\t\tREST\n");
                if(crnfr==4) printf("\t\t\tRNFR\n");
                if(crnto==4) printf("\t\t\tRNTO\n");
                if(cabor==4) printf("\t\t\tABOR\n");
                if(cdele==4) printf("\t\t\tDELE\n");
                if(clist==4) printf("\t\t\tLIST\n");
                if(csite==4) printf("\t\t\tSITE\n");
                if(csyst==4) printf("\t\t\tSYST\n");
                if(cstat==4) printf("\t\t\tSTAT\n");
                if(chelp==4) printf("\t\t\tHELP\n");
                if(cnoop==4) printf("\t\t\tNOOP\n");
                if(cquit==4) printf("\t\t\tQUIT\n");

                i++;
            }
            print_ascii(ftp,length);
            break;
        case 2:
            printf("\t\t\t(FTP)");
            while (i < length-4)
            {
                cuser=0;
                cpass=0;
                cacct=0;
                ccwd=0;
                ccdup=0;
                cquit=0;
                cport=0;
                cpasv=0;
                ctype=0;
                cretr=0;
                cstor=0;
                cappe=0;
                crest=0;
                crnfr=0;
                crnto=0;
                cabor=0;
                cdele=0;
                crmd=0;
                cmkd=0;
                cpwd=0;
                clist=0;
                csite=0;
                csyst=0;
                cstat=0;
                chelp=0;
                cnoop=0;
                for (j=0;j<4;j++){
                    if((cwd[j] == ftp[i+j]) && (j<3))
                        ccwd++;
                    if((rmd[j] == ftp[i+j]) && (j<3))
                        crmd++;
                    if((mkd[j] == ftp[i+j]) && (j<3))
                        cmkd++;
                    if((pwd[j] == ftp[i+j]) && (j<3))
                        cpwd++;
                    if(user[j] == ftp[i+j])
                        cuser++;
                    if(quit[j] == ftp[i+j])
                        cquit++;
                    if(pass[j] == ftp[i+j])
                        cpass++;
                    if(acct[j] == ftp[i+j])
                        cacct++;
                    if(cdup[j] == ftp[i+j])
                        ccdup++;
                    if(port[j] == ftp[i+j])
                        cport++;
                    if(pasv[j] == ftp[i+j])
                        cpasv++;
                    if(type[j] == ftp[i+j])
                        ctype++;
                    if(retr[j] == ftp[i+j])
                        cretr++;
                    if(stor[j] == ftp[i+j])
                        cstor++;
                    if(appe[j] == ftp[i+j])
                        cappe++;
                    if(rest[j] == ftp[i+j])
                        crest++;
                    if(rnfr[j] == ftp[i+j])
                        crnfr++;
                    if(rnto[j] == ftp[i+j])
                        crnto++;
                    if(abor[j] == ftp[i+j])
                        cabor++;
                    if(dele[j] == ftp[i+j])
                        cdele++;
                    if(list[j] == ftp[i+j])
                        clist++;
                    if(site[j] == ftp[i+j])
                        csite++;
                    if(syst[j] == ftp[i+j])
                        csyst++;
                    if(stat[j] == ftp[i+j])
                        cstat++;
                    if(help[j] == ftp[i+j])
                        chelp++;
                    if(noop[j] == ftp[i+j])
                        cnoop++;
                }
                if(ccwd==3) printf(" CWD");
                if(crmd==3) printf(" RMD");
                if(cpwd==3) printf(" CPWD");
                if(cmkd==3) printf(" MKD");
                if(cuser==4) printf(" USER");
                if(cpass==4) printf(" PASS");
                if(cacct==4) printf(" ACCT");
                if(ccdup==4) printf(" CDUP");
                if(cport==4) printf(" PORT");
                if(cpasv==4) printf(" PASV");
                if(ctype==4) printf(" TYPE");
                if(cretr==4) printf(" RETR");
                if(cstor==4) printf(" STOR");
                if(cappe==4) printf(" APPE");
                if(crest==4) printf(" REST");
                if(crnfr==4) printf(" RNFR");
                if(crnto==4) printf(" RNTO");
                if(cabor==4) printf(" ABOR");
                if(cdele==4) printf(" DELE");
                if(clist==4) printf(" LIST");
                if(csite==4) printf(" SITE");
                if(csyst==4) printf(" SYST");
                if(cstat==4) printf(" STAT");
                if(chelp==4) printf(" HELP");
                if(cnoop==4) printf(" NOOP");
                if(cquit==4) printf(" QUIT");

                i++;
            }
            printf("\n");
            break;
        case 1:
            printf(" | (FTP) \n");
            break;
        default:
            break;
    }

	return NULL;
}