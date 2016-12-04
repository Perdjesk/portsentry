/************************************************************************/
/*                                                                      */
/* Psionic PortSentry							*/
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 02-18-2002                                                 */
/*                                                                      */
/* Send all changes/modifications/bugfixes to sentrysupport@psionic.com */
/*                                                                      */
/*                                                                      */
/* This software is Copyright(c) 1997-2002 Psionic Technologies, Inc.   */
/*                                                                      */
/* Disclaimer:                                                          */
/*                                                                      */
/* All software distributed by Psionic Technologies is distributed 	*/
/* AS IS and carries NO WARRANTY or GUARANTEE OF ANY KIND. End users of */
/* the software acknowledge that they will not hold Psionic Technologies*/
/* liable for failure or non-function of the software product. YOU ARE 	*/
/* USING THIS PRODUCT AT YOUR OWN RISK.					*/
/*                                                                      */
/* Licensing restrictions apply. Commercial re-sell is prohibited under */
/* certain conditions. See the license that came with this package or 	*/
/* visit http://www.psionic.com for more information. 			*/
/*                                                                      */
/* $Id: portsentry.h,v 1.34 2002/04/08 16:48:27 crowland Exp crowland $ */
/************************************************************************/

#define VERSION "2.0b1"

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#ifdef BSD
	#include <netinet/in_systm.h>
	#include <netinet/ip_ether.h>
#endif

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include "portsentry_config.h"

#define MAXBUF	1024
#define MAXPORTS 64

#define ERROR -1
#define TRUE 1
#define FALSE 0

/* TCP Bits for unused */
#define TCP_UNUSED1 0x40
#define TCP_UNUSED2 0x80

/* max size of an IP address plus NULL */
#define IPMAXBUF 16

/* Really is about 1025, but we don't need the length for our purposes */
#define DNSMAXBUF 255

/* Size of link encapsulation */
#define LINK_ETHERSIZE 14

/* prototypes */
void PktEngine(u_char *, const struct pcap_pkthdr *, const u_char *);
int CheckIP(const struct ip *);
int CheckTCP(const struct ip *, const struct tcphdr *);
int CheckUDP(const struct ip *, const struct udphdr *);
int CheckICMP(const struct ip *, const struct icmp *);
int InitInterface(char * interface);
int InitStats(void);
int InitFilter(void);
int InitConfig (void);
int Dispose (char *, int, char *);
int CheckStateEngine (char *);
int InitConfig(void);
void Usage (void);
int SmartVerify(int, char *);


/* Status Variables */
/* XXX Make these less global */
struct stats{
	int gblFrameCount;
	int gblIPPackCount;
	int gblIcmpPackCount;
	int gblTcpPackCount;
	int gblUdpPackCount;
} gblStats;

