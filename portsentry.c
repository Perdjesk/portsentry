/************************************************************************/
/*                                                                      */
/* Psionic PortSentry																										*/
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 03-27-2002                                                 */
/*                                                                      */
/* Send all changes/modifications/bugfixes to sentrysupport@psionic.com */
/*                                                                      */
/*                                                                      */
/* This software is Copyright(c) 1997-2002 Psionic Technologies, Inc.   */
/*                                                                      */
/* Disclaimer:                                                          */
/*                                                                      */
/* All software distributed by Psionic Technologies is distributed 			*/
/* AS IS and carries NO WARRANTY or GUARANTEE OF ANY KIND. End users of */
/* the software acknowledge that they will not hold Psionic Technologies*/
/* liable for failure or non-function of the software product. YOU ARE 	*/
/* USING THIS PRODUCT AT YOUR OWN RISK.																	*/
/*                                                                      */
/* Licensing restrictions apply. Commercial re-sell is prohibited under */
/* certain conditions. See the license that came with this package or 	*/
/* visit http://www.psionic.com for more information. 									*/
/*                                                                      */
/* $Id: portsentry.c,v 1.53 2002/04/08 16:48:15 crowland Exp crowland $ */
/************************************************************************/

#include "portsentry.h"
#include "portsentry_io.h"
#include "portsentry_util.h"

/* Globals */
pcap_t *gblPcapSocketPtr;
pcap_t *gblHandlePtr;
bpf_u_int32 gblAddressPcapPtr;
bpf_u_int32 gblNetmaskPcapPtr;
int gblDataLink;
int gblLinkSize;
struct in_addr gblSrc, gblDst;
char gblAttackerIP[IPMAXBUF], gblTargetIP[IPMAXBUF];

struct {
	char gblScanDetectHost[MAXSTATE][IPMAXBUF];
	char gblKillRoute[MAXBUF];
	char gblKillHostsDeny[MAXBUF];
	char gblKillRunCmd[MAXBUF];
	char gblBlockedFile[MAXBUF];
	char gblHistoryFile[MAXBUF];
	char gblIgnoreFile[MAXBUF];
	char gblInterface[MAXBUF];
	char gblInterfaceAddr[MAXBUF];
	int gblScanDetectCount;
	int gblTriggerCount;
} gblConfig;


struct {
	int gblBlockTCP;
	int gblBlockUDP;
	int gblRunCmdFirst;
	int gblResolveHost;
	int gblIPChecks;
	int gblTCPChecks;
	int gblUDPChecks;
	int gblICMPChecks;
} gblFlags;


/* Here we go */
int main (int argc, char **argv)
{


if (argc != 1)
	{
		Usage ();
		ExitNow (ERROR);
	}
else if ((geteuid ()) && (getuid ()) != 0)
	{
		printf ("You need to be root to run this.\n");
		ExitNow (ERROR);
	}
else if (CheckConfig () != TRUE)
	{
	  Log ("adminalert: ERROR: Configuration files are missing/corrupted. Shutting down.\n");
	  printf ("ERROR: Configuration files are missing/corrupted.\n");
	  printf ("ERROR: Check your syslog for a more detailed error message.\n");
	  printf ("ERROR: PortSentry is shutting down!\n");
	  ExitNow (ERROR);
	}
else if (InitConfig () != TRUE)
	{
	  Log ("adminalert: ERROR: Your config file is corrupted/missing mandatory option! Shutting down.\n");
	  printf ("ERROR: Your config file is corrupted/missing mandatory option!\n");
	  printf ("ERROR: Check your syslog for a more detailed error message.\n");
	  printf ("ERROR: PortSentry is shutting down!\n");
	  ExitNow (ERROR);
	}
else if (InitStats () != TRUE)
	{
	  Log ("adminalert: ERROR: Couldn't initialize statistics. Shutting down.\n");
	  printf ("ERROR: Couldn't initialize statistics. Shutting down.\n");
	  ExitNow (ERROR);
	}
#ifndef NODAEMON
else if (DaemonSeed () == ERROR)
	{
	  Log ("adminalert: ERROR: could not go into daemon mode. Shutting down.\n");
	  printf ("ERROR: could not go into daemon mode. Shutting down.\n");
	  ExitNow (ERROR);
	}
#endif
else if (InitInterface (gblConfig.gblInterface) != TRUE)
	{
	  Log ("adminalert: ERROR: Couldn't initialize interface. Shutting down.\n");
	  printf ("ERROR: Couldn't initialize interface. Shutting down.\n");
	  ExitNow (ERROR);
	}
else if(InitFilter() != TRUE)
	{
	  Log ("adminalert: ERROR: Couldn't initialize BPF filter. Shutting down.\n");
	  printf ("ERROR: Couldn't initialize BPF filter. Shutting down.\n");
	  ExitNow (ERROR);
	}

Log("adminalert: PortSentry is initialized and monitoring.");


/* Grab multiple packets */
pcap_loop(gblHandlePtr, -1, PktEngine, NULL);

/* Close interface */
pcap_close(gblHandlePtr);

exit(0);
}


/****************************************************************/
/* Reads generic config options into global variables           */
/****************************************************************/
int
InitConfig (void)
{
  FILE *input;
  char configToken[MAXBUF];

  gblFlags.gblBlockTCP = CheckFlag ("BLOCK_TCP");
  gblFlags.gblBlockUDP = CheckFlag ("BLOCK_UDP");
  gblFlags.gblResolveHost = CheckFlag ("RESOLVE_HOST");
  gblFlags.gblIPChecks = CheckFlag("CHECK_IP");
  gblFlags.gblTCPChecks = CheckFlag("CHECK_TCP");
  gblFlags.gblUDPChecks = CheckFlag("CHECK_UDP");
  gblFlags.gblICMPChecks = CheckFlag("CHECK_ICMP");

  memset (gblConfig.gblKillRoute, '\0', MAXBUF);
  memset (gblConfig.gblKillHostsDeny, '\0', MAXBUF);
  memset (gblConfig.gblKillRunCmd, '\0', MAXBUF);

  if ((ConfigTokenRetrieve ("SCAN_TRIGGER", configToken)) == FALSE)
    {
      Log ("adminalert: ERROR: Could not read SCAN_TRIGGER option from config file. Disabling SCAN DETECTION TRIGGER");
      gblConfig.gblTriggerCount = 0;
    }
  else
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved SCAN_TRIGGER option: %s \n",
	   configToken);
#endif
      gblConfig.gblTriggerCount = atoi (configToken);
    }

  if ((ConfigTokenRetrieve ("KILL_ROUTE", gblConfig.gblKillRoute)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved KILL_ROUTE option: %s \n",
	   gblConfig.gblKillRoute);
#endif
    }
  else
    {
#ifdef DEBUG
      Log ("debug: InitConfig: KILL_ROUTE option NOT FOUND.\n");
#endif
    }

  if ((ConfigTokenRetrieve ("KILL_HOSTS_DENY", gblConfig.gblKillHostsDeny)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved KILL_HOSTS_DENY option: %s \n",
	   gblConfig.gblKillHostsDeny);
#endif
    }
  else
    {
#ifdef DEBUG
      Log ("debug: InitConfig: KILL_HOSTS_DENY option NOT FOUND.\n");
#endif
    }

  if ((ConfigTokenRetrieve ("KILL_RUN_CMD", gblConfig.gblKillRunCmd)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved KILL_RUN_CMD option: %s \n",
	   gblConfig.gblKillRunCmd);
#endif
	/* Check the order we should run the KILL_RUN_CMD */
	/* Default is to run the command after blocking */
	gblFlags.gblRunCmdFirst = CheckFlag ("KILL_RUN_CMD_FIRST");
    }
  else
    {
#ifdef DEBUG
      Log ("debug: InitConfig: KILL_RUN_CMD option NOT FOUND.\n");
#endif
    }

  if ((ConfigTokenRetrieve ("BLOCKED_FILE", gblConfig.gblBlockedFile)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved BLOCKED_FILE option: %s \n",
	   gblConfig.gblBlockedFile);
      Log ("debug: CheckConfig: Removing old block file: %s \n",
	   gblConfig.gblBlockedFile);
#endif

 		if ((input = fopen (gblConfig.gblBlockedFile, "w")) == NULL)
			{
	  	Log ("adminalert: ERROR: Cannot delete blocked file on startup: %s.\n",
	     gblConfig.gblBlockedFile);
	  	return (FALSE);
			}
		else
			fclose(input);
   }
  else
    {
      Log ("adminalert: ERROR: Cannot retrieve BLOCKED_FILE option! Aborting\n");
      return (FALSE);
    }


  if ((ConfigTokenRetrieve ("HISTORY_FILE", gblConfig.gblHistoryFile)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved HISTORY_FILE option: %s \n",
	   gblConfig.gblHistoryFile);
#endif
    }
  else
    {
      Log ("adminalert: ERROR: Cannot retrieve HISTORY_FILE option! Aborting\n");
      return (FALSE);
    }


  if ((ConfigTokenRetrieve ("IGNORE_FILE", gblConfig.gblIgnoreFile)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved IGNORE_FILE option: %s \n",
	   gblConfig.gblIgnoreFile);
#endif
    }
  else
    {
      Log ("adminalert: ERROR: Cannot retrieve IGNORE_FILE option! Aborting\n");
      return (FALSE);
    }

  if ((ConfigTokenRetrieve ("INTERFACE", gblConfig.gblInterface)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved INTERFACE option: %s \n",
	   gblConfig.gblInterface);
#endif
    }
  else
    {
      Log ("adminalert: ERROR: Cannot retrieve INTERFACE option! Aborting\n");
      return (FALSE);
    }

  if ((ConfigTokenRetrieve ("INTERFACE_ADDRESS", gblConfig.gblInterfaceAddr)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved INTERFACE_ADDRESS option: %s \n",
	   gblConfig.gblInterface);
#endif
    }
  else
    {
      Log ("adminalert: ERROR: Cannot retrieve INTERFACE_ADDRESS option! Aborting\n");
      return (FALSE);
    }

  return (TRUE);
}


/* Initialize statistic counters */
int InitStats(void)
{
	gblStats.gblFrameCount=0;
	gblStats.gblIPPackCount=0;
	gblStats.gblIcmpPackCount=0;
	gblStats.gblTcpPackCount=0;
	gblStats.gblUdpPackCount=0;

return(TRUE);
}


/* Initialize the interface */
int InitInterface(char *interface)
{

char *interfacePtr;
char pcapError[PCAP_ERRBUF_SIZE];
/* XXX lookupnet vars
struct in_addr addr;
char *addressPtr, *netmaskPtr;
*/

/* Initialize Interface */
if(strcmp(interface,"auto") == 0)
	interfacePtr = pcap_lookupdev(pcapError);
else
	interfacePtr = interface;

if(interfacePtr == NULL)
{
	Log("adminalert: ERROR: Error looking up interface: %s\n", pcapError);
	return(ERROR);
}

#ifdef DEBUG
      Log ("debug: InitInterface: Opening interface: %s \n",interfacePtr);
#endif

/* Initialize address/netmask */
if(pcap_lookupnet(interfacePtr, &gblAddressPcapPtr, &gblNetmaskPcapPtr, pcapError) == ERROR)
{
	Log("adminalert: ERROR: Error looking up network: %s\n", pcapError);
	return(ERROR);
}

/* XXX Broken. Can't determine Interface IP */
/*addr.s_addr = gblAddressPcapPtr;
addressPtr = (char *)inet_ntoa(addr);
addr.s_addr = gblNetmaskPcapPtr;
netmaskPtr = (char *)inet_ntoa(addr);

if(addressPtr == NULL)
{
	Log("adminalert: ERROR: Can't translate network address for parsing.\n");
	return(ERROR);
}
*/

Log("adminalert: Monitoring interface %s and address: %s\n", interfacePtr, gblConfig.gblInterfaceAddr);

/* Open device */
if((gblHandlePtr = pcap_open_live(interfacePtr, MAXBUF, 0, 0, pcapError)) == NULL)
{
	Log("adminalert: ERROR: Can't open device %s for monitoring: %s\n", interfacePtr, pcapError);
	return(ERROR);
}

#ifdef DEBUG
      Log ("debug: InitInterface: Interface %s is now live. \n",interfacePtr);
#endif


/* Check media type function here */
gblDataLink = pcap_datalink(gblHandlePtr);
switch(gblDataLink)
	{
	case DLT_EN10MB:
		gblLinkSize = LINK_ETHERSIZE;
		break;
	default:
		Log("adminalert: ERROR: Datalink type is not supported yet.");
		return(ERROR);
	}

return(TRUE);
}



/* Initialize BPF */
int InitFilter(void)
{
char tcpPorts[MAXBUF], udpPorts[MAXBUF], filterString[MAXBUF * 2], finalFilter[MAXBUF * 2];
struct bpf_program BPF;


Log ("adminalert: Initializing PortSentry BPF filters.\n");

/* XXX */
/* Need to do:
 Bypass ports in use already
 Add unused ports to list  with 'or' separator
 add ICMP
 put in the config retrieve in the main init function.
*/

 if ((ConfigTokenRetrieve ("TCP_PORTS", tcpPorts)) == FALSE)
      Log ("adminalert: No TCP_PORTS defined in config file. Continuing.");
 else
      Log ("adminalert: Monitoring TCP ports: %s\n", tcpPorts);

 if ((ConfigTokenRetrieve ("UDP_PORTS", udpPorts)) == FALSE)
      Log ("adminalert: No UDP_PORTS defined in config file. Continuing.");
 else
      Log ("adminalert: Monitoring UDP ports: %s\n", udpPorts);


 if ((strlen(tcpPorts) == 0) && (strlen(udpPorts) == 0))
    {
      Log("adminalert: No TCP or UDP ports defined in config file. Aborting.");
      return(ERROR);
    }
 else
    {
	SafeStrncpy(finalFilter, "not src host ", 14);
	strncat(finalFilter, gblConfig.gblInterfaceAddr, IPMAXBUF);
	if(strlen(tcpPorts) != 0)
	   {
		strncat(finalFilter, " and tcp dst port ", MAXBUF);
		SubstString(" or ", ",", tcpPorts, filterString);
		strncat(finalFilter, filterString, ((MAXBUF * 2)- strlen(finalFilter)));
	   }
	if(strlen(udpPorts) != 0)
	   {
		/* Straigtens out filter ordering here */
		if(strlen(tcpPorts) != 0)
			strncat(finalFilter, " or udp dst port ", ((MAXBUF * 2) - strlen(finalFilter)));
		else
			strncat(finalFilter, " and udp dst port ", ((MAXBUF * 2) - strlen(finalFilter)));

		SubstString(" or ", ",", udpPorts, filterString);
		strncat(finalFilter, filterString, ((MAXBUF * 2) - strlen(finalFilter)));
	   }
    }


#ifdef DEBUG
      Log ("debug: InitFilter: Applying filter: \"%s\" \n", finalFilter);
#endif

/* Set Filters function here */
if (pcap_compile(gblHandlePtr, &BPF, finalFilter, 0, gblNetmaskPcapPtr) == -1)
	{
      		Log ("adminalert: ERROR: Could not apply BPF filter: %s", pcap_geterr(gblHandlePtr));
   		return(ERROR);
	}
else if(pcap_setfilter(gblHandlePtr, &BPF) == -1)
	{
      Log ("adminalert: ERROR: Could not apply BPF filter: %s", pcap_geterr(gblHandlePtr));
   		return(ERROR);
	}


#ifdef DEBUG
      Log ("debug: InitFilter: Filter set.\n", finalFilter);
#endif

return(TRUE);
}


void PktEngine(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

const struct ether_header *ethernet;
const struct ip *ip;
const struct tcphdr *tcp;
const struct udphdr *udp;
const struct icmp *icmp;
int dataoffset = 0;
int result = FALSE;


gblStats.gblFrameCount++;

#ifdef DEBUG
      Log ("debug: PktEngine: Frame counter: %d\n",gblStats.gblFrameCount);
      Log ("debug: PktEngine: IP counter: %d\n",gblStats.gblIPPackCount);
      Log ("debug: PktEngine: TCP counter: %d\n",gblStats.gblTcpPackCount);
      Log ("debug: PktEngine: UDP counter: %d\n",gblStats.gblUdpPackCount);
      Log ("debug: PktEngine: ICMP counter: %d\n",gblStats.gblIcmpPackCount);
#endif

/* shuts up compiler about uninitialized ip struct warning in switch() */
ip = NULL;


/* XXX Re-evaluate this switch statement if you apply BPF first */
/* the ethertype check is probably not necessary with ip,tcp,udp,icmp options with BPF */
switch(gblDataLink)
	{
		case DLT_EN10MB:
			ethernet = (struct ether_header *) (packet);
			if (ntohs(ethernet -> ether_type) == ETHERTYPE_IP)
				{
#ifdef DEBUG
      Log ("debug: PktEngine: Found ETHERTYPE_IP\n");
#endif
					gblStats.gblIPPackCount++;
					ip = (struct ip *) (packet + gblLinkSize);
					gblSrc.s_addr = ip->ip_src.s_addr;
					gblDst.s_addr = ip->ip_dst.s_addr;
					if((dataoffset = CheckIP(ip)))
						{
							SafeStrncpy (gblAttackerIP, (char *) inet_ntoa (gblSrc), IPMAXBUF);
							SafeStrncpy (gblTargetIP, (char *) inet_ntoa (gblDst), IPMAXBUF);
							break;
						}
					else
						{
							Log("attackalert: An illegal IP packet type was detected and discarded.\n");
							break;
						}

				}
			/* Found other ETHERTYPE (probably an ARP) */
			else
			  	break;
	}

if(dataoffset)
	{
	  /* check if we should ignore this IP */
	/* XXX This should read in at Init and placed into a list */
	  result = NeverBlock (gblAttackerIP, gblConfig.gblIgnoreFile);
		if (result == ERROR)
		 		Log ("attackalert: ERROR: cannot open ignore file. Analyzing attack anyway.\n");
		else if(result == TRUE) /* Ignore this IP */
			return;

	/* check if this target is already blocked */
	if (IsBlocked (gblAttackerIP, gblConfig.gblBlockedFile) == TRUE)
		{
			Log ("attackalert: Host: %s is already blocked - Ignoring", gblAttackerIP);
			return;
		}

	/* check if they've visited before */
	if (!CheckStateEngine (gblAttackerIP))
		return;

	switch(ip->ip_p)
		{
			case IPPROTO_TCP:
				tcp = (struct tcphdr *) (packet + gblLinkSize + dataoffset);
				gblStats.gblTcpPackCount++;
				if (!CheckTCP(ip, tcp))
					Log("adminalert: ERROR: Error checking TCP packet.\n");
				break;
			case IPPROTO_UDP:
				gblStats.gblUdpPackCount++;
				udp = (struct udphdr *) (packet + gblLinkSize + dataoffset);
				if (!CheckUDP(ip, udp))
					Log("adminalert: ERROR: Error checking UDP packet.\n");
				break;
			case IPPROTO_ICMP:
				gblStats.gblIcmpPackCount++;
				icmp = (struct icmp *) (packet + gblLinkSize + dataoffset);
				if (!CheckICMP(ip, icmp))
					Log("adminalert: ERROR: Error checking ICMP packet.\n");
				break;
		}
	}

}

int CheckTCP(const struct ip *ip, const struct tcphdr *tcp)
{
char resolvedHost[DNSMAXBUF];
char *scanType;
int dstPort = 0, srcPort = 0;


/* Set destination/src port  */
dstPort = ntohs(tcp->th_dport);
srcPort = ntohs(tcp->th_sport);

if(SmartVerify(dstPort, "TCP") == TRUE)
	{
#ifdef DEBUG
		Log("debug: CheckTCP: SmartVerify indicates port is in use. Ignoring connection\n");
#endif DEBUG
		return(TRUE);
	}

	/* By-Bye */
if (Dispose(gblAttackerIP, dstPort, "TCP") != TRUE)
	Log ("attackalert: ERROR: Could not block host %s!", gblAttackerIP);

/* Ok we've already blocked this guy or ignored the actions */
/* Since those are the time critical areas we'll now do the optional */
/* resolution for logging */
if (gblFlags.gblResolveHost)
	{
		if(CleanAndResolve(resolvedHost, gblAttackerIP) != TRUE)
			{
				Log ("attackalert: ERROR: Error resolving host. \
			      	resolving disabled for this host.\n");
				snprintf (resolvedHost, DNSMAXBUF, "%s", gblAttackerIP);
			}
	}
else
	snprintf (resolvedHost, DNSMAXBUF, "%s", gblAttackerIP);

/* XXX Put in flags to null out for unused bit attack vulnerability or simply report?? */
/* Also this false alarms with Explicit Congestion Notification aware kernels */
/*
if (tcp->th_flags & (TCP_UNUSED1|TCP_UNUSED2))
	Log("attackalert: TCP Unused bits set. Detection evasion technique in use!\n");
*/

if(tcp->th_flags == 0)
	{
		Log("attackalert: TCP NULL scan from host %s/%s to TCP port: %d from TCP port: %d", resolvedHost, \
				gblAttackerIP, dstPort, srcPort);
		scanType="NULL";
	}
else if (tcp->th_flags == (TH_FIN|TH_URG|TH_PUSH|TH_ACK|TH_SYN|TH_RST))
	{
		Log("attackalert: TCP XMAS-FULL scan from host %s/%s to TCP port: %d from TCP port: %d", resolvedHost, \
				gblAttackerIP, dstPort, srcPort);
		scanType="XMAS-FULL";
	}
else if (tcp->th_flags == (TH_FIN|TH_URG|TH_PUSH))
	{
		Log("attackalert: TCP XMAS scan from host %s/%s to TCP port: %d from TCP port: %d", resolvedHost, \
				gblAttackerIP, dstPort, srcPort);
		scanType="XMAS";
	}
else if (tcp->th_flags == TH_SYN)
	{
		Log("attackalert: TCP SYN scan from host %s/%s to TCP port: %d from TCP port: %d", resolvedHost, \
				gblAttackerIP, dstPort, srcPort);
		scanType="SYN";
	}
else if (tcp->th_flags == TH_FIN)
	{
		Log("attackalert: TCP FIN scan from host %s/%s to TCP port: %d from TCP port: %d", resolvedHost, \
				gblAttackerIP, dstPort, srcPort);
		scanType="FIN";
	}
else
	{
	Log("attackalert: Unknown/Illegal scan type: TCP Packet Flags: FIN %d SYN: %d RST: %d PUSH: %d ACK: %d URG: %d \
UNUSED1: %d UNUSED2: %d scan from host %s/%s to TCP port: %d from TCP port: %d", \
  ((tcp->th_flags & TH_FIN) >> 0), \
	((tcp->th_flags & TH_SYN) >> 1), \
  ((tcp->th_flags & TH_RST) >> 2), \
  ((tcp->th_flags & TH_PUSH) >> 3), \
  ((tcp->th_flags & TH_ACK) >> 4), \
  ((tcp->th_flags & TH_URG) >> 5), \
  ((tcp->th_flags & TCP_UNUSED1) >> 6), \
  ((tcp->th_flags & TCP_UNUSED2) >> 7), \
	resolvedHost, gblAttackerIP, dstPort, srcPort);
	scanType="UNKNOWN";
	}

if (WriteBlocked (gblAttackerIP, resolvedHost, "TCP", scanType, dstPort, srcPort, \
		gblConfig.gblBlockedFile, gblConfig.gblHistoryFile) != TRUE)
			Log("attackalert: ERROR: Could not write out to history/blocked file.");


#ifdef DEBUG
	Log("debug: CheckTCP: src: %s\n", gblAttackerIP);
	Log("debug: CheckTCP: dst: %s\n", gblTargetIP);
	Log("debug: CheckTCP: src port: %d\n", ntohs(tcp->th_sport));
	Log("debug: CheckTCP: dst port: %d\n", ntohs(tcp->th_dport));
	Log("debug: CheckTCP: FIN: %d\n", (tcp->th_flags & TH_FIN) >> 0);
	Log("debug: CheckTCP: SYN: %d\n", (tcp->th_flags & TH_SYN) >> 1);
	Log("debug: CheckTCP: RST: %d\n", (tcp->th_flags & TH_RST) >> 2);
	Log("debug: CheckTCP: PSH: %d\n", (tcp->th_flags & TH_PUSH) >> 3);
	Log("debug: CheckTCP: ACK: %d\n", (tcp->th_flags & TH_ACK) >> 4);
	Log("debug: CheckTCP: URG: %d\n", (tcp->th_flags & TH_URG) >> 5);
	Log("debug: CheckTCP: UNUSED1: %d\n", (tcp->th_flags & TCP_UNUSED1) >> 6);
	Log("debug: CheckTCP: UNUSED2: %d\n", (tcp->th_flags & TCP_UNUSED2) >> 7);
	Log("debug: CheckTCP: total flags: %d\n", tcp->th_flags);
#endif

return(TRUE);
}


int CheckUDP(const struct ip *ip, const struct udphdr *udp)
{
char resolvedHost[DNSMAXBUF];
int dstPort = 0, srcPort = 0;


/* Set destination/src port  */
dstPort = ntohs(udp->uh_dport);
srcPort = ntohs(udp->uh_sport);

if((SmartVerify(dstPort, "UDP")) == TRUE)
	{
#ifdef DEBUG
		Log("debug: CheckUDP: SmartVerify indicates port is in use. Ignoring connection\n");
#endif DEBUG
		return(TRUE);
	}

	/* By-Bye */
if (Dispose(gblAttackerIP, dstPort, "UDP") != TRUE)
	Log ("attackalert: ERROR: Could not block host %s!", gblAttackerIP);

/* Ok we've already blocked this guy or ignored the actions */
/* Since those are the time critical areas we'll now do the optional */
/* resolution for logging */
if (gblFlags.gblResolveHost)
	{
		if(CleanAndResolve(resolvedHost, gblAttackerIP) != TRUE)
			{
				Log ("attackalert: ERROR: Error resolving host. \
			      	resolving disabled for this host.\n");
				snprintf (resolvedHost, DNSMAXBUF, "%s", gblAttackerIP);
			}
	}
else
	snprintf (resolvedHost, DNSMAXBUF, "%s", gblAttackerIP);

Log("attackalert: UDP scan from host %s/%s to UDP port: %d from UDP port: %d", resolvedHost, \
gblAttackerIP, dstPort, srcPort);
if (WriteBlocked (gblAttackerIP, resolvedHost, "UDP", "UDP", dstPort, srcPort, \
	gblConfig.gblBlockedFile, gblConfig.gblHistoryFile) != TRUE)
	Log("attackalert: ERROR: Could not write out to history/blocked file.");

#ifdef DEBUG
	Log("debug: CheckUDP: src: %s\n", gblAttackerIP);
	Log("debug: CheckUDP: dst: %s\n", gblTargetIP);
	Log("debug: CheckUDP: src port: %d\n", ntohs(udp->uh_sport));
	Log("debug: CheckUDP: dst port: %d\n", ntohs(udp->uh_dport));
#endif

return(TRUE);
}



/* XXX Not used yet */
int CheckICMP(const struct ip *ip, const struct icmp *icmp)
{
struct in_addr saddr;

saddr.s_addr = ip->ip_src.s_addr;

	Log("attackalert: ICMP scan from host %s\n", gblAttackerIP);
	printf("ICMP Scan from host %s\n", gblAttackerIP);

return(TRUE);
}



int CheckIP(const struct ip *ip)
{
int dataoffset = 0;

	/* This should never be less than 5 */
	if (ip->ip_hl < 5)
		{
			Log ("attackalert: Illegal IP header length detected in IP packet - length: %d from (possible) host: %s\n",
			ip->ip_hl, inet_ntoa (gblSrc));
			Log("attackalert: This could be an attempt to bypass detection or attack the system.\n");
		}
	else
		{
#ifdef DEBUG
			Log("debug: PktEngine: Found a good IP packet. Type: %d hlen: %d\n", ip->ip_p, ip->ip_hl);
#endif
			if((dataoffset = (ip->ip_hl * 4)) > 20)
				{
					Log ("attackalert: An IP packet with options set was found - length: %d from host: %s\n",
	 				ip->ip_hl, inet_ntoa (gblSrc));
					Log("attackalert: This could be an attempt to bypass detection or attack the system.\n");
				}
		}

/* XXX Put additional checks in here if anomaly flag is set */
return(dataoffset);
}


int
SmartVerify (int port, char *mode)
{
  int testSockfd;

/* Ok here is where we "Smart-Verify" the socket. If the port was previously */
/* unbound, but now appears to have someone there, then we will skip responding */
/* to this inbound packet. This a basic "stateful" inspection of the */
/* the connection */

  if (mode == "TCP")
	{
  	if ((testSockfd = OpenTCPSocket ()) == ERROR)
    	{
    	  Log ("adminalert: ERROR: could not open TCP socket to SmartVerify.\n");
     	 	return (FALSE);
    	}
	}
	else if (mode == "UDP")
	{
  	if ((testSockfd = OpenUDPSocket ()) == ERROR)
    	{
   	   	Log ("adminalert: ERROR: could not open UDP socket to SmartVerify.\n");
     	 	return (FALSE);
    	}
	}
	else
   	{
			Log ("adminalert: ERROR: Illegal socket mode passed to SmartVerify.\n");
   	 	return (FALSE);
   	}


  if (BindSocket (testSockfd, port) == ERROR)
		{
#ifdef DEBUG
 			Log ("debug: SmartVerify: SmartVerify Port In Use: %d", port);
#endif
 			close (testSockfd);
 			return (TRUE);
		}

  close (testSockfd);
  return (FALSE);
}


void
Usage (void)
{
  printf ("Psionic PortSentry - Port Scan Detector.\n");
  printf ("Copyright 1997-2002 Psionic Technologies, Inc. http://www.psionic.com\n");
  printf ("Licensing restrictions apply. COMMERCIAL RESALE PROHIBITED WITHOUT LICENSING.\n");
  printf ("See documentation for more information. Questions and comments: <sentrysupport@psionic.com>\n");
  printf ("Version: %s\n\n", VERSION);
  printf ("usage: portsentry\n\n");
  printf ("*** PLEASE READ THE DOCS BEFORE USING *** \n\n");
}

/* our cheesy state engine to monitor who has connected here before */
int
CheckStateEngine (char *target)
{
  int count = 0, scanDetectTrigger = TRUE;
  int gotOne = 0;

/* This is the rather basic scan state engine. It maintains     */
/* an array of past hosts who triggered a connection on a port */
/* when a new host arrives it is compared against the array */
/* if it is found in the array it increments a state counter by */
/* one and checks the remainder of the array. It does this until */
/* the end is reached or the trigger value has been exceeded */
/* This would probably be better as a linked list/hash table, */
/* but for the number of hosts we are tracking this is just as good. */
/* This will probably change in the future */

  gotOne = 1;			/* our flag counter if we get a match */
  scanDetectTrigger = TRUE;	/* set to TRUE until set otherwise */

  if (gblConfig.gblTriggerCount > 0)
    {
      for (count = 0; count < MAXSTATE; count++)
	{
	  /* if the array has the IP address then increment the gotOne counter and */
	  /* check the trigger value. If it is exceeded break out of the loop and */
	  /* set the detecttrigger to TRUE */
	  if (strcmp (gblConfig.gblScanDetectHost[count], target) == 0 )
	    {
	      /* compare the number of matches to the configured trigger value */
	      /* if we've exceeded we can stop this noise */
	      if (++gotOne >= gblConfig.gblTriggerCount)
		{
		  scanDetectTrigger = TRUE;
#ifdef DEBUG
		  Log ("debug: CheckStateEngine: host: %s has exceeded trigger value: %d\n",
		     gblConfig.gblScanDetectHost[count], gblConfig.gblTriggerCount);
#endif
		  break;
		}
	    }
	  else
	    scanDetectTrigger = FALSE;
	}

      /* now add the fresh meat into the state engine */
      /* if our array is still less than MAXSTATE large add it to the end */
      if (gblConfig.gblScanDetectCount < MAXSTATE)
	{
	  SafeStrncpy (gblConfig.gblScanDetectHost[gblConfig.gblScanDetectCount], target,
		       IPMAXBUF);
	  gblConfig.gblScanDetectCount++;
	}
      else
	{
	  /* otherwise tack it to the beginning and start overwriting older ones */
	  gblConfig.gblScanDetectCount = 0;
	  SafeStrncpy (gblConfig.gblScanDetectHost[gblConfig.gblScanDetectCount], target,
		       IPMAXBUF);
	  gblConfig.gblScanDetectCount++;
	}

#ifdef DEBUG
      for (count = 0; count < MAXSTATE; count++)
	Log ("debug: CheckStateEngine: state engine host: %s -> position: %d Detected: %d\n",
	   gblConfig.gblScanDetectHost[count], count, scanDetectTrigger);
#endif
      /* end catch to set state if gblConfigTriggerCount == 0 */
      if (gotOne >= gblConfig.gblTriggerCount)
	scanDetectTrigger = TRUE;
    }


  if (gblConfig.gblTriggerCount > MAXSTATE)
    {
      Log ("securityalert: WARNING: Trigger value %d is larger than state engine capacity of %d.\n",
	gblConfig.gblTriggerCount);
      Log ("Adjust the value lower or recompile with a larger state engine value.\n",
	 MAXSTATE);
      Log ("securityalert: Blocking host anyway because of invalid trigger value");
      scanDetectTrigger = TRUE;
    }
  return (scanDetectTrigger);
}




/* kill the connection depending on config option */
int
Dispose (char *target, int port, char *mode)
{
  int status = TRUE;
	int responseFlags = 0;

if (mode == "TCP")
	responseFlags = gblFlags.gblBlockTCP;
else if (mode == "UDP")
	responseFlags = gblFlags.gblBlockUDP;
else
	{
   Log ("attackalert: An unknown response type was passed to the Dispose function.\n");
   return(ERROR);
	}

#ifdef DEBUG
  Log ("debug: Dispose: disposing of host %s on port %d with mode %s and option: %d",
       target, port, mode, responseFlags);
  Log ("debug: Dispose: killRunCmd: %s", gblConfig.gblKillRunCmd);
  Log ("debug: Dispose: gblRunCmdFirst: %d", gblFlags.gblRunCmdFirst);
  Log ("debug: Dispose: killHostsDeny: %s", gblConfig.gblKillHostsDeny);
  Log ("debug: Dispose: killRoute: %s  %d", gblConfig.gblKillRoute,
       strlen (gblConfig.gblKillRoute));
#endif

	/* Should we ignore active response? */
	if (responseFlags == 1)
		{
			/* run external command first, hosts.deny second, dead route last */
			if (gblFlags.gblRunCmdFirst)
				{
					if (strlen (gblConfig.gblKillRunCmd) > 0)
						if (KillRunCmd (target, port, gblConfig.gblKillRunCmd, mode) != TRUE)
							status = FALSE;
					if (strlen (gblConfig.gblKillHostsDeny) > 0)
						if (KillHostsDeny (target, port, gblConfig.gblKillHostsDeny, mode) != TRUE)
							status = FALSE;
					if (strlen (gblConfig.gblKillRoute) > 0)
						if (KillRoute (target, port, gblConfig.gblKillRoute, mode) != TRUE)
							status = FALSE;
				}
			/* run hosts.deny first, dead route second, external command last */
			else
				{
					if (strlen (gblConfig.gblKillHostsDeny) > 0)
						if (KillHostsDeny (target, port, gblConfig.gblKillHostsDeny, mode) != TRUE)
						status = FALSE;
					if (strlen (gblConfig.gblKillRoute) > 0)
						if (KillRoute (target, port, gblConfig.gblKillRoute, mode) != TRUE)
						status = FALSE;
					if (strlen (gblConfig.gblKillRunCmd) > 0)
						if (KillRunCmd (target, port, gblConfig.gblKillRunCmd, mode) != TRUE)
						status = FALSE;
				}
		}
	else if (responseFlags == 2)
		{
			/* run external command only */
			if (strlen (gblConfig.gblKillRunCmd) > 0)
				if (KillRunCmd (target, port, gblConfig.gblKillRunCmd, mode) != TRUE)
				status = FALSE;
		}
	else
		Log ("attackalert: Ignoring response per configuration file setting.");

return (status);
}


