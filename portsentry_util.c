/************************************************************************/
/*                                                                      */
/* Psionic PortSentry							*/
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 03-26-2002                                                 */
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
/* the software acknowledge that they will not hold Psionic Software	*/
/* liable for failure or non-function of the software product. YOU ARE 	*/
/* USING THIS PRODUCT AT YOUR OWN RISK.					*/
/*                                                                      */
/* Licensing restrictions apply. Commercial re-sell is prohibited under */
/* certain conditions. See the license that came with this package or 	*/
/* visit http://www.psionic.com for more information. 			*/
/*                                                                      */
/* $Id: portsentry_util.c,v 1.14 2002/04/08 16:48:54 crowland Exp crowland $ */
/************************************************************************/

#include "portsentry.h"
#include "portsentry_io.h"
#include "portsentry_util.h"

/* A replacement for strncpy that covers mistakes a little better */
char *
SafeStrncpy (char *dest, const char *src, size_t size)
{
  if (!dest)
    {
      dest = NULL;
      return (NULL);
    }
  else if (size < 1)
    {
      dest = NULL;
      return (NULL);
    }

  /* Null terminate string. */
  memset (dest, '\0', size);
  strncpy (dest, src, size - 1);

  return (dest);
}


/************************************************************************/
/* Generic safety function to process an IP address and remove anything */
/* that is:                                                             */
/* 1) Not a number.                                                     */
/* 2) Not a period.                                                     */
/* 3) Greater than IPMAXBUF (15)                                        */
/************************************************************************/
char *
CleanIpAddr (char *cleanAddr, const char *dirtyAddr)
{
  int count = 0, maxdot = 0, maxoctet = 0;

#ifdef DEBUG
  Log("debug: cleanAddr: Cleaning Ip address: %s", dirtyAddr);
#endif

  memset (cleanAddr, '\0', IPMAXBUF);
  /* dirtyAddr must be valid */
  if(dirtyAddr == NULL)
	return(cleanAddr);

  for (count = 0; count < IPMAXBUF - 1; count++)
    {
      if (isdigit (dirtyAddr[count]))
	{
	  if (++maxoctet > 3)
	    {
	      cleanAddr[count] = '\0';
	      break;
	    }
	  cleanAddr[count] = dirtyAddr[count];
	}
      else if (dirtyAddr[count] == '.')
	{
	  if (++maxdot > 3)
	    {
	      cleanAddr[count] = '\0';
	      break;
	    }
	  maxoctet = 0;
	  cleanAddr[count] = dirtyAddr[count];
	}
      else
	{
	  cleanAddr[count] = '\0';
	  break;
	}
    }

#ifdef DEBUG
  Log("debug: cleanAddr: Cleaned IpAddress: %s Dirty IpAddress: %s", cleanAddr, dirtyAddr);
#endif

  return (cleanAddr);
}


/************************************************************************/
/* Generic safety function to process an unresolved address and remove  */
/* anything that is:                                                    */
/* 1) Not a number.                                                     */
/* 2) Not a period.                                                     */
/* 3) Greater than DNSMAXBUF (255)                                      */
/* 4) Not a legal DNS character (a-z, A-Z, 0-9, - )			*/
/* 									*/
/* XXX THIS FUNCTION IS NOT COMPLETE 					*/
/************************************************************************/
int CleanAndResolve (char *resolvedHost, const char *unresolvedHost)
{
  struct hostent *hostPtr = NULL;
  struct in_addr addr;

#ifdef DEBUG
  Log("debug: CleanAndResolv: Resolving address: %s", unresolvedHost);
#endif

  memset (resolvedHost, '\0', DNSMAXBUF);
  /* unresolvedHost must be valid */
  if(unresolvedHost == NULL)
	return(ERROR);
  
  /* Not a valid address */
  if ((inet_aton(unresolvedHost, &addr)) == 0)
	return(ERROR);

  hostPtr = gethostbyaddr ((char *) &addr.s_addr, sizeof (addr.s_addr), AF_INET);
  if (hostPtr != NULL)
  	snprintf (resolvedHost, DNSMAXBUF, "%s", hostPtr->h_name);
  else
  	snprintf (resolvedHost, DNSMAXBUF, "%s", unresolvedHost);

#ifdef DEBUG
  Log("debug: CleanAndResolve: Cleaned Resolved: %s Dirty Unresolved: %s", resolvedHost, unresolvedHost);
#endif

  return (TRUE);
}


