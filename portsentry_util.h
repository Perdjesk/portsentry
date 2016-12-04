/************************************************************************/
/*                                                                      */
/* Psionic PortSentry							*/
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 06-26-2002                                                 */
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
/* $Id: portsentry_util.h,v 1.10 2002/03/27 22:32:14 crowland Exp crowland $ */
/************************************************************************/


/* IP address length plus null */
#define IPMAXBUF 16


char * SafeStrncpy (char *, const char *, size_t ); 
char * CleanIpAddr (char *, const char *);
int CleanAndResolve (char *, const char *);

