/************************************************************************/
/*                                                                      */
/* Psionic PortSentry							*/
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 03-05-2002                                                 */
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
/* the software acknowledge that they will not hold Psionic Technlogies	*/
/* liable for failure or non-function of the software product. YOU ARE 	*/
/* USING THIS PRODUCT AT YOUR OWN RISK.					*/
/*                                                                      */
/* Licensing restrictions apply. Commercial re-sell is prohibited under */
/* certain conditions. See the license that came with this package or 	*/
/* visit http://www.psionic.com for more information. 			*/
/*                                                                      */
/* $Id: portsentry_config.h,v 1.7 2002/04/08 17:23:46 crowland Exp crowland $ */
/************************************************************************/

/* IMPORTANT NOTE: If you're editing this file DON'T DELETE THE '#' signs! */
/* We get questions from people who do this thinking they are comments. */
/* They are not comments and are required. This file is going to disappear */
/* in the later versions of this program so don't get too attached to it. */

/* These are probably ok. Be sure you change the Makefile if you */
/* change the path */
#define CONFIG_FILE "/usr/local/psionic/portsentry2/portsentry.conf"

/* The location of Wietse Venema's TCP Wrapper hosts.deny file */
#define WRAPPER_HOSTS_DENY "/etc/hosts.deny"

/* The default syslog is as daemon.notice. You can also use */
/* any of the facilities from syslog.h to send messages to (LOCAL0, etc) */
#define SYSLOG_FACILITY LOG_DAEMON
#define SYSLOG_LEVEL LOG_NOTICE


/* the maximum number of hosts to keep in a "previous connect" state engine*/
#define MAXSTATE 50 

