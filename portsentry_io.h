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
/* the software acknowledge that they will not hold Psionic Software	*/
/* liable for failure or non-function of the software product. YOU ARE 	*/
/* USING THIS PRODUCT AT YOUR OWN RISK.					*/
/*                                                                      */
/* Licensing restrictions apply. Commercial re-sell is prohibited under */
/* certain conditions. See the license that came with this package or 	*/
/* visit http://www.psionic.com for more information. 			*/
/*                                                                      */
/* $Id: portsentry_io.h,v 1.17 2002/03/06 04:53:43 crowland Exp crowland $ */
/************************************************************************/

/* prototypes */
void Log (char *,...);
void ExitNow (int);
void Start (void);
void PrintStats(void);
int DaemonSeed (void);
int NeverBlock (char *, char *);
int WriteBlocked (char *, char *, char *, char *, int , int, char *, char *);
int CheckConfig (void);
int BindSocket (int, int);
int OpenTCPSocket (void);
int OpenUDPSocket (void);
int KillRoute (char *, int, char *, char *);
int KillHostsDeny (char *, int, char *, char *);
int KillRunCmd (char *, int, char *, char *);
int ConfigTokenRetrieve (char *, char *);
int IsBlocked (char *, char *);
int SubstString (const char *, const char *, const char *, char *);
int CheckFlag (char *);
int CompareIPs(char *, char *, int);
void SignalCatcher(int);
