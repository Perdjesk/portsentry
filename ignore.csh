#!/bin/csh -f
#########################################################################
# This script automatically adds hosts to the .ignore file              #
# of PortSentry. This is useful for dynamic IP hosts and                #
# should be run after each reboot or IP change.                         #
#                                                                       #
# Author: Christopher P. Lindsey <lindsey@mallorn.com>                  #
# Date: 06-03-99                                                        #
# Note: Created script                                                  #
#                                                                       #
# Modified: Craig H. Rowland <crowland@psionic.com>                     #
# Modified Date: 06-03-99                                               #
# Modified Note: Fixed /tmp race condition. Added secure path.          #
#                                                                       #
# Modified: Christopher P. Lindsey <lindsey@mallorn.com>                #
# Modified Date: 06-04-99                                               #
# Modified Note: Added support for various OSs, -f flag on startup      #
#									#
# Modified: Craig H. Rowland <crowland@psionic.com>	                #
# Modified Date: 04-08-02                                               #
# Modified Note: Changed SENTRYDIR to portsentry2			#
#									#	
#                                                                       #
# $Id: ignore.csh,v 1.5 2002/04/08 17:23:58 crowland Exp crowland $     #
#########################################################################

# Choose an OS
#
# Acceptable values are "FreeBSD", "HPUX", "IRIX", "Linux", "OSF1",
# "NeXTStep", "Solaris 2.x", "SunOS 4.x"
set OS="Linux"

# Known good path
set path = (/bin /usr/bin /sbin /usr/sbin)

if ($OS == "IRIX") then
   set path = ($path /usr/etc)
elseif ($OS == "NeXTStep" || $OS == "SunOS 4.x") then
   set path = ($path /etc)
endif
  
# Safe directory 
set SENTRYDIR=/usr/local/psionic/portsentry2
set TMPFILE=portsentry.ignore.tmp
 
if (-f $SENTRYDIR/portsentry.ignore) then 
   head -3 $SENTRYDIR/portsentry.ignore > $SENTRYDIR/$TMPFILE
else
   echo > $SENTRYDIR/$TMPFILE
endif

# This entry should always be in the file.
echo '0.0.0.0' >> $SENTRYDIR/$TMPFILE

if ($OS == "Linux") then 
   foreach i ( `ifconfig -a | grep inet | awk '{print $2}' | sed 's/addr://'` )
      echo $i >> $SENTRYDIR/$TMPFILE
   end
else if ($OS == "HPUX") then
   foreach i (`lanscan -i`)
      ifconfig $i | grep inet | awk '{print $2}' >> $SENTRYDIR/$TMPFILE
   end
else if ($OS == "Solaris 2.x" || $OS == "NeXTStep" || $OS == "FreeBSD" || \
         $OS == "SunOS 4.x" || $OS == "OSF1" || $OS == "IRIX") then
   foreach i ( `ifconfig -a | grep inet | awk '{print $2}'` )
      echo $i >> $SENTRYDIR/$TMPFILE
   end
endif

cp $SENTRYDIR/$TMPFILE $SENTRYDIR/portsentry.ignore
rm $SENTRYDIR/$TMPFILE
