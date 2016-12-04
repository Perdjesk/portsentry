# Makefile for PortSentry package.
# 
# Send problems/code hacks to sentrysupport@psionic.com 
#
#
#
# $Id: Makefile,v 1.78 2002/04/08 17:42:33 crowland Exp crowland $
#
# Generic compiler (usually linked to gcc on most platforms)
CC = cc

# GNU..
#CC = gcc 

# Normal systems flags
CFLAGS = -O -Wall

# Debug mode for portsentry
#CFLAGS = -Wall -g -DNODAEMON -DDEBUG
#CFLAGS = -Wall -g -DNODAEMON -DDEBUG -DDEBUG2
#CFLAGS = -Wall -g -DNODAEMON
#CFLAGS = -Wall -g -DDEBUG

# Profiler mode for portsentry
#CFLAGS = -pg -O -Wall -DNODAEMON
#LIBS = /usr/lib/libefence.a

INSTALLDIR = /usr/local/psionic
CHILDDIR=/portsentry2

all:
		@echo ""
		@echo ""
		@echo "Usage: make <systype>"
		@echo ""
		@echo "<systype> is one of: generic, linux, bsd, openbsd, freebsd, netbsd"
		@echo ""
		@echo "NOTE: bsd, openbsd, freebsd, netbsd, generic have NOT BEEN TESTED FOR THIS BETA VERSION" 
		@echo ""
		@echo "This code requires snprintf()/vsnprintf() system calls"
		@echo "to work. If you run a modern OS it should work on"
		@echo "your system with 'make generic'. If you get it to"
		@echo "work on an unlisted OS please write us with the" 
		@echo "changes." 
		@echo "" 
		@echo "Install: AFTER YOU FOLLOWED THE ABOVE STEP: make install"
		@echo "" 
		@echo "NOTE: This will install the package in this" 
		@echo "      directory: $(INSTALLDIR)" 
		@echo "" 
		@echo "Edit the makefile if you wish to change these paths." 
		@echo "Existing files will be moved to a .bak extension."

clean:		
		/bin/rm ./portsentry

uninstall:	
		/bin/rm $(INSTALLDIR)$(CHILDDIR)/*
		/bin/rmdir $(INSTALLDIR)

install:	
		@echo "Creating psionic directory $(INSTALLDIR)"
		@if [ ! -d $(INSTALLDIR) ]; then /bin/mkdir $(INSTALLDIR); fi
		@echo "Setting directory permissions"
		@if [ "$(INSTALLDIR)" = "/usr/local/psionic" ]; then /bin/chmod 700 $(INSTALLDIR) ; fi
		@echo "Creating portsentry directory $(INSTALLDIR)$(CHILDDIR)"
		@if [ ! -d $(INSTALLDIR)$(CHILDDIR) ]; then /bin/mkdir\
			$(INSTALLDIR)$(CHILDDIR); fi
		@echo "Setting directory permissions"
		chmod 700 $(INSTALLDIR)$(CHILDDIR)
		@echo "Copying files"
		@if [ -f $(INSTALLDIR)$(CHILDDIR)/portsentry.conf ]; then /bin/cp\
		$(INSTALLDIR)$(CHILDDIR)/portsentry.conf $(INSTALLDIR)$(CHILDDIR)/portsentry.conf.bak; fi
		cp ./portsentry.conf $(INSTALLDIR)$(CHILDDIR)
		@if [ -f $(INSTALLDIR)$(CHILDDIR)/portsentry.ignore ]; then /bin/cp\
		$(INSTALLDIR)$(CHILDDIR)/portsentry.ignore $(INSTALLDIR)$(CHILDDIR)/portsentry.ignore.bak; fi
		cp ./portsentry.ignore $(INSTALLDIR)$(CHILDDIR)
		@if [ -f $(INSTALLDIR)$(CHILDDIR)/portsentry ]; then /bin/cp\
		$(INSTALLDIR)$(CHILDDIR)/portsentry $(INSTALLDIR)$(CHILDDIR)/portsentry.bak; fi
		cp ./portsentry $(INSTALLDIR)$(CHILDDIR)
		@echo "Setting permissions"
		chmod 600 $(INSTALLDIR)$(CHILDDIR)/portsentry.ignore
		chmod 600 $(INSTALLDIR)$(CHILDDIR)/portsentry.conf
		chmod 700 $(INSTALLDIR)$(CHILDDIR)/portsentry
		@echo ""
		@echo ""
		@echo "Edit $(INSTALLDIR)$(CHILDDIR)/portsentry.conf and change"
		@echo "your settings if you haven't already. (route, etc)" 
		@echo ""
		@echo ""

linux:		
		SYSTYPE=linux 
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -D_BSD_SOURCE -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c -lpcap


# The following are NOT TESTED for Beta

openbsd:		
		SYSTYPE=openbsd
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c -lpcap


bsd:		
		SYSTYPE=bsd
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c -lpcap

freebsd:		
		SYSTYPE=freebsd
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c -lpcap

osx:		
		SYSTYPE=osx
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c -lpcap

netbsd:		
		SYSTYPE=netbsd
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c -lpcap


generic:		
		SYSTYPE=generic
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c -lpcap

