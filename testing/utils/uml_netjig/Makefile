# FreeS/WAN subdir makefile
# Copyright (C) 1998-2001  Henry Spencer.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.22 2004/04/03 19:44:52 ken Exp $

OPENSWANSRCDIR=../../..
OBJS = nethub.o cmdmode.o port.o hash.o tuntap.o
OBJS+=getopt_long.o

NOBJS = uml_netjig.o $(OBJS)
SOBJS = uml_switch.o $(OBJS)

OPTIONS=-DARP_PROCESS -DTUNTAP

# To use the netdissect option, you have to have a very recent (pre-alpha) copy
# of tcpdump source code from www.tcpdump.org. For now, leave it unset.
# 
# If you want to play with it, you'll need libnetdissect.a. You can get this
# by checking code out of www.tcpdump.org:
#
# cvs -d :pserver:tcpdump@cvs.tcpdump.org:/tcpdump/master checkout -rmcr_dissect -dnetdissect_tcpdump
#
#NETDISSECTH=-DNETDISSECT -I/home/mcr/src/tcpdump
#NETDISSECTLIB=-L/home/mcr/src/linux/i386/tcpdump -lnetdissect

# to decode ESP packets (with netdissect), you need crypto, which you can
# get from ssl. 
#OPENSSL=-L/usr/local/ssl/lib -lcrypto

# To read/write files, you need to have libpcap (-devel if on RH) installed.
PCAPH=-I/usr/include/pcap
PCAPLIB=-lpcap
#PCAPH=-I/home/mcr/src/libpcap
#PCAPLIB=-L/home/mcr/src/linux/i386/libpcap -lpcap

CFLAGS = -g -Wall ${PCAPH} ${NETDISSECTH} ${OPTIONS}
LIBS = ${NETDISSECTLIB} ${PCAPLIB} ${OPENSSL}


include $(OPENSWANSRCDIR)/Makefile.inc

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

checkprograms: uml_netjig uml_switch

uml_netjig : $(NOBJS)
	$(CC) $(CFLAGS) -o uml_netjig $(NOBJS) $(LIBS)

uml_switch : $(SOBJS)
	$(CC) $(CFLAGS) -o uml_switch $(SOBJS) $(LIBS)

clean : 
	rm -f uml_netjig uml_switch $(SOBJS) $(NOBJS) *~

install_check: uml_netjig
	@install -d $(LIBEXECDIR)
	@install -s uml_netjig $(LIBEXECDIR)

install_file_list:
	@true

install programs check: 
	@true

depend: 
	makedepend -- ${CFLAGS} -- ${NOBJS:.o=.c} uml_netjig.c uml_switch.c

# DO NOT DELETE - these were hand edited.

nethub.o: port.h hash.h nethub.h netjig.h nethub.c
cmdmode.o: nethub.h netjig.h cmdmode.c
port.o: hash.h port.h nethub.h port.c
hash.o: switch.h hash.h hash.c
tuntap.o: port.h tuntap.c
uml_netjig.o: port.h hash.h netjig.h nethub.h uml_netjig.c
uml_switch.o: port.h hash.h netjig.h nethub.h uml_netjig.c
