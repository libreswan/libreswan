# Pluto Makefile
# Copyright (C) 2001  Michael Richardson
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
# RCSID $Id: Makefile,v 1.6 2004/04/03 19:44:52 ken Exp $



include ../../../Makefile.inc



FMANDIR=$(MANTREE)/man5
PMANDIR=$(MANTREE)/man8

OPENSWANSRCDIR=../../..
FREESWANLIBDIR=${OPENSWANSRCDIR}/lib
FREESWANINCLS= -I$(FREESWANLIBDIR) -I${OPENSWANSRCDIR}
FREESWANLIB=$(FREESWANLIBDIR)/libfreeswan.a

CFLAGS = -g -Wall -W -Wmissing-prototypes -Wpointer-arith -Wbad-function-cast \
	-Wcast-qual -Wmissing-declarations -Wwrite-strings 
CFLAGS+= -Wstrict-prototypes 
CFLAGS+= -Werror
#CFLAGS+= -Wundef

HDRDIRS =  $(FREESWANINCLS)

CPPFLAGS = $(HDRDIRS) $(BYTE_ORDER) -DDEBUG 

ALLFLAGS = $(CPPFLAGS) $(CFLAGS)

LIBSWHACK =

BINNAMEPING  = ikeping

RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

# files for a (source) distribution

OBJSPING = ikeping.o $(FREESWANLIB)

all: $(BINNAMEPING)

install: all
	$(INSTALL) $(INSTBINFLAGS) $(BINNAMEPING) $(BINDIR)
	$(INSTALL) $(INSTMANFLAGS) ikeping.8 $(PMANDIR)/ipsec_ikeping.8

$(BINNAMEPING): $(OBJSPING)
	$(CC) -o $(BINNAMEPING) $(LDFLAGS) $(OBJSPING) $(LIBSPING)

distlist:
	@echo $(DIST)

# Exuberant Ctags doesn't work if LC_ALL is set to something other than C

CTAGSFLAGS = -N --format=1 # fishy options required for Exuberant Ctags

tags:	$(DISTSRC)
	LC_ALL=C ctags $(CTAGSFLAGS) $(DISTSRC)

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

clean:
	$(RM) $(RMFLAGS) $(OBJSPING) *.core core *~ a.out ktrace.out
	$(RM) $(RMFLAGS) $(BINNAMEPING) 

check:
	echo no checks in lib right now.

.c.o:
	$(CC) $(COPTS) $(ALLFLAGS) -c $<

# These rules are not for production use
$(FREESWANLIB):
	cd $(FREESWANLIBDIR) ; $(MAKE)

programs: ikeping

checkprograms: ikeping

check: 


ikeping.o: ${OPENSWANSRCDIR}/pluto/constants.h
ikeping.o: ${OPENSWANSRCDIR}/pluto/packet.h
ikeping.o: ${OPENSWANSRCDIR}/lib/freeswan.h
