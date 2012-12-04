# Libreswan library for parsing configuration files
# Copyright (C) 2005 Michael Richardson <mcr@xelerance.com> Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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


LIBRESWANSRCDIR?=$(shell cd ../..; pwd)

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

LIBRARY=ipsecconf
LIB=lib${LIBRARY}.a
MANDIR=$(MANTREE)/man3

ONEFILE=parser.y
SRCS=confread.c confwrite.c starterwhack.c starterlog.c 
SRCS+=cmp.c parser.tab.c lex.yy.c keywords.c alloc.c oeconns.c
SRCS+=interfaces.c

#enable to get lots more debugging about semantics.
#CFLAGS+=-DPARSER_TYPE_DEBUG

#ifeq ($(USE_FIPSCHECK),true)
#CFLAGS+=-DFIPS_CHECK
#endif

ifeq ($(USE_NM),true)
CFLAGS+=-DHAVE_NM
endif

ifeq ($(USE_LABELED_IPSEC),true)
CFLAGS+=-DHAVE_LABELED_IPSEC
endif

OBJS=${SRCS:.c=.o} 

include ${srcdir}../Makefile.library

keywords.c: parser.tab.h

lex.yy.c: parser.tab.c parser.l parser.y 
	$(LEX) ${srcdir}parser.l

parser.tab.h parser.tab.c: parser.l parser.y 
	$(BISON) ${BISONOSFLAGS} -v -d ${srcdir}parser.y

cleanall::
	$(RM) -f parser.tab.* lex.yy.*



