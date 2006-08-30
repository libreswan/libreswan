# Copyright (C) 2000, 2001  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: Makefile,v 1.11 2005/09/17 21:57:45 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

CINCLUDES =	-I${srcdir}${ISCARCH}/include \
		-I${srcdir}../libisc/${ISCARCH}/include \
		-I${srcdir}../libisc/include \
		-I. -I./include -I${srcdir}include 
CDEFINES = -g
CWARNINGS = -Werror

CFLAGS=${USERCOMPILE} ${PORTINCLUDE} ${CINCLUDES} ${CDEFINES} ${CWARNINGS} 

VERSION="@(\#) openswan-hacking-9.3-for-osw2"
LIBINTERFACE=2
LIBREVISION=0
LIBAGE=1

# Alphabetically
OBJS =		async.o context.o gai_strerror.o getaddrinfo.o gethost.o \
		getipnode.o getnameinfo.o getrrset.o getrrset2.o herror.o \
		lwbuffer.o lwconfig.o lwpacket.o lwresutil.o \
		lwres_gabn.o lwres_gnba.o lwres_grbn.o lwres_noop.o \
		lwinetaton.o lwinetpton.o lwinetntop.o version.o

# Alphabetically
SRCS =		async.c context.c gai_strerror.c getaddrinfo.c gethost.c \
		getipnode.c getnameinfo.c getrrset.c getrrset2.c herror.c \
		lwbuffer.c lwconfig.c lwpacket.c lwresutil.c \
		lwres_gabn.c lwres_gnba.c lwres_grbn.c lwres_noop.c \
		lwinetaton.c lwinetpton.c lwinetntop.c

LIB=liblwres.a
LIBRARY=lwres
ONEFILE=async.c

.PHONY:	all install clean l t lt tar check depend checkprograms

all: programs

version.o: version.c
	${LIBTOOL} ${CC} ${CFLAGS} \
		-DVERSION=\"${VERSION}\" \
		-DLIBINTERFACE=${LIBINTERFACE} \
		-DLIBREVISION=${LIBREVISION} \
		-DLIBAGE=${LIBAGE} \
		${CINCLUDES} ${CDEFINES} ${CWARNINGS} \
		-c ${srcdir}version.c

timestamp: liblwres.a
	touch timestamp

$(OBJS):	$(HDRS)

check:
	echo no checks in lib right now.

checkprograms:
	@true

include ${srcdir}../Makefile.library
