# Libreswan library for pluto
#
# mostly contains minor support items that are placed here to make unit testing
# of pluto easier. Generally, this code can depend upon -lswan, and -llswlog,
# it should not depend upon anything else (ideally, including other code in this
# this library)
#
# Copyright (C) 2007 Xelerance Corporation
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

srcdir?=${LIBRESWANSRCDIR}/lib/libpluto/

LIBRARY=pluto
LIB=lib${LIBRARY}.a
MANDIR=$(MANTREE)/man3

ONEFILE=pluto_constants.c
SRCS=pluto_constants.c packet.c
SRCS+=readwhackmsg.c

ifeq ($(USE_LIBCURL),true)
CFLAGS+=-DLIBCURL
endif

ifeq ($(USE_LDAP),true)
CFLAGS+=-DLDAP_VER=3
endif

#enable to get lots more debugging about semantics.
#CFLAGS+=-DPARSER_TYPE_DEBUG

OBJS=${SRCS:.c=.o} 

include ${srcdir}../Makefile.library

