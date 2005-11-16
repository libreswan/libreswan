# openswan userland AES library
# Copyright (C) 2004	Michael Richardson <mcr@xelerance.com>
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
# RCSID $Id: Makefile,v 1.6 2004/12/18 18:13:33 mcr Exp $


OPENSWANSRCDIR?=$(shell cd ../../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

AES_CORE_OBJ:=aes.o
AES_CORE_SRC:=aes.c

ASM-$(ARCH_ASM):=1
ASM_X86:=$(ASM-i586)$(ASM-i686)
ifneq ($(strip $(ASM_X86)),)
AES_CORE_OBJ:= aes-i586.o
AES_CORE_SRC:= aes-i586.S
endif

BASE_SRCS=aes_xcbc_mac.c aes_cbc.o 
SRCS=${BASE_SRCS} ${AES_CORE_SRC}

OBJS=${BASE_SRCS:.c=.o} ${AES_CORE_OBJ}

HDRS=	

KLIPSD=${OPENSWANSRCDIR}/linux/include
SRCDIR=${OPENSWANSRCDIR}/linux/net/ipsec/aes

VPATH += ${SRCDIR}

LIB=libaes.a

# Original flags
CFLAGS=-I. -I${SRCDIR} -I${KLIPSD} -I${OPENSWANSRCDIR} $(USERCOMPILE)
CFLAGS+=-O3 -fomit-frame-pointer -Wall  -Wcast-qual 
CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wcast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
CFLAGS+= -Wbad-function-cast 

.PHONY:	all install clean check depend checkprograms

all:	$(LIB) 
programs: $(LIB)

install install_file_list:
	@exit 0

$(LIB):	$(OBJS)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

clean:
	rm -f $(LIB) *.o try* core *.core $(EXTHDRS) $(EXTLIBS) version.c

check:
	echo no checks in lib right now.

depend:
	makedepend -Y -- $(CFLAGS) -- $(SRCS)

checkprograms:

# DO NOT DELETE

#aes_xcbc_mac.o: aes.h aes_xcbc_mac.h
#aes.o: aes.h 
