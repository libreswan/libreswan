# Libreswan library for faking out the kernel
# Copyright (C) 2005 Xelerance Corporation
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


LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

MANDIR=$(MANTREE)/man3

SRCS=printk.c jiffies.c sysctl.c panic.c skb.c netif.c stack.c
SRCS+=vmalloc.c  module.c debugflags.c
SRCS+=bh.c ipv4.c talloc.c skbcreate.c
# XXX need to have checksum.c for non-x86

ASSRCS+=checksum.S

KSRCS=kernelenv.c core.c

OBJS=${SRCS:.c=.o} ${ASSRCS:.S=.o} ${KSRCS:.c=.o} version.o

LIBA=libkern.a
KLIPSSRCDIR=${LIBRESWANSRCDIR}/linux

UMLPLAIN=$(shell . ${LIBRESWANSRCDIR}/umlsetup.sh; echo $${POOLSPACE}/plain$${KERNVER})

# Original flags
CFLAGS=-I. -I${KLIPSSRCDIR}/include -I${LIBRESWANSRCDIR}
CFLAGS+=-DHAVE_IP_PKTINFO
CFLAGS+= -I${LIBRESWANSRCDIR}/testing/kunit/include
CFLAGS+= -I${LIBRESWANSRCDIR}/include -g -O2
#KLIPS_FLAGS+=-D__KERNEL__
#KLIPS_FLAGS+=-O2 -U__i386__ -Ui386  -D__arch_um__ -DSUBARCH=\"i386\"
#KLIPS_FLAGS+=-I${UMLPLAIN}/include
#KLIPS_FLAGS+=-I${UMLPLAIN}/arch/um/include
#KLIPS_FLAGS+=-I${UMLPLAIN}/arch/um/kernel/tt/include
#KLIPS_FLAGS+=-I${UMLPLAIN}/arch/um/kernel/skas/include
CFLAGS+=${KLIPS_FLAGS}
CFLAGS+= ${WERROR}

CFLAGS+= -fno-inline

ARFLAGS=crvs
EXTHDRS=
EXTLIBS=
MANS=

.PHONY:	all install clean l t lt tar check checkprograms

all:	$(LIBA) ${LIBL}
programs: $(LIBA) ${LIBL}

install:

install_file_list:

$(LIBA): $(OBJS)
	$(AR) $(ARFLAGS) $(LIBA) $(OBJS)

$(OBJS):	$(HDRS)

$(LOGOBJS):	$(HDRS)

# build version.c using version number from Makefile.ver
version.c:	${SRCDIR}version.in.c ${LIBRESWANSRCDIR}/Makefile.ver
	sed '/"/s/@IPSECVERSION@/$(IPSECVERSION)/' ${SRCDIR}version.in.c >$@

clean:
	rm -f $(LIB) *.o try* core *.core $(EXTHDRS) $(EXTLIBS) version.c


tar:	clean
	tar -cvf /tmp/lib.tar Makefile [a-z]*

check:	libkern.a

checkprograms:

# DO NOT DELETE
