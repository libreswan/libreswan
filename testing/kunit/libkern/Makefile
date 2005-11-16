# Openswan library for faking out the kernel
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
#
# RCSID $Id: Makefile,v 1.6 2005/04/28 21:01:13 mcr Exp $


OPENSWANSRCDIR?=$(shell cd ../../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

MANDIR=$(MANTREE)/man3

SRCS=printk.c jiffies.c sysctl.c panic.c skb.c netif.c stack.c
SRCS+=vmalloc.c  module.c
SRCS+=bh.c checksum.S ipv4.c talloc.c skbcreate.c

KSRCS=kernelenv.c core.c

OBJS=${SRCS:.c=.o} ${SRCS:.S=.o} ${KSRCS:.c=.o} version.o

LIBA=libkern.a
KLIPSSRCDIR=${OPENSWANSRCDIR}/linux

UMLPLAIN=$(shell source ${OPENSWANSRCDIR}/umlsetup.sh; echo $${POOLSPACE}/plain$${KERNVER})

# Original flags
CFLAGS=-I. -I${KLIPSSRCDIR}/include -I${OPENSWANSRCDIR} -DDEBUG
CFLAGS+=-DWITH_UDPFROMTO -DHAVE_IP_PKTINFO
CFLAGS+= -I${OPENSWANSRCDIR}/testing/kunit/include
CFLAGS+= -I${OPENSWANSRCDIR}/include -g -O2
#KLIPS_FLAGS+=-D__KERNEL__ 
#KLIPS_FLAGS+=-O2 -U__i386__ -Ui386  -D__arch_um__ -DSUBARCH=\"i386\" 
KLIPS_FLAGS+=-I${UMLPLAIN}/include
KLIPS_FLAGS+=-I${UMLPLAIN}/arch/um/include
KLIPS_FLAGS+=-I${UMLPLAIN}/arch/um/kernel/tt/include
KLIPS_FLAGS+=-I${UMLPLAIN}/arch/um/kernel/skas/include
CFLAGS+=${KLIPS_FLAGS}
CFLAGS+= -Wall
#CFLAGS+= -Wconversion
#CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wcast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
CFLAGS+= -Wbad-function-cast 
CFLAGS+= -fno-inline

ARFLAGS=crvs
EXTHDRS=
EXTLIBS=
MANS=

.PHONY:	all install clean l t lt tar check depend checkprograms

all:	$(LIBA) ${LIBL}
programs: $(LIBA) ${LIBL}

install:

install_file_list:

$(LIBA): $(OBJS)
	$(AR) $(ARFLAGS) $(LIBA) $(OBJS)

$(OBJS):	$(HDRS)

$(LOGOBJS):	$(HDRS)

# build version.c using version number from Makefile.ver
version.c:	version.in.c ${OPENSWANSRCDIR}/Makefile.ver
	sed '/"/s/xxx/$(IPSECVERSION)/' version.in.c >$@

clean:
	rm -f $(LIB) *.o try* core *.core $(EXTHDRS) $(EXTLIBS) version.c


tar:	clean
	tar -cvf /tmp/lib.tar Makefile [a-z]*

check:	libkern.a

depend:
	makedepend -Y -- $(CFLAGS) -- $(SRCS)

checkprograms:

# DO NOT DELETE
