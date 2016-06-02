# Libreswan library

# Copyright (C) 1998-2001  Henry Spencer.
# Copyright (C) 2003, 2004 Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
# Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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

ifndef top_srcdir
include ../../mk/dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk
include $(top_srcdir)/mk/targets.mk

X509LIB=x509dn.c asn1.c oid.c

SRCS=addrtoa.c addrtot.c addrtypeof.c alg_info.c anyaddr.c \
	constants.c datatot.c \
	alloc.c diag.c \
	goodmask.c id.c initaddr.c initsaid.c initsubnet.c \
	nss_copies.c \
	iprange.c \
        keyblobtoid.c \
	kernel_alg.c lex.c \
	realtimetoa.c lswconf.c \
	lswfips.c \
	portof.c rangetosubnet.c sameaddr.c \
	satot.c secrets.c subnetof.c subnettoa.c subnettot.c \
	subnettypeof.c ttoaddr.c ttodata.c ttoprotoport.c \
	ttorange.c ttosa.c ttosubnet.c ttoul.c ultot.c \
	secitem_chunk.c \
	base64_rsa_pubkey.c \
	lswnss.c \
	$(X509LIB)

ifeq ($(USE_DNSSEC),true)
SRCS+=unbound.c
endif

SRCS+=sanitizestring.c pfkey_print.c pfkey_sock.c pfkey_error.c

ifeq ($(USE_KLIPS),true)
KLIPS_DEFS=-DKLIPS
endif

ifeq ($(USE_PFKEYv2),true)
PFKEYV2_DEFS=-DPFKEYV2
PFKEYV2_SRCS+=pfkey_v2_build.c pfkey_v2_ext_bits.c pfkey_v2_parse.c
PFKEYV2_SRCS+=pfkey_v2_debug.c
endif

CFLAGS+=-I${LIBRESWANSRCDIR}/lib/libcrypto/libsha2
CFLAGS+=-I${LIBRESWANSRCDIR}/lib/libcrypto/libaes_xcbc

LOGSRCS=lswlog.c lswid.c


OBJS=${SRCS:.c=.o} ${PFKEYV2_SRCS:.c=.o} version.o
LOGOBJS=${LOGSRCS:.c=.o}

KLIPSSRCDIR?=${LIBRESWANSRCDIR}/linux/net/ipsec

VPATH+= ${KLIPSSRCDIR}

HDRS=${KLIPSINC}/libreswan.h internal.h

LIBA=libswan.a
LIBL=liblswlog.a
# Original flags
CFLAGS+=${PORTINCLUDE} -I. -I${KLIPSSRCDIR} -I${KLIPSINC}
CFLAGS+=-I${LIBRESWANSRCDIR}
CFLAGS+=${PFKEYV2_DEFS} ${KLIPS_DEFS} $(NSSFLAGS)
CFLAGS+=-I${LIBRESWANSRCDIR}/include ${PORTINCLUDE}
# XXX: hack until everything uses a consistent .c.o rule
CFLAGS+=$(USERLAND_CFLAGS)
CFLAGS+=${CROSSFLAGS}

ARFLAGS=crvs
EXTHDRS=des.h
EXTLIBS=libdes.a

# XXX: Switch directory hack
local-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) buildall

local-clean-base:
	rm -f $(builddir)/*core* core *.core
	rm -f $(foreach f,$(OBJS) $(LOGOBJS) $(LIBA) $(LIBL) $(EXTHDRS) $(EXTLIBS) version.c, $(builddir)/$(f))

buildall: $(LIBA) $(LIBL)
list-local-base:
	@: never nothing to do

$(LIBA): $(OBJS)
	$(AR) $(ARFLAGS) $(LIBA) $(OBJS)

$(LIBL): $(LOGOBJS)
	$(AR) $(ARFLAGS) $(LIBL) $(LOGOBJS)

$(OBJS):	$(HDRS)

$(LOGOBJS):	$(HDRS)

# build version.c using version number from Makefile.ver
version.c:	version.in.c ${LIBRESWANSRCDIR}/Makefile.ver
	sed -e '/"/s/@IPSECVERSION@/$(IPSECVERSION)/' -e '/"/s/@IPSECVIDVERSION@/$(IPSECVIDVERSION)/' ${KLIPSSRCDIR}/version.in.c >$@

#libdes.a:	../libdes/libdes.a
#	ln -f -s ../libdes/libdes.a
#
# yes, that's CFLAG=, not CFLAGS=
#../libdes/libdes.a:
#	cd ../libdes ; \
#	if test " `arch | sed 's/^i[3456]/x/'`" = " x86" ; \
#	then $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' TESTING='' x86-elf ; \
#	else $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' libdes.a ; \
#	fi

test-%: %.c
	${CC} ${CFLAGS} -D`echo $* | tr 'a-z' 'A-Z'`_MAIN $*.c -o test-$*

# developer-only stuff
l:
	$(MAKE) $(LIB) ARFLAGS=crv CFLAGS=-O
	$(RANLIB) $(LIB)

t:	$(LIB)
	ln -f -s ${KLIPSSRCDIR}/ttosubnet.c try1a.c
	${CC} ${CFLAGS} -DTTOSUBNET_MAIN try1a.c $(LIB) -o try1a
	./try1a -r
	ln -f -s ${KLIPSSRCDIR}/ttodata.c try2.c
	${CC} ${CFLAGS} -DTTODATA_MAIN try2.c $(LIB) -o try2
	./try2 -r
	ln -f -s ${KLIPSSRCDIR}/ttosa.c try4a.c
	${CC} ${CFLAGS} -DTTOSA_MAIN try4a.c $(LIB) -o try4a
	./try4a -r
	ln -f -s ${KLIPSSRCDIR}/rangetosubnet.c try6.c
	${CC} ${CFLAGS} -DRANGETOSUBNET_MAIN try6.c $(LIB) -o try6
	./try6 -r
	ln -f -s ${KLIPSSRCDIR}/addrtot.c try7.c
	${CC} ${CFLAGS} -DADDRTOT_MAIN try7.c $(LIB) -o try7
	./try7 -r

tar:	clean
	tar -cvf /tmp/lib.tar Makefile [a-z]*

check:
	echo no checks in lib right now.

MK_DEPEND_CFLAGS =  ${CFLAGS} ${PORTINCLUDE} ${ALLFLAGS}
MK_DEPEND_FILES = $(SRCS)
include $(top_srcdir)/mk/depend.mk
