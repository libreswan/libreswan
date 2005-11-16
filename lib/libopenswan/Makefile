# Openswan library
# Copyright (C) 1998-2001  Henry Spencer.
# Copyright (C) 2003, 2004 Xelerance Corporation
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
# RCSID $Id: Makefile,v 1.18 2005/01/25 20:06:40 mcr Exp $


OPENSWANSRCDIR?=$(shell cd ../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver


MANDIR=$(MANTREE)/man3

SRCS=addrtoa.c addrtot.c addrtypeof.c alg_info.c anyaddr.c atoaddr.c \
	atoasr.c atosubnet.c atoul.c constants.c copyright.c datatot.c \
	alloc.c diag.c \
	goodmask.c initaddr.c initsaid.c initsubnet.c keyblobtoid.c \
	kernel_alg.c \
	optionsfrom.c \
	pfkey_v2_build.c pfkey_v2_ext_bits.c pfkey_v2_parse.c \
	pfkey_v2_debug.c prng.c \
	packet.c \
	portof.c rangetoa.c rangetosubnet.c sameaddr.c \
	satot.c subnetof.c subnettoa.c subnettot.c \
	subnettypeof.c ttoaddr.c ttodata.c ttoprotoport.c \
	ttosa.c ttosubnet.c ttoul.c ultoa.c ultot.c \
	udpfromto.c

SRCS+=sanitizestring.c pfkey_print.c

LOGSRCS=oswlog.c 


OBJS=${SRCS:.c=.o} version.o
LOGOBJS=${LOGSRCS:.c=.o}

KLIPSD=${OPENSWANSRCDIR}/linux/include
KLIPSSRCDIR=${OPENSWANSRCDIR}/linux/net/ipsec
MANSRCDIR=${OPENSWANSRCDIR}/lib/libopenswan

VPATH+= ${KLIPSSRCDIR}

HDRS=${KLIPSD}/openswan.h internal.h

LIBA=libopenswan.a
LIBL=liboswlog.a
# Original flags
CFLAGS=-I. -I${KLIPSSRCDIR} -I${KLIPSD} -I${OPENSWANSRCDIR} -DDEBUG
CFLAGS+=-DWITH_UDPFROMTO -DHAVE_IP_PKTINFO
CFLAGS+= -I${OPENSWANSRCDIR}/include $(USERCOMPILE)
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
CFLAGS+= -DX509_VERSION=\"${X509_VERSION}\"

ifeq ($(USE_NAT_TRAVERSAL),true)
CFLAGS+= -DNAT_TRAVERSAL
endif


ARFLAGS=crvs
EXTHDRS=des.h
EXTLIBS=libdes.a
MANS=anyaddr.3 atoaddr.3 atoasr.3 atoul.3 goodmask.3 \
	initaddr.3 initsubnet.3 optionsfrom.3 portof.3 rangetosubnet.3 \
	sameaddr.3 subnetof.3 ttoaddr.3 ttodata.3 ttosa.3 ttoul.3 version.3

.PHONY:	all install clean l t lt tar check depend checkprograms

all:	$(LIBA) ${LIBL}
programs: $(LIBA) ${LIBL}

install:
	@mkdir -p $(MANDIR)
	@for f in $(MANS) ; \
	do \
		$(INSTALL) $(INSTMANFLAGS) $(MANSRCDIR)/$$f $(MANDIR)/ipsec_$$f || exit 1 ; \
	done
	@$(OPENSWANSRCDIR)/packaging/utils/manlink $(foreach man, $(MANS), ${MANSRCDIR}/$(man)) | \
	while read from to; \
	do \
		ln -s -f ipsec_$$from $(MANDIR)/$$to; \
	done


install_file_list:
	@for f in $(MANS) ; \
	do \
		echo $(MANDIR)/ipsec_$$f;\
	done;
	@$(OPENSWANSRCDIR)/packaging/utils/manlink $(foreach man, $(MANS), ${MANSRCDIR}/$(man)) | \
	while read from to; \
	do \
		echo $(MANDIR)/$$to; \
	done

$(LIBA): $(OBJS)
	$(AR) $(ARFLAGS) $(LIBA) $(OBJS)

$(LIBL): $(LOGOBJS)
	$(AR) $(ARFLAGS) $(LIBL) $(LOGOBJS)

$(OBJS):	$(HDRS)

$(LOGOBJS):	$(HDRS)

# build version.c using version number from Makefile.ver
version.c:	version.in.c ${OPENSWANSRCDIR}/Makefile.ver
	sed '/"/s/xxx/$(IPSECVERSION)/' ${KLIPSSRCDIR}/version.in.c >$@

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

clean:
	rm -f $(LIB) *.o try* core *.core $(EXTHDRS) $(EXTLIBS) version.c


# developer-only stuff
l:
	$(MAKE) $(LIB) ARFLAGS=crv CFLAGS=-O
	$(RANLIB) $(LIB)

t:	$(LIB) 
	ln -f -s ${KLIPSSRCDIR}/atosubnet.c try.c
	${CC} ${CFLAGS} -DATOSUBNET_MAIN try.c $(LIB) -o try
	./try -r
	ln -f -s ${KLIPSSRCDIR}/ttosubnet.c try1a.c
	${CC} ${CFLAGS} -DTTOSUBNET_MAIN try1a.c $(LIB) -o try1a
	./try1a -r
	ln -f -s ${KLIPSSRCDIR}/ttodata.c try2.c
	${CC} ${CFLAGS} -DTTODATA_MAIN try2.c $(LIB) -o try2
	./try2 -r
	ln -f -s ${KLIPSSRCDIR}/atoasr.c try3.c
	${CC} ${CFLAGS} -DATOASR_MAIN try3.c $(LIB) -o try3
	./try3 -r
	ln -f -s ${KLIPSSRCDIR}/ttosa.c try4a.c
	${CC} ${CFLAGS} -DTTOSA_MAIN try4a.c $(LIB) -o try4a
	./try4a -r
	ln -f -s ${KLIPSSRCDIR}/rangetosubnet.c try6.c
	${CC} ${CFLAGS} -DRANGETOSUBNET_MAIN try6.c $(LIB) -o try6
	./try6 -r
	ln -f -s ${KLIPSSRCDIR}/addrtot.c try7.c
	${CC} ${CFLAGS} -DADDRTOT_MAIN try7.c $(LIB) -o try7
	./try7 -r

lt:	$(LIB)
	$(MAKE) t
	cp optionsfrom.c try5.c
	cc -DTEST try5.c $(LIB) -o try5
	echo --foo --bar >try5in1
	echo --optionsfrom >>try5in1
	echo try5in2 >>try5in1
	echo --foo >try5in2
	./try5 --foo --bar --optionsfrom try5in1 --bar something

tar:	clean
	tar -cvf /tmp/lib.tar Makefile [a-z]*

check:
	echo no checks in lib right now.

depend:
	makedepend -Y -- $(CFLAGS) -- $(SRCS)

checkprograms:

# DO NOT DELETE

alg_info.o: ../../linux/include/openswan.h
alg_info.o: ../../linux/include/openswan/ipsec_param.h
alg_info.o: ../../linux/include/openswan/ipsec_policy.h
alg_info.o: ../../linux/include/openswan/passert.h
alg_info.o: ../../linux/include/pfkeyv2.h ../../include/constants.h
alg_info.o: ../../include/ietf_constants.h ../../include/pluto_constants.h
alg_info.o: ../../include/alg_info.h ../../include/oswlog.h
alg_info.o: ../../include/oswalloc.h
atoaddr.o: internal.h ../../linux/include/openswan.h
atoaddr.o: ../../linux/include/openswan/ipsec_param.h
atoasr.o: internal.h ../../linux/include/openswan.h
atoasr.o: ../../linux/include/openswan/ipsec_param.h
atosubnet.o: internal.h ../../linux/include/openswan.h
atosubnet.o: ../../linux/include/openswan/ipsec_param.h
atoul.o: internal.h ../../linux/include/openswan.h
atoul.o: ../../linux/include/openswan/ipsec_param.h
constants.o: ../../linux/include/openswan.h
constants.o: ../../linux/include/openswan/ipsec_param.h
constants.o: ../../linux/include/openswan/ipsec_policy.h
constants.o: ../../linux/include/openswan/passert.h ../../include/constants.h
constants.o: ../../include/ietf_constants.h ../../include/pluto_constants.h
constants.o: ../../include/enum_names.h
copyright.o: internal.h ../../linux/include/openswan.h
copyright.o: ../../linux/include/openswan/ipsec_param.h
alloc.o: ../../linux/include/openswan.h
alloc.o: ../../linux/include/openswan/ipsec_param.h ../../include/constants.h
alloc.o: ../../include/ietf_constants.h ../../include/pluto_constants.h
alloc.o: ../../include/oswalloc.h
diag.o: ../../linux/include/openswan.h
diag.o: ../../linux/include/openswan/ipsec_param.h ../../include/constants.h
diag.o: ../../include/ietf_constants.h ../../include/pluto_constants.h
diag.o: ../../include/oswlog.h ../../linux/include/openswan/passert.h
initsaid.o: internal.h ../../linux/include/openswan.h
initsaid.o: ../../linux/include/openswan/ipsec_param.h
initsubnet.o: internal.h ../../linux/include/openswan.h
initsubnet.o: ../../linux/include/openswan/ipsec_param.h
keyblobtoid.o: internal.h ../../linux/include/openswan.h
keyblobtoid.o: ../../linux/include/openswan/ipsec_param.h
kernel_alg.o: ../../linux/include/pfkeyv2.h ../../linux/include/pfkey.h
kernel_alg.o: ../../linux/include/openswan.h
kernel_alg.o: ../../linux/include/openswan/ipsec_param.h
kernel_alg.o: ../../linux/include/openswan/ipsec_policy.h
kernel_alg.o: ../../include/constants.h ../../include/ietf_constants.h
kernel_alg.o: ../../include/pluto_constants.h ../../include/alg_info.h
kernel_alg.o: ../../include/kernel_alg.h ../../include/oswlog.h
kernel_alg.o: ../../linux/include/openswan/passert.h ../../include/oswalloc.h
optionsfrom.o: internal.h ../../linux/include/openswan.h
optionsfrom.o: ../../linux/include/openswan/ipsec_param.h
packet.o: ../../linux/include/openswan.h
packet.o: ../../linux/include/openswan/ipsec_param.h
packet.o: ../../include/constants.h ../../include/ietf_constants.h
packet.o: ../../include/pluto_constants.h ../../include/oswlog.h
packet.o: ../../linux/include/openswan/passert.h ../../include/packet.h
portof.o: internal.h ../../linux/include/openswan.h
portof.o: ../../linux/include/openswan/ipsec_param.h
rangetosubnet.o: internal.h ../../linux/include/openswan.h
rangetosubnet.o: ../../linux/include/openswan/ipsec_param.h
sameaddr.o: internal.h ../../linux/include/openswan.h
sameaddr.o: ../../linux/include/openswan/ipsec_param.h
subnettot.o: internal.h ../../linux/include/openswan.h
subnettot.o: ../../linux/include/openswan/ipsec_param.h
subnettypeof.o: internal.h ../../linux/include/openswan.h
subnettypeof.o: ../../linux/include/openswan/ipsec_param.h
ttoaddr.o: internal.h ../../linux/include/openswan.h
ttoaddr.o: ../../linux/include/openswan/ipsec_param.h
ttodata.o: internal.h ../../linux/include/openswan.h
ttodata.o: ../../linux/include/openswan/ipsec_param.h
ttoprotoport.o: internal.h ../../linux/include/openswan.h
ttoprotoport.o: ../../linux/include/openswan/ipsec_param.h
ttosa.o: internal.h ../../linux/include/openswan.h
ttosa.o: ../../linux/include/openswan/ipsec_param.h
ttosubnet.o: internal.h ../../linux/include/openswan.h
ttosubnet.o: ../../linux/include/openswan/ipsec_param.h
ttoul.o: internal.h ../../linux/include/openswan.h
ttoul.o: ../../linux/include/openswan/ipsec_param.h
sanitizestring.o: ../../linux/include/openswan.h
sanitizestring.o: ../../linux/include/openswan/ipsec_param.h
sanitizestring.o: ../../linux/include/openswan/passert.h
pfkey_print.o: ../../linux/include/openswan.h
pfkey_print.o: ../../linux/include/openswan/ipsec_param.h
pfkey_print.o: ../../linux/include/pfkeyv2.h ../../linux/include/pfkey.h
