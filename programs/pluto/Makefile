# Pluto Makefile
# Copyright (C) 1997 Angelos D. Keromytis.
# Copyright (C) 1998-2001  D. Hugh Redelmeier
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
# RCSID $Id: Makefile,v 1.205 2005/10/02 21:42:03 mcr Exp $

# All of the USE_ and HAVE_ variables are controlled from openswan/Makefile.inc


# relative path to top directory of Openswan source
# Note: referenced in ${OPENSWANSRCDIR}/Makefile.inc
OPENSWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${srcdir}Makefile.options

FMANDIR=$(MANTREE)/man5
PMANDIR=$(MANTREE)/man8

BINNAMEPLUTO = pluto
BINNAMEWHACK = whack
BINNAMEWHACKINIT = whackinit
BINNAMEADNS = _pluto_adns

OSDEP?=$(shell uname -s | tr 'A-Z' 'a-z')
SYSDEP_SRC=sysdep_${OSDEP}.c
SYSDEP_OBJ=sysdep_${OSDEP}.o

BUILDER=${shell echo ${USER}@`hostname` }
# End of configuration coping options.

CPPFLAGS = $(HDRDIRS) $(DEFINES) \
	-DSHARED_SECRETS_FILE=\"${FINALCONFDIR}/ipsec.secrets\" \
	-DPOLICYGROUPSDIR=\"${FINALCONFDDIR}/policies\" \
	-DPERPEERLOGDIR=\"${FINALLOGDIR}/pluto/peer\"

ALLFLAGS = $(CPPFLAGS) $(CFLAGS)

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

LIBSADNS = $(OPENSWANLIB)
LIBSADNS += -lresolv # -lefence

# Solaris needs -lsocket -lnsl
LIBSWHACK = ${WHACKLIB} ${OPENSWANLIB} 


RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

# files for a (source) distribution

DISTMISC = CHANGES PLUTO-CONVENTIONS TODO ipsec.secrets Makefile routing.txt \
	 pluto.8 ipsec.secrets.5 .cvsignore

DISTGCRYPT = \
	gcryptfix.c gcryptfix.h \
	dsa.c dsa.h \
	elgamal.c elgamal.h \
	primegen.c \
	smallprime.c

DISTSRC = \
	connections.c connections.h \
	pending.c pending.h \
	foodgroups.c foodgroups.h \
	cookie.c cookie.h \
	pluto_constants.c \
	crypto.h crypto.c \
	db_ops.c \
	defs.h defs.c \
	demux.c demux.h \
	dnskey.c dnskey.h \
	dpd.c dpd.h \
	myid.c \
	ipsec_doi.c ipsec_doi.h ikev1_quick.c ikev1_continuations.h \
	kernel.c kernel.h \
	${NETKEY_SRCS} \
	${KLIPS_SRCS} ${MAST_SRCS} ${WIN2K_SRCS} ${FUNK_SRCS} ${BSDKAME_SRCS} \
	kernel_noklips.c kernel_noklips.h \
	ike_alg.c ike_alg.h ikeping.c \
	ike_alg_aes.c ike_alginit.c \
	rcv_whack.c rcv_whack.h \
	$(IPSECPOLICY_DIST_SRCS) \
	${EXTRA_CRYPTO_SRCS} \
	log.c log.h \
	plutomain.c plutoalg.c \
	ocsp.c ocsp.h \
	pluto_crypt.c crypt_utils.c pluto_crypt.h crypt_ke.c crypt_dh.c \
	keys.c keys.h \
	rnd.c rnd.h \
	server.c server.h \
	${SMARTCARD_DIST_SRCS} \
	spdb.c spdb_struct.c spdb_print.c spdb.h \
	state.c state.h \
	stubs.c \
	${SYSDEP_SRC} \
	timer.c timer.h \
	$(DISTGCRYPT) \
	$(X509_DIST_SRCS) \
	$(HAVE_THREADS_DIST_SRCS) \
	vendor.c nat_traversal.c virtual.c \
	adns.c adns.h \
	whack.c whackinit.c \
	${XAUTH_DIST_SRCS} \
	${AGGRESSIVE_DIST_SRCS} \
	${HAVE_OCF_DIST_SRCS}

DIST = $(DISTMISC) $(DISTSRC)


# start of support for DSS/DSA.  Not currently used.
# OBJSGCRYPT =  gcryptfix.o dsa.o elgamal.o primegen.o smallprime.o
OBJSGCRYPT =

OBJSPLUTO  = connections.o pending.o cookie.o crypto.o defs.o dpd.o
OBJSPLUTO += foodgroups.o log.o state.o plutomain.o plutoalg.o server.o
OBJSPLUTO += timer.o pluto_constants.o
OBJSPLUTO += myid.o ipsec_doi.o ikev1_quick.o ikeping.o kernel.o 
OBJSPLUTO += $(NETKEY_OBJS) ${KLIPS_OBJS} ${MAST_OBJS} ${WIN2K_OBJS} ${FUNK_OBJS}
OBJSPLUTO += $(BSDKAME_OBJS) 
OBJSPLUTO += kernel_noklips.o rcv_whack.o 
OBJSPLUTO += ${IPSECPOLICY_OBJS} demux.o keys.o dnskey.o
OBJSPLUTO += pluto_crypt.o crypt_utils.o crypt_ke.o crypt_dh.o
OBJSPLUTO += rnd.o spdb.o spdb_struct.o spdb_print.o 
OBJSPLUTO += vendor.o nat_traversal.o virtual.o 
OBJSPLUTO += ike_alg_aes.o ike_alginit.o
OBJSPLUTO += ${EXTRA_CRYPTO_OBJS}
OBJSPLUTO += ike_alg.o db_ops.o 
OBJSPLUTO += ${XAUTH_OBJS}
OBJSPLUTO += ${AGGRESSIVE_OBJS}
OBJSPLUTO += ${SMARTCARD_OBJS} ${X509_OBJS} ${HAVE_THREADS_OBJS}
OBJSPLUTO += ${OBJSLIBPLUTO}
OBJSPLUTO += ${HAVE_OCF_OBJS}
OBJSPLUTO += ${SYSDEP_OBJ} stubs.o

OBJSADNS = adns.o

OBJSWHACK = whack.o
OBJSWHACKINIT = whackinit.o

# we can't do tests with two conditions, but we can concatenate the strings
SHOULDWERESTART=${USE_OBJDIR}$(wildcard plutomain.c)
ifeq ($(SHOULDWERESTART),trueplutomain.c)
all programs clean install:
	cd ${OPENSWANSRCDIR} && cd ${OBJDIRTOP}/programs/pluto && $(MAKE) $@
else
all: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK) #$(BINNAMEWHACKINIT) 
programs: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK) #$(BINNAMEWHACKINIT)
clean:	cleanall
install: doinstall

endif

doinstall: all
	mkdir -p ${LIBEXECDIR} ${LIBDIR}
	mkdir -p -m 755 $(CONFDIR)/ipsec.d
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/cacerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/aacerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/ocspcerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/certs
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/crls
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/private
	mkdir -p -m 700 $(VARDIR)/run/pluto
	$(INSTALL) $(INSTBINFLAGS) $(BINNAMEPLUTO) $(BINNAMEWHACK) $(LIBEXECDIR)
	#$(INSTALL) $(INSTSUIDFLAGS) $(BINNAMEWHACKINIT) $(LIBEXECDIR)
	if $(USE_ADNS) ; then $(INSTALL) $(INSTBINFLAGS) $(BINNAMEADNS)  $(LIBEXECDIR) ; fi
	$(INSTALL) $(INSTMANFLAGS) ${srcdir}pluto.8 $(PMANDIR)/ipsec_pluto.8
	sh ${OPENSWANSRCDIR}/packaging/utils/manlink ${srcdir}pluto.8 | \
		while read from to ; \
		do \
			ln -s -f ipsec_$$from $(PMANDIR)/$$to; \
		done
	$(INSTALL) $(INSTMANFLAGS) ${srcdir}ipsec.secrets.5 $(FMANDIR)
	sh ${OPENSWANSRCDIR}/packaging/utils/manlink ${srcdir}ipsec.secrets.5 | \
		while read from to ; \
		do \
		 ln -s -f $$from $(FMANDIR)/$$to; \
		done

install_file_list:
	@echo $(LIBEXECDIR)/$(BINNAMEPLUTO)
	@if $(USE_ADNS) ; then echo $(LIBDIR)/$(BINNAMEADNS) ; fi
	@echo $(LIBEXECDIR)/$(BINNAMEWHACK)
	@echo $(PMANDIR)/ipsec_pluto.8
	@sh ${OPENSWANSRCDIR}/packaging/utils/manlink pluto.8 | \
		while read from to; \
		do\
			 echo $(PMANDIR)/$$to; \
		done
	@echo $(FMANDIR)/ipsec.secrets.5
	@sh ${OPENSWANSRCDIR}/packaging/utils/manlink ipsec.secrets.5 | \
		while read from to; \
		do \
			echo $(FMANDIR)/$$to; \
		done

alg_info_test: alg_info_test.o ike_alg.o constants.o defs.o log.o db_ops.o crypto.o $(LIBDESLITE) $(OPENSWANLIB)
	$(CC) -o $@ $^ $(LIBSPLUTO)

${LIBTPM}: $(wildcard ${srcdir}tpm/*.c) $(wildcard ${srcdir}tpm/*.h) $(wildcard ${srcdir}tpm/*.i)
	@(cd tpm && ${MAKE} srcdir=${srcdir}tpm/ libtpm.a )

$(BINNAMEPLUTO): $(OBJSPLUTO) $(ALG_LIBS) $(OPENSWANLIB) ${LIBTPM} ${LIBSPLUTO}
	$(CC) -o $(BINNAMEPLUTO) $(LDFLAGS) $(USERLINK) $(OBJSPLUTO) $(LIBSPLUTO) ${PLUTOMINUSL}

$(BINNAMEADNS): $(OBJSADNS) ${LIBSPLUTO}
	$(CC) -o $(BINNAMEADNS) $(OBJSADNS) $(USERLINK) $(LIBSADNS) ${ADNSMINUSL}

$(BINNAMEWHACK): $(OBJSWHACK) ${LIBSPLUTO}
	$(CC) -o $(BINNAMEWHACK) $(OBJSWHACK) $(USERLINK) $(LIBSWHACK) ${WHACKMINUSL}

$(BINNAMEWHACKINIT): $(OBJSWHACKINIT) ${LIBSPLUTO}
	$(CC) -o $(BINNAMEWHACKINIT) $(OBJSWHACKINIT) $(USERLINK) $(LIBSWHACK)

distlist:
	@echo $(DIST)

cleanall: 
	$(RM) $(RMFLAGS) *.core core *~ a.out ktrace.out \
		$(OBJSPLUTO) $(BINNAMEPLUTO) \
		$(OBJSWHACK) $(BINNAMEWHACK) \
		$(OBJSADNS) $(BINNAMEADNS)

distclean: clean

mostlyclean: clean

realclean: clean

check:
	echo no checks in lib right now.

checkprograms:

.c.o:
	$(CC) $(USERCOMPILE) ${PORTINCLUDE} $(COPTS) $(ALLFLAGS) -c $<

%.i: %.c
	$(CC) $(USERCOMPILE) ${PORTINCLUDE} $(COPTS) $(ALLFLAGS) -E -o $@ $<


# Gather dependencies caused by explicit #includes within .c files
depend:
	@(ls $(DISTSRC) | grep '\.c' | xargs gcc -MM ${COPTS} ${PORTINCLUDE} ${ALLFLAGS} ) | sed -e 's,${OPENSWANSRCDIR},../..,g' >Makefile.depend

-include ${srcdir}Makefile.depend

# DO NOT DELETE

