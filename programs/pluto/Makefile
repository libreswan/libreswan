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

# All of the USE_ and HAVE_ variables are controlled from libreswan/Makefile.inc


# relative path to top directory of Libreswan source
# Note: referenced in ${LIBRESWANSRCDIR}/Makefile.inc
LIBRESWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${srcdir}Makefile.options
-include ${srcdir}Makefile.extra
include ${srcdir}../Makefile.manpages

FMANDIR=$(MANTREE)/man5
PMANDIR=$(MANTREE)/man8
MANPAGES=pluto.8 ipsec.secrets.5

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
	-DIPSEC_SBINDIR=\"${FINALSBINDIR}\" \
	-DIPSEC_LIBDIR=\"${FINALLIBDIR}\" \
	-DIPSEC_EXECDIR=\"${FINALLIBEXECDIR}\" \
	-DPOLICYGROUPSDIR=\"${FINALCONFDDIR}/policies\" \
	-DFIPSPRODUCTCHECK=\"${FIPSPRODUCTCHECK}\" \

ifeq ($(HAVE_BROKEN_POPEN),true)
CFLAGS+=-DHAVE_BROKEN_POPEN
endif

ifeq ($(HAVE_NO_FORK),true)
CFLAGS+=-DHAVE_NO_FORK
endif

# Enable ALLOW_MICROSOFT_BAD_PROPOSAL
CFLAGS+=-DALLOW_MICROSOFT_BAD_PROPOSAL

ALLFLAGS = $(CPPFLAGS) $(CFLAGS) ${CROSSFLAGS} ${NSSFLAGS}

LDFLAGS+=${NSSLIBS}

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

LIBSADNS = $(LIBRESWANLIB)
LIBSADNS += -lresolv # -lefence

LIBSPLUTO += $(IPSECCONFLIB) $(LIBRESWANLIB)
ifeq ($(USE_DNSSEC),true)
LIBSPLUTO += -lunbound
endif

ifeq ($(USE_LINUX_AUDIT),true)
LIBSPLUTO += -laudit
endif

# Solaris needs -lsocket -lnsl
LIBSWHACK = ${WHACKLIB} ${LIBRESWANLIB}


RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

# files for a (source) distribution

DISTMISC = CHANGES PLUTO-CONVENTIONS TODO ipsec.secrets Makefile routing.txt \
	 pluto.8 ipsec.secrets.5 .cvsignore

DISTSRC = \
        connections.c initiate.c terminate.c connections.h \
	pending.c pending.h \
	foodgroups.c foodgroups.h \
	cookie.c cookie.h \
	crypto.h crypto.c \
	db_ops.c \
	defs.h defs.c \
	demux.c demux.h msgdigest.c \
	dnskey.c dnskey.h \
	dpd.c dpd.h \
	myid.c hmac.c \
	hostpair.c \
	ipsec_doi.c ipsec_doi.h ikev1.c ikev1_quick.c ikev1_continuations.h \
        ikev2.c ikev2_parent.c ikev2_child.c ikev2_crypto.c \
	ikev2_prfplus.c spdb_v2_struct.c \
	kernel.c kernel.h \
	${NETKEY_SRCS} \
	${KLIPS_SRCS} ${MAST_SRCS} ${WIN2K_SRCS} \
	kernel_noklips.c kernel_noklips.h \
	ike_alg.c ike_alg_status.c ike_alg.h \
	ike_alg_aes.c ikev2_rsa.c ikev2_psk.c ikev2_x509.c \
	rcv_whack.c rcv_whack.h \
	${EXTRA_CRYPTO_SRCS} ike_alg_sha2.c \
	log.c log.h \
	plutomain.c plutoalg.c \
	pluto_crypt.c crypt_utils.c pluto_crypt.h \
	crypt_ke.c crypt_dh.c crypt_start_dh.c \
	keys.c keys.h \
	rnd.c rnd.h \
	server.c server.h \
	spdb.c spdb_struct.c spdb_v1_struct.c spdb_print.c spdb.h \
	state.c state.h \
	${SYSDEP_SRC} \
	timer.c timer.h \
	$(X509_DIST_SRCS) \
	$(THREADS_DIST_SRCS) \
	vendor.c nat_traversal.c virtual.c \
	adns.c adns.h \
	whack.c whackinit.c \
	${XAUTH_DIST_SRCS} \
	${AGGRESSIVE_DIST_SRCS} \
	${LABELED_IPSEC_DIST_SRCS} \
	packet.c pluto_constants.c readwhackmsg.c

DIST = $(DISTMISC) $(DISTSRC)

OBJSPLUTO  = connections.o initiate.o terminate.o
OBJSPLUTO += pending.o cookie.o crypto.o defs.o dpd.o
OBJSPLUTO += foodgroups.o log.o state.o plutomain.o plutoalg.o server.o
OBJSPLUTO += timer.o hmac.o hostpair.o
OBJSPLUTO += myid.o ipsec_doi.o
OBJSPLUTO += ikev1.o ikev1_main.o   ikev1_quick.o
OBJSPLUTO += ikev2.o ikev2_parent.o ikev2_child.o spdb_v2_struct.o
OBJSPLUTO += kernel.o
OBJSPLUTO += $(NETKEY_OBJS) $(BSDKAME_OBJS) ${KLIPS_OBJS} ${MAST_OBJS} ${WIN2K_OBJS} ${PFKEYv2_OBJS}
OBJSPLUTO += kernel_noklips.o rcv_whack.o
OBJSPLUTO += demux.o msgdigest.o keys.o dnskey.o
OBJSPLUTO += pluto_crypt.o crypt_utils.o crypt_ke.o crypt_dh.o crypt_start_dh.o
OBJSPLUTO += ikev2_crypto.o ikev2_prfplus.o
OBJSPLUTO += rnd.o spdb.o spdb_struct.o spdb_v1_struct.o spdb_print.o
OBJSPLUTO += vendor.o nat_traversal.o virtual.o
OBJSPLUTO += ike_alg_aes.o ikev2_rsa.o ikev2_psk.o ikev2_x509.o
OBJSPLUTO += ${EXTRA_CRYPTO_OBJS} ike_alg_sha2.o
OBJSPLUTO += ike_alg.o ike_alg_status.o db_ops.o
OBJSPLUTO += ${XAUTH_OBJS}
OBJSPLUTO += ${AGGRESSIVE_OBJS}
OBJSPLUTO += ${LABELED_IPSEC_OBJS}
OBJSPLUTO += ${X509_OBJS} ${THREADS_OBJS}
OBJSPLUTO += ${OBJSLIBPLUTO}
OBJSPLUTO += ${SYSDEP_OBJ}
OBJSPLUTO += packet.o pluto_constants.o readwhackmsg.o

OBJSADNS = adns.o

OBJSWHACK = whack.o
OBJSWHACKINIT = whackinit.o

# we can't do tests with two conditions, but we can concatenate the strings
SHOULDWERESTART=${USE_OBJDIR}$(wildcard plutomain.c)
ifeq ($(SHOULDWERESTART),trueplutomain.c)
all programs clean install:
	cd ${LIBRESWANSRCDIR} && cd ${OBJDIRTOP}/programs/pluto && $(MAKE) $@
else
all: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK) #$(BINNAMEWHACKINIT)
programs: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK) $(MANPAGES) #$(BINNAMEWHACKINIT) 
clean:	cleanall
install: doinstall
endif

doinstall: all
	mkdir -p ${LIBEXECDIR} ${LIBDIR}
	mkdir -p -m 700 $(CONFDIR)/ipsec.d
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/cacerts
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/aacerts
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/certs
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/crls
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/private
	mkdir -p -m 755 $(VARDIR)/run/pluto
	$(INSTALL) $(INSTBINFLAGS) $(BINNAMEPLUTO) $(BINNAMEWHACK) $(LIBEXECDIR)
	#
	#$(INSTALL) $(INSTSUIDFLAGS) $(BINNAMEWHACKINIT) $(LIBEXECDIR)
	if $(USE_ADNS) ; then $(INSTALL) $(INSTBINFLAGS) $(BINNAMEADNS)  $(LIBEXECDIR) ; fi
	g=`if [ -r pluto.8 ]; then echo pluto.8; else echo ${srcdir}/pluto.8; fi`; \
	$(INSTALL) $(INSTMANFLAGS) $$g $(PMANDIR)/ipsec_pluto.8 || exit 1; \
	sh ${LIBRESWANSRCDIR}/packaging/utils/manlink $$g | \
		while read from to ; \
		do \
			ln -s -f ipsec_$$from $(PMANDIR)/$$to; \
		done
	g=`if [ -r ipsec.secrets.5 ]; then echo ipsec.secrets.5; else echo ${srcdir}/ipsec.secrets.5; fi`; \
	$(INSTALL) $(INSTMANFLAGS) $$g $(FMANDIR)/ipsec.secrets.5 || exit 1; \
	sh ${LIBRESWANSRCDIR}/packaging/utils/manlink $$g | \
		while read from to ; \
		do \
		 ln -s -f $$from $(FMANDIR)/$$to; \
		done

install_file_list:
	@echo $(LIBEXECDIR)/$(BINNAMEPLUTO)
	@if $(USE_ADNS) ; then echo $(LIBDIR)/$(BINNAMEADNS) ; fi
	@echo $(LIBEXECDIR)/$(BINNAMEWHACK)
	@echo $(PMANDIR)/ipsec_pluto.8
	@sh ${LIBRESWANSRCDIR}/packaging/utils/manlink pluto.8 | \
		while read from to; \
		do\
			 echo $(PMANDIR)/$$to; \
		done
	@echo $(FMANDIR)/ipsec.secrets.5
	@sh ${LIBRESWANSRCDIR}/packaging/utils/manlink ipsec.secrets.5 | \
		while read from to; \
		do \
			echo $(FMANDIR)/$$to; \
		done

alg_info_test: alg_info_test.o ike_alg.o constants.o defs.o log.o db_ops.o crypto.o $(LIBDESLITE) $(LIBRESWANLIB)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBSPLUTO)

$(BINNAMEPLUTO): $(OBJSPLUTO) $(ALG_LIBS) $(LIBRESWANLIB)
	$(CC) -o $(BINNAMEPLUTO) $(LDFLAGS) $(USERLINK) $(OBJSPLUTO) $(LIBSPLUTO) ${PLUTOMINUSL} $(LIBDESLITE)

$(BINNAMEADNS): $(OBJSADNS)
	$(CC) -o $(BINNAMEADNS) $(LDFLAGS) $(OBJSADNS) $(USERLINK) $(LIBSADNS) ${ADNSMINUSL}

$(BINNAMEWHACK): $(OBJSWHACK)
	$(CC) -o $(BINNAMEWHACK) $(LDFLAGS) $(OBJSWHACK) $(USERLINK) $(LIBSWHACK) ${WHACKMINUSL}

$(BINNAMEWHACKINIT): $(OBJSWHACKINIT)
	$(CC) -o $(BINNAMEWHACKINIT) $(LDFLAGS) $(OBJSWHACKINIT) $(USERLINK) $(LIBSWHACK)

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
Makefile.depend: $(DISTSRC) $(LIBRESWANSRCDIR)/programs/pluto/Makefile
	@(ls $(wildcard $(addprefix $(LIBRESWANSRCDIR)/programs/pluto/,$(DISTSRC))) | grep '\.c' | xargs $(CC) -MM ${COPTS} ${PORTINCLUDE} ${ALLFLAGS} ) >Makefile.depend

-include ${srcdir}Makefile.depend

# DO NOT DELETE
