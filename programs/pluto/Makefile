# Pluto Makefile
#
# Copyright (C) 1997 Angelos D. Keromytis.
# Copyright (C) 1998-2001  D. Hugh Redelmeier
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

ifndef top_srcdir
include ../../mk/dirs.mk
endif

# XXX: Pluto doesn't include mk/program.mk?
include ${LIBRESWANSRCDIR}/Makefile.inc
include ${SRCDIR}Makefile.options
-include ${SRCDIR}Makefile.extra
include ${SRCDIR}../Makefile.manpages

FMANDIR=$(MANTREE)/man5
PMANDIR=$(MANTREE)/man8
MANPAGES=pluto.8 ipsec.secrets.5

BINNAMEPLUTO = pluto
BINNAMEWHACK = whack
BINNAMEWHACKINIT = whackinit
BINNAMEADNS = _pluto_adns
BINNAMEIMPORTCRL = _import_crl

OSDEP?=$(shell uname -s | tr 'A-Z' 'a-z')
SYSDEP_SRC=sysdep_${OSDEP}.c
SYSDEP_OBJ=sysdep_${OSDEP}.o

BUILDER=${shell echo ${USER}@`hostname` }
# End of configuration coping options.

LDFLAGS+=${NSSLIBS}

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

LIBSADNS = $(LIBRESWANLIB)
LIBSADNS += -lresolv # -lefence

LIBSPLUTO += $(IPSECCONFLIB) $(LIBRESWANLIB)   -lrt
ifeq ($(USE_DNSSEC),true)
LIBSPLUTO += -lunbound
endif

ifeq ($(USE_LINUX_AUDIT),true)
LIBSPLUTO += -laudit
endif

LIBSPLUTO += -levent
LIBSPLUTO += -levent_pthreads

ifeq ($(USE_KLIPS),true)
# Linux always supports udpfromto
UDPFROMTO_SRCS=udpfromto.c
endif
ifeq ($(USE_NETKEY),true)
# Linux always supports udpfromto
UDPFROMTO_SRCS=udpfromto.c
endif
ifeq ($(USE_BSDKAME),true)
# BSD always supports udpfromto
UDPFROMTO_SRCS=udpfromto.c
endif

# Solaris needs -lsocket -lnsl
LIBSWHACK = ${WHACKLIB} ${LIBRESWANLIB}


RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

# files for a (source) distribution

DISTMISC = CHANGES PLUTO-CONVENTIONS TODO ipsec.secrets Makefile routing.txt \
	 pluto.8 ipsec_whack.8 ipsec.secrets.5 .cvsignore

DISTSRC = \
	ike_alg_nss_cbc.h ike_alg_nss_cbc.c \
	cbc_test_vectors.h cbc_test_vectors.c \
	ctr_test_vectors.h ctr_test_vectors.c \
	gcm_test_vectors.h gcm_test_vectors.c \
	test_buffer.h test_buffer.c \
        connections.c initiate.c terminate.c connections.h \
	pending.c pending.h \
	foodgroups.c foodgroups.h \
	cookie.c cookie.h \
	crypto.h crypto.c \
	db_ops.c \
	defs.h defs.c \
	demux.c demux.h msgdigest.c \
	dnskey.c dnskey.h \
	myid.c hmac.c \
	hostpair.c ipsec_doi.c ipsec_doi.h \
	spdb.c spdb_struct.c spdb_print.c spdb.h \
	ikev1.c ikev1_quick.c ikev1_continuations.h \
	ikev1_dpd.c ikev1_dpd.h ikev1_spdb_struct.c \
	ikev1_msgid.c \
        ikev2.c ikev2_parent.c ikev2_child.c ikev2_crypto.c \
	crypt_symkey.c crypt_prf.c ikev1_prf.c ikev2_prf.c \
	ikev2_spdb_struct.c \
	ikev2_rsa.c ikev2_psk.c \
	kernel.c kernel.h \
	${NETKEY_SRCS} \
	${KLIPS_SRCS} ${MAST_SRCS} ${WIN2K_SRCS} \
	kernel_noklips.c kernel_noklips.h \
	ike_alg.c ike_alg_status.c ike_alg.h \
	ike_alg_aes.c \
	ike_alg_camellia.c \
	rcv_whack.c rcv_whack.h \
	${EXTRA_CRYPTO_SRCS} ike_alg_sha2.c \
	log.c log.h \
	plutomain.c plutoalg.c \
	pluto_crypt.c crypt_utils.c pluto_crypt.h \
	crypt_ke.c crypt_dh.c crypt_start_dh.c \
	keys.c keys.h \
	rnd.c rnd.h \
	server.c server.h \
	state.c state.h \
	state_entry.c state_entry.h \
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
	packet.c pluto_constants.c readwhackmsg.c \
	nss_cert_load.c nss_cert_load.h pem.c \
	nss_cert_vfy.c nss_cert_vfy.h \
	nss_ocsp.c nss_ocsp.h \
	nss_crl_import.c nss_crl_import.h \
	${UDPFROMTO_SRCS}

DIST = $(DISTMISC) $(DISTSRC)

OBJSPLUTO  = connections.o initiate.o terminate.o
OBJSPLUTO += ike_alg_nss_cbc.o
OBJSPLUTO += cbc_test_vectors.o
OBJSPLUTO += ctr_test_vectors.o
OBJSPLUTO += gcm_test_vectors.o
OBJSPLUTO += test_buffer.o
OBJSPLUTO += pending.o cookie.o crypto.o defs.o
OBJSPLUTO += foodgroups.o log.o state.o plutomain.o plutoalg.o server.o
OBJSPLUTO += state_entry.o
OBJSPLUTO += timer.o hmac.o hostpair.o
OBJSPLUTO += myid.o ipsec_doi.o
OBJSPLUTO += ikev1.o ikev1_main.o ikev1_quick.o ikev1_dpd.o ikev1_spdb_struct.o ikev1_msgid.o
OBJSPLUTO += ikev2.o ikev2_parent.o ikev2_child.o ikev2_spdb_struct.o 
OBJSPLUTO += ikev2_rsa.o ikev2_psk.o ikev2_crypto.o
OBJSPLUTO += crypt_symkey.o crypt_prf.o ikev1_prf.o ikev2_prf.o
OBJSPLUTO += kernel.o
OBJSPLUTO += $(NETKEY_OBJS) $(BSDKAME_OBJS) ${KLIPS_OBJS} ${MAST_OBJS} ${WIN2K_OBJS} ${PFKEYv2_OBJS}
OBJSPLUTO += kernel_noklips.o rcv_whack.o
OBJSPLUTO += demux.o msgdigest.o keys.o dnskey.o
OBJSPLUTO += pluto_crypt.o crypt_utils.o crypt_ke.o crypt_dh.o crypt_start_dh.o
OBJSPLUTO += rnd.o spdb.o spdb_struct.o spdb_print.o
OBJSPLUTO += vendor.o nat_traversal.o virtual.o
OBJSPLUTO += ike_alg_aes.o
OBJSPLUTO += ike_alg_camellia.o
OBJSPLUTO += ${EXTRA_CRYPTO_OBJS} ike_alg_sha2.o
OBJSPLUTO += ike_alg.o ike_alg_status.o db_ops.o
OBJSPLUTO += ${XAUTH_OBJS}
OBJSPLUTO += ${AGGRESSIVE_OBJS}
OBJSPLUTO += ${LABELED_IPSEC_OBJS}
OBJSPLUTO += ${X509_OBJS} ${THREADS_OBJS}
OBJSPLUTO += ${OBJSLIBPLUTO}
OBJSPLUTO += ${SYSDEP_OBJ}
OBJSPLUTO += packet.o pluto_constants.o readwhackmsg.o
OBJSPLUTO += nss_cert_load.o pem.o nss_cert_vfy.o
OBJSPLUTO += nss_ocsp.o nss_crl_import.o
OBJSPLUTO += ${UDPFROMTO_SRCS:.c=.o}

OBJSADNS = adns.o

OBJSWHACK = whack.o
OBJSWHACKINIT = whackinit.o

CAVP += cavp_ikev1_psk

SHOULDWERESTART=$(wildcard plutomain.c)
ifeq ($(SHOULDWERESTART),plutomain.c)
all programs clean install:
	cd ${LIBRESWANSRCDIR} && cd ${OBJDIRTOP}/programs/pluto && $(MAKE) $@
else
all: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK) $(CAVP) #$(BINNAMEWHACKINIT)
programs: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK) $(MANPAGES) $(CAVP) #$(BINNAMEWHACKINIT) 
clean:	cleanall
install: doinstall
endif

doinstall: all
	mkdir -p ${LIBEXECDIR}
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
	g=`if [ -r pluto.8 ]; then echo pluto.8; else echo ${SRCDIR}/pluto.8; fi`; \
	$(INSTALL) $(INSTMANFLAGS) $$g $(PMANDIR)/ipsec_pluto.8 || exit 1; \
	echo '.so man8/ipsec_pluto.8' > $(PMANDIR)/ipsec_whack.8 || exit 1; \
	sh ${LIBRESWANSRCDIR}/packaging/utils/manlink $$g | \
		while read from to ; \
		do \
			ln -s -f ipsec_$$from $(PMANDIR)/$$to; \
		done
	g=`if [ -r ipsec.secrets.5 ]; then echo ipsec.secrets.5; else echo ${SRCDIR}/ipsec.secrets.5; fi`; \
	$(INSTALL) $(INSTMANFLAGS) $$g $(FMANDIR)/ipsec.secrets.5 || exit 1; \
	sh ${LIBRESWANSRCDIR}/packaging/utils/manlink $$g | \
		while read from to ; \
		do \
		 ln -s -f $$from $(FMANDIR)/$$to; \
		done

install_file_list:
	@echo $(LIBEXECDIR)/$(BINNAMEPLUTO)
	@if $(USE_ADNS) ; then echo $(LIBEXECDIR)/$(BINNAMEADNS) ; fi
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

$(BINNAMEPLUTO): $(OBJSPLUTO) $(ALG_LIBS) $(LIBRESWANLIB)
	$(CC) -o $(BINNAMEPLUTO) $(LDFLAGS) $(USERLINK) $(OBJSPLUTO) $(LIBSPLUTO) ${PLUTOMINUSL}

$(BINNAMEADNS): $(OBJSADNS)
	$(CC) -o $(BINNAMEADNS) $(LDFLAGS) $(OBJSADNS) $(USERLINK) $(LIBSADNS) ${ADNSMINUSL}

$(BINNAMEWHACK): $(OBJSWHACK)
	$(CC) -o $(BINNAMEWHACK) $(LDFLAGS) $(OBJSWHACK) $(USERLINK) $(LIBSWHACK) ${WHACKMINUSL}

$(BINNAMEWHACKINIT): $(OBJSWHACKINIT)
	$(CC) -o $(BINNAMEWHACKINIT) $(LDFLAGS) $(OBJSWHACKINIT) $(USERLINK) $(LIBSWHACK)

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

# Cryptographic Algorithm Validation Program (CAVP)
# see: http://csrc.nist.gov/groups/STM/cavp/index.html
DISTSRC += cavp.c cavp_stubs.c cavp_ikev1_psk.c
OBJSCAVP = cavp.o cavp_stubs.o $(filter-out plutomain.o, $(OBJSPLUTO))
cavp_ikev1_psk: $(OBJSCAVP) cavp_ikev1_psk.o 
	$(CC) -o $@ $(OBJSCAVP) $@.o \
		$(LDFLAGS) $(USERLINK) $(LIBSPLUTO) ${PLUTOMINUSL}

%.i: %.c
	$(CC) $(MK_DEPEND_CFLAGS) -E -o $@ $<

MK_DEPEND_FILES = $(DISTSRC)
MK_DEPEND_CFLAGS = $(USERLAND_CFLAGS) ${PORTINCLUDE} $(COPTS) $(HDRDIRS) $(DEFINES) $(NSSFLAGS) $(CFLAGS) ${CROSSFLAGS}
include $(top_srcdir)/mk/depend.mk
