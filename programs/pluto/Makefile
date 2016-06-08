# Pluto Makefile
#
# Copyright (C) 1997 Angelos D. Keromytis.
# Copyright (C) 1998-2001 D. Hugh Redelmeier
# Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
# Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
# Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
# Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
# Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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

# XXX: Pluto doesn't include mk/program.mk and define PROGRAM
MANPAGES += ipsec_pluto.8

# XXX: Pluto doesn't include mk/program.mk?
include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/manpages.mk

ifeq ($(USE_LDAP),true)
# Everyone (should) be using LDAPv3, however LDAP_VERSION=2 is an option
# if you require LDAPv2
LDAP_VERSION=3
endif

# compile with PAM support will increase the size of the distribution
# and thus it may not be the best solution for embeded systems. XAUTH
# will use the crypt() lib and a password file by default.
ifeq ($(USE_XAUTHPAM),true)
XAUTH_HAVE_PAM=1
endif

# where to find klips headers and Libreswan headers
# and 2.6 kernel's <rtnetlink.h> and <xfrm.h>
HDRDIRS = -I${LIBRESWANSRCDIR}/programs/pluto/linux26 -I${LIBRESWANSRCDIR}/include -I$(LIBRESWANSRCDIR)/lib/libcrypto -I$(KLIPSINC)


# BYTE_ORDER = -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=BIG_ENDIAN
# BYTE_ORDER = -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN

# -DKLIPS enables interface to Kernel LINUX IPsec code
# -DNETKEY enables interface to Kernel NETKEY/XFRM IPsec code
# -DOLD_RESOLVER.  At some point, the resolver interface changed.
#    This macro enables Pluto support for the old interface.
#    It is automatically defined, based on the value of the <resolver.h>
#    macro __RES.  We don't know the correct threshold, so you may
#    find that you must manually define this.  If so, please inform
#    us so that we can refine the threshold.

# The following are best left undefined -- each can be overridden at runtime
# if need be.
# -DPORT=n sets the default UDP port for IKE messages (otherwise 500)
# -DSHARED_SECRETS_FILE=string overrides /etc/ipsec.secrets as the
#    default name of the file containing secrets used to authenticate other
#    IKE daemons.  In the Makefile, two levels of quoting are needed:
#    -DSHARED_SECRETS_FILE='"/etc/ipsec.secrets"'
# -DDEFAULT_CTLBASE=string overrides /var/run/pluto as default directory
#    and basename for pluto's lockfile (.pid) and control socket (.ctl).
#    Double quoting may be needed.

ifeq ($(USE_PFKEYv2),true)
PFKEYv2_DIST_SRC=kernel_pfkey.c kernel_pfkey.h
PFKEYv2_OBJS=kernel_pfkey.o
else
PFKEYv2_DIST_SRC=
PFKEYv2_OBJS=
endif

NETKEY_DIST_SRCS=kernel_netlink.c kernel_netlink.h
ifeq ($(USE_NETKEY),true)
NETKEY_DEFS=-DNETKEY_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES -DPFKEY
NETKEY_SRCS=${NETKEY_DIST_SRCS} ${PFKEYv2_DIST_SRC}
NETKEY_OBJS=kernel_netlink.o
endif

KLIPS_DIST_SRCS=kernel_klips.c
ifeq ($(USE_KLIPS),true)
KLIPS_SRCS=${KLIPS_DIST_SRCS}
KLIPS_DEFS=-DKLIPS -DPFKEY
KLIPS_OBJS=kernel_klips.o
endif

MAST_DIST_SRCS=kernel_mast.c
ifeq ($(USE_MAST),true)
MAST_SRCS=${MAST_DIST_SRCS}
MAST_DEFS=-DKLIPS_MAST
MAST_OBJS=kernel_mast.o
endif

WIN2K_DIST_SRCS=kernel_win2k.c
ifeq ($(USE_WIN2K_NATIVE),true)
WIN2K_SRCS=${WIN2K_DIST_SRCS}
WIN2K_DEFS=-DWIN2K_NATIVE_IPSEC
WIN2K_OBJS=kernel_win2k.o
endif

BSDKAME_DIST_SRCS=kernel_bsdkame.c
ifeq ($(USE_BSDKAME),true)
BSDKAME_SRCS=${BSDKAME_DIST_SRCS}
BSDKAME_DEFS=-DBSD_KAME
BSDKAME_OBJS=kernel_bsdkame.o
BSDKAME_LIBS=${LIBBSDPFKEY}
endif


# the files are defined here so that TAGS: can catch them.
#
X509_DIST_OBJS=x509.o
X509_DIST_SRCS=${X509_DIST_OBJS:.o=.c}
X509_DIST_SRCS+=fetch.h
THREADS_DIST_OBJS=fetch.o
THREADS_DIST_SRCS=${THREADS_DIST_OBJS:.o=.c}
X509_OBJS=${X509_DIST_OBJS}
X509_SRCS=${X509_DIST_SRCS}

# dynamic LDAP CRL fetching requires OpenLDAP library
ifeq ($(USE_LDAP),true)
X509_LLIBS+= -lldap -llber
PLUTOMINUSL+= -llber
ifdef LDAP_VERSION
X509_DEFS+= -DLDAP_VER=$(LDAP_VERSION)
endif
endif

THREADS_OBJS=${THREADS_DIST_OBJS}
THREADS_SRCS=${THREADS_DIST_SRCS}
THREADS_LLIBS=-lpthread

ifeq ($(USE_IPSEC_CONNECTION_LIMIT),true)
IPSEC_CONNECTION_LIMIT_DEFS=-DIPSEC_CONNECTION_LIMIT=$(IPSEC_CONNECTION_LIMIT)
endif

XAUTH_DIST_SRCS=ikev1_xauth.c ikev1_xauth.h addresspool.c addresspool.h pam_conv.c pam_conv.h
XAUTH_DIST_OBJS=ikev1_xauth.o addresspool.o pam_conv.o
XAUTH_OBJS=${XAUTH_DIST_OBJS}
XAUTH_SRCS=${XAUTH_DIST_SRCS}
ifneq ($(BUILDENV), darwin)
XAUTH_LLIBS=-lcrypt
endif
# if we use pam for password checking then add it too
ifeq ($(USE_XAUTHPAM),true)
XAUTHPAM_DEFS=-DXAUTH_HAVE_PAM
XAUTHPAM_LIBS=-lpam
endif

AGGRESSIVE_DIST_OBJS=ikev1_aggr.o
AGGRESSIVE_DIST_SRCS=${AGGRESSIVE_DIST_OBJS:.o=.c}
AGGRESSIVE_OBJS=${AGGRESSIVE_DIST_OBJS}
AGGRESSIVE_SRCS=${AGGRESSIVE_DIST_SRCS}

# LABELED IPSEC support - requires SElinux
LABELED_IPSEC_DIST_OBJS=security_selinux.o
LABELED_IPSEC_DIST_SRCS=${LABELED_IPSEC_DIST_OBJS:.o=.c}
ifeq ($(USE_LABELED_IPSEC),true)
LABELED_IPSEC_DEFS=-DHAVE_LABELED_IPSEC
LABELED_IPSEC_OBJS=${LABELED_IPSEC_DIST_OBJS}
LABELED_IPSEC_SRCS=${LABELED_IPSEC_DIST_SRCS}
LABELED_IPSEC_LIBS=-lselinux
endif

SYSTEMD_NOTIFY_DIST_OBJS=pluto_sd.o
SYSTEMD_NOTIFY_DIST_SRCS=${SYSTEMD_NOTIFY_DIST_OBJS:.o=.c}
ifeq ($(USE_SYSTEMD_WATCHDOG),true)
SYSTEMD_NOTIFY_DEFS=-DUSE_SYSTEMD_WATCHDOG
SYSTEMD_NOTIFY_OBJS=${SYSTEMD_NOTIFY_DIST_OBJS}
SYSTEMD_NOTIFY_SRC=${SYSTEMD_NOTIFY_DIST_SRC}
SYSTEMD_NOTIFY_LIBS=-lsystemd
endif


ifeq ($(USE_LIBCURL),true)
# This compile option activates dynamic URL fetching
# with libcurl in the source code
CURL_DEFS=-DLIBCURL
CURL_LLIBS=-lcurl
endif

ifeq ($(USE_EXTRACRYPTO),true)
EXTRA_CRYPTO_DEFS=-DUSE_TWOFISH -DUSE_SERPENT
EXTRA_CRYPTO_SRCS=ike_alg_twofish.c ike_alg_serpent.c
EXTRA_CRYPTO_OBJS=ike_alg_twofish.o ike_alg_serpent.o
EXTRA_CRYPTO_LIBS=$(LIBTWOFISH) $(LIBSERPENT)
endif

ifeq ($(USE_SINGLE_CONF_DIR),true)
SINGLE_CONF_DIR=-DSINGLE_CONF_DIR
endif

DEFINES = $(EXTRA_DEFINES) \
	${VENDORID} \
	$(KEYRR_DEFINES) \
	$(BYTE_ORDER) \
	$(NETKEY_DEFS) \
	$(X509_DEFS) \
	${EXTRA_CRYPTO_DEFS} \
	${KLIPS_DEFS} ${WIN2K_DEFS} ${MAST_DEFS} ${BSDKAME_DEFS} \
	${LABELED_IPSEC_DEFS} \
	${SYSTEMD_NOTIFY_DEFS} \
	${XAUTH_DEFS} ${XAUTHPAM_DEFS} \
	${CURL_DEFS}\
	${SINGLE_CONF_DIR} \
	${IPSEC_CONNECTION_LIMIT_DEFS} \


# libefence is a free memory allocation debugger
# Solaris 2 needs -lsocket -lnsl
LIBSPLUTO+=$(LIBRESWANLIB) $(LIBPLUTO)
LIBSPLUTO+=${LIBSHA1} ${LIBMD5} $(LIBSHA2) ${LIBAES_XCBC}
LIBSPLUTO+=$(X509_LIBS)
LIBSPLUTO+=$(THREADS_LIBS)
LIBSPLUTO+=${CURL_LIBS}
LIBSPLUTO+=${EXTRA_CRYPTO_LIBS} ${LABELED_IPSEC_LIBS}
LIBSPLUTO+=${SYSTEMD_NOTIFY_LIBS}
LIBSPLUTO+=${WHACKLIB} ${BSDKAME_LIBS} $(NSS_LDFLAGS)
PLUTOMINUSL+= ${X509_LLIBS} ${CURL_LLIBS} ${THREADS_LLIBS}
PLUTOMINUSL+= ${XAUTH_LLIBS} ${XAUTHPAM_LIBS} $(NSS_LDFLAGS)
PLUTOMINUSL+= ${LIBCRYPT}

# For avoiding implicit DSO linking
LIBSPLUTO+= -lpthread

ifeq ($(USE_FIPSCHECK),true)
LIBSPLUTO+= -lfipscheck
endif

ifeq ($(USE_LIBCAP_NG),true)
DEFINES+=-DHAVE_LIBCAP_NG
LIBSPLUTO+= -lcap-ng
endif

BINNAMEPLUTO = pluto
BINNAMEWHACK = whack
BINNAMEIMPORTCRL = _import_crl

OSDEP?=$(shell uname -s | tr 'A-Z' 'a-z')
SYSDEP_SRC=sysdep_${OSDEP}.c
SYSDEP_OBJ=sysdep_${OSDEP}.o

# End of configuration coping options.

LDFLAGS+=$(NSS_LDFLAGS)

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

LIBSPLUTO += $(IPSECCONFLIB) $(LIBRESWANLIB)   -lrt
LIBSPLUTO += $(UNBOUND_LDFLAGS)

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

DISTMISC = CHANGES PLUTO-CONVENTIONS TODO Makefile routing.txt \
	 pluto.8 ipsec_whack.8 .cvsignore

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
	myid.c hmac.c \
	hostpair.c ipsec_doi.c ipsec_doi.h \
	spdb.c spdb_struct.c spdb.h \
	ikev1.c ikev1_quick.c ikev1_continuations.h \
	ikev1_dpd.c ikev1_dpd.h ikev1_spdb_struct.c \
	ikev1_msgid.c \
        ikev2.c ikev2_parent.c ikev2_child.c ikev2_crypto.c \
	crypt_dbg.c \
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
	whack.c \
	${XAUTH_DIST_SRCS} \
	${AGGRESSIVE_DIST_SRCS} \
	${LABELED_IPSEC_DIST_SRCS} \
	${SYSTEMD_NOTIFY_DIST_SRCS} \
	packet.c pluto_constants.c readwhackmsg.c \
	nss_cert_load.c nss_cert_load.h pem.c \
	nss_cert_vfy.c nss_cert_vfy.h \
	nss_ocsp.c nss_ocsp.h \
	nss_crl_import.c nss_crl_import.h \
	nss_err.c nss_err.h \
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
OBJSPLUTO += crypt_dbg.o
OBJSPLUTO += crypt_symkey.o crypt_prf.o ikev1_prf.o ikev2_prf.o
OBJSPLUTO += kernel.o
OBJSPLUTO += $(NETKEY_OBJS) $(BSDKAME_OBJS) ${KLIPS_OBJS} ${MAST_OBJS} ${WIN2K_OBJS} ${PFKEYv2_OBJS}
OBJSPLUTO += kernel_noklips.o rcv_whack.o
OBJSPLUTO += demux.o msgdigest.o keys.o
OBJSPLUTO += pluto_crypt.o crypt_utils.o crypt_ke.o crypt_dh.o crypt_start_dh.o
OBJSPLUTO += rnd.o spdb.o spdb_struct.o
OBJSPLUTO += vendor.o nat_traversal.o virtual.o
OBJSPLUTO += ike_alg_aes.o
OBJSPLUTO += ike_alg_camellia.o
OBJSPLUTO += ${EXTRA_CRYPTO_OBJS} ike_alg_sha2.o
OBJSPLUTO += ike_alg.o ike_alg_status.o db_ops.o
OBJSPLUTO += ${XAUTH_OBJS}
OBJSPLUTO += ${AGGRESSIVE_OBJS}
OBJSPLUTO += ${LABELED_IPSEC_OBJS}
OBJSPLUTO += ${SYSTEMD_NOTIFY_OBJS}
OBJSPLUTO += ${X509_OBJS} ${THREADS_OBJS}
OBJSPLUTO += ${OBJSLIBPLUTO}
OBJSPLUTO += ${SYSDEP_OBJ}
OBJSPLUTO += packet.o pluto_constants.o readwhackmsg.o
OBJSPLUTO += nss_cert_load.o pem.o nss_cert_vfy.o
OBJSPLUTO += nss_ocsp.o nss_crl_import.o
OBJSPLUTO += nss_err.o
OBJSPLUTO += ${UDPFROMTO_SRCS:.c=.o}

OBJSWHACK = whack.o

CAVP += cavp

local-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) buildall

local-clean-base: $(builddir)/Makefile
	$(RM) $(RMFLAGS) *.core core *~ a.out ktrace.out \
		$(foreach f,$(OBJSPLUTO) $(BINNAMEPLUTO) $(OBJSWHACK) $(BINNAMEWHACK) $(BINNAMEADNS) $(OBJSCAVP) $(CAVP), $(builddir)/$(f))

local-install-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) doinstall
buildall: $(BINNAMEPLUTO) $(BINNAMEWHACK) $(CAVP)

doinstall:
	mkdir -p ${LIBEXECDIR}
	mkdir -p -m 700 $(CONFDIR)/ipsec.d
	mkdir -p -m 755 $(VARDIR)/run/pluto
	$(INSTALL) $(INSTBINFLAGS) $(BINNAMEPLUTO) $(BINNAMEWHACK) $(LIBEXECDIR)

list-local-base:
	@echo $(LIBEXECDIR)/$(BINNAMEPLUTO)
	@echo $(LIBEXECDIR)/$(BINNAMEWHACK)

$(BINNAMEPLUTO): $(OBJSPLUTO) $(ALG_LIBS) $(LIBRESWANLIB)
	$(CC) -o $(BINNAMEPLUTO) $(LDFLAGS) $(USERLINK) $(OBJSPLUTO) $(LIBSPLUTO) ${PLUTOMINUSL}

$(BINNAMEWHACK): $(OBJSWHACK)
	$(CC) -o $(BINNAMEWHACK) $(LDFLAGS) $(OBJSWHACK) $(USERLINK) $(LIBSWHACK) ${WHACKMINUSL}

check:
	echo no checks in lib right now.

checkprograms:

# Cryptographic Algorithm Validation Program (CAVP)
# see: http://csrc.nist.gov/groups/STM/cavp/index.html
CAVPSRC += cavp.c
CAVPSRC += cavp_print.c
CAVPSRC += cavp_stubs.c
CAVPSRC += cavp_ikev1.c
CAVPSRC += cavp_ikev2.c
DISTSRC += $(CAVPSRC)
OBJSCAVP = $(CAVPSRC:.c=.o) $(filter-out plutomain.o, $(OBJSPLUTO))
cavp: $(OBJSCAVP)
	$(CC) -o $@ $(OBJSCAVP) \
		$(LDFLAGS) $(USERLINK) $(LIBSPLUTO) ${PLUTOMINUSL}

%.i: %.c
	$(CC) $(MK_DEPEND_CFLAGS) -E -o $@ $<

MK_DEPEND_FILES = $(DISTSRC)
MK_DEPEND_CFLAGS = $(USERLAND_CFLAGS) ${PORTINCLUDE} $(COPTS) $(HDRDIRS) $(DEFINES) $(NSSFLAGS) $(CFLAGS) ${CROSSFLAGS}
include $(top_srcdir)/mk/depend.mk
