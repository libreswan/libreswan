# Pluto Makefile
#
# Copyright (C) 1997 Angelos D. Keromytis.
# Copyright (C) 1998-2001 D. Hugh Redelmeier
# Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
# Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
# Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
# Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
# Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015-2017 Andrew Cagney <cagney@gnu.org>
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

# XXX: Old code would define custom make variables and then append
# those variables to OBJSPLUTO.  New code should just append needed
# values directly.

# Object files required by this pluto build.
OBJSPLUTO =

# where to find klips headers and Libreswan headers
# and 2.6 kernel's <rtnetlink.h> and <xfrm.h>
HDRDIRS = -I${LIBRESWANSRCDIR}/programs/pluto/linux26 -I${LIBRESWANSRCDIR}/include -I$(LIBRESWANSRCDIR)/lib/libcrypto -I$(KLIPSINC)

# -DKLIPS enables interface to Kernel LINUX IPsec code
# -DNETKEY enables interface to Kernel NETKEY/XFRM IPsec code

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
PFKEYv2_OBJS=kernel_pfkey.o
else
PFKEYv2_OBJS=
endif

ifeq ($(USE_NETKEY),true)
NETKEY_DEFS=-DNETKEY_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES -DPFKEY
NETKEY_OBJS=kernel_netlink.o
endif

ifeq ($(USE_KLIPS),true)
KLIPS_DEFS=-DKLIPS -DPFKEY
KLIPS_OBJS=kernel_klips.o
endif

ifeq ($(USE_MAST),true)
MAST_DEFS=-DKLIPS_MAST
MAST_OBJS=kernel_mast.o
endif

ifeq ($(USE_WIN2K_NATIVE),true)
WIN2K_DEFS=-DWIN2K_NATIVE_IPSEC
WIN2K_OBJS=kernel_win2k.o
endif

ifeq ($(USE_BSDKAME),true)
BSDKAME_DEFS=-DBSD_KAME
BSDKAME_OBJS=kernel_bsdkame.o
BSDKAME_LIBS=${LIBBSDPFKEY}
endif


# the files are defined here so that TAGS: can catch them.
#
X509_DIST_OBJS=x509.o
THREADS_DIST_OBJS=fetch.o
X509_OBJS=${X509_DIST_OBJS}

THREADS_OBJS=${THREADS_DIST_OBJS}
THREADS_LLIBS=-lpthread

ifeq ($(USE_IPSEC_CONNECTION_LIMIT),true)
IPSEC_CONNECTION_LIMIT_DEFS=-DIPSEC_CONNECTION_LIMIT=$(IPSEC_CONNECTION_LIMIT)
endif

# pam_conv.c is wrapped in #ifdef XAUTH_HAVE_PAM
OBJSPLUTO += ikev1_xauth.o addresspool.o pam_conv.o
LIBSPLUTO += $(XAUTHPAM_LDFLAGS)
ifneq ($(BUILDENV), darwin)
LIBSPLUTO += -lcrypt
endif

AGGRESSIVE_DIST_OBJS=ikev1_aggr.o
AGGRESSIVE_OBJS=${AGGRESSIVE_DIST_OBJS}

# LABELED IPSEC support - requires SElinux
ifeq ($(USE_LABELED_IPSEC),true)
OBJSPLUTO += security_selinux.o
LIBSPLUTO += -lselinux
endif

ifeq ($(USE_SECCOMP),true)
OBJSPLUTO += pluto_seccomp.o
endif

SYSTEMD_NOTIFY_DIST_OBJS=pluto_sd.o
ifeq ($(USE_SYSTEMD_WATCHDOG),true)
SYSTEMD_NOTIFY_DEFS=-DUSE_SYSTEMD_WATCHDOG
SYSTEMD_NOTIFY_OBJS=${SYSTEMD_NOTIFY_DIST_OBJS}
SYSTEMD_NOTIFY_LIBS=-lsystemd
endif


ifeq ($(USE_LIBCURL),true)
# This compile option activates dynamic URL fetching
# with libcurl in the source code
CURL_DEFS=-DLIBCURL
CURL_LLIBS=-lcurl
endif

EXTRA_CRYPTO_OBJS+=ike_alg_nss_hash_ops.o
EXTRA_CRYPTO_OBJS+=ike_alg_hmac_prf_ops.o
EXTRA_CRYPTO_OBJS+=ike_alg_nss_prf_ops.o
EXTRA_CRYPTO_OBJS+=ike_alg_nss_gcm.o

EXTRA_CRYPTO_OBJS+=ike_alg_null.o

ifeq ($(USE_SERPENT),true)
EXTRA_CRYPTO_OBJS+=ike_alg_serpent.o
EXTRA_CRYPTO_LIBS+=$(LIBSERPENT)
endif

ifeq ($(USE_TWOFISH),true)
EXTRA_CRYPTO_OBJS+=ike_alg_twofish.o
EXTRA_CRYPTO_LIBS+=$(LIBTWOFISH)
endif

ifeq ($(USE_CAST),true)
EXTRA_CRYPTO_OBJS+=ike_alg_cast.o
endif

ifeq ($(USE_RIPEMD),true)
EXTRA_CRYPTO_OBJS+=ike_alg_ripemd.o
endif

EXTRA_CRYPTO_OBJS += ike_alg_sha1.o

EXTRA_CRYPTO_OBJS += ike_alg_md5.o

ifeq ($(USE_3DES),true)
EXTRA_CRYPTO_OBJS += ike_alg_3des.o
endif

ifeq ($(USE_SINGLE_CONF_DIR),true)
SINGLE_CONF_DIR=-DSINGLE_CONF_DIR
endif

DEFINES = $(EXTRA_DEFINES) \
	${VENDORID} \
	$(KEYRR_DEFINES) \
	$(NETKEY_DEFS) \
	${KLIPS_DEFS} ${WIN2K_DEFS} ${MAST_DEFS} ${BSDKAME_DEFS} \
	${LABELED_IPSEC_DEFS} \
	${SYSTEMD_NOTIFY_DEFS} \
	${CURL_DEFS}\
	${SINGLE_CONF_DIR} \
	${IPSEC_CONNECTION_LIMIT_DEFS} \


# libefence is a free memory allocation debugger
# Solaris 2 needs -lsocket -lnsl
LIBSPLUTO+=$(LIBRESWANLIB) $(LIBPLUTO)
LIBSPLUTO+=$(THREADS_LIBS)
LIBSPLUTO+=${CURL_LIBS}
LIBSPLUTO+=${EXTRA_CRYPTO_LIBS} ${LABELED_IPSEC_LIBS} $(SECCOMP_LDFLAGS)
LIBSPLUTO+=${SYSTEMD_NOTIFY_LIBS}
LIBSPLUTO+=${WHACKLIB} ${BSDKAME_LIBS}
LIBSPLUTO+=$(NSS_LDFLAGS)

# For avoiding implicit DSO linking
LIBSPLUTO+= -lpthread

LIBSPLUTO += $(FIPSCHECK_LDFLAGS)

ifeq ($(USE_LIBCAP_NG),true)
DEFINES+=-DHAVE_LIBCAP_NG
LIBSPLUTO+= -lcap-ng
endif

BINNAMEPLUTO = pluto

OSDEP?=$(shell uname -s | tr 'A-Z' 'a-z')
SYSDEP_OBJ=sysdep_${OSDEP}.o

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

LIBSPLUTO += $(LDAP_LDFLAGS) $(CURL_LLIBS) $(THREADS_LLIBS)
LIBSPLUTO += $(LIBCRYPT)

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
OBJSPLUTO += $(UDPFROMTO_SRCS:.c=.o)

RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

OBJSPLUTO += connections.o initiate.o terminate.o
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
OBJSPLUTO += crypt_hash.o
OBJSPLUTO += kernel.o
OBJSPLUTO += $(NETKEY_OBJS) $(BSDKAME_OBJS) ${KLIPS_OBJS} ${MAST_OBJS} ${WIN2K_OBJS} ${PFKEYv2_OBJS}
OBJSPLUTO += kernel_noklips.o rcv_whack.o
OBJSPLUTO += demux.o msgdigest.o keys.o
OBJSPLUTO += pluto_crypt.o crypt_utils.o crypt_ke.o crypt_dh.o crypt_start_dh.o
OBJSPLUTO += rnd.o spdb.o spdb_struct.o
OBJSPLUTO += vendor.o nat_traversal.o virtual.o
OBJSPLUTO += ike_alg_aes.o
OBJSPLUTO += ike_alg_dh.o
OBJSPLUTO += ike_alg_camellia.o
OBJSPLUTO += ${EXTRA_CRYPTO_OBJS} ike_alg_sha2.o
OBJSPLUTO += ike_alg.o db_ops.o
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

CAVP += cavp

local-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) buildall

local-clean-base: $(builddir)/Makefile
	$(RM) $(RMFLAGS) *.core core *~ a.out ktrace.out \
		$(foreach f,$(OBJSPLUTO) $(BINNAMEPLUTO) $(OBJSCAVP) $(CAVP), $(builddir)/$(f))

local-install-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) doinstall
buildall: $(BINNAMEPLUTO) $(CAVP)

doinstall:
	mkdir -p ${LIBEXECDIR}
	mkdir -p -m 700 $(CONFDIR)/ipsec.d
	mkdir -p -m 755 $(VARDIR)/run/pluto
	$(INSTALL) $(INSTBINFLAGS) $(BINNAMEPLUTO) $(LIBEXECDIR)

list-local-base:
	@echo $(LIBEXECDIR)/$(BINNAMEPLUTO)

$(BINNAMEPLUTO): $(OBJSPLUTO) $(ALG_LIBS) $(LIBRESWANLIB)
	$(CC) -o $(BINNAMEPLUTO) $(LDFLAGS) $(USERLINK) $(OBJSPLUTO) $(LIBSPLUTO)

check:
	echo no checks in lib right now.

checkprograms:

# Cryptographic Algorithm Validation Program (CAVP)
# see: http://csrc.nist.gov/groups/STM/cavp/index.html
OBJSCAVP += cavp.o
OBJSCAVP += cavp_print.o
OBJSCAVP += cavp_stubs.o
OBJSCAVP += cavp_ikev1.o
OBJSCAVP += cavp_ikev2.o
OBJSCAVP += cavp_sha.o
OBJSCAVP += cavp_hmac.o
OBJSCAVP += cavp_gcm.o
OBJSCAVP += $(filter-out plutomain.o, $(OBJSPLUTO))
cavp: $(OBJSCAVP)
	$(CC) -o $@ $(OBJSCAVP) \
		$(LDFLAGS) $(USERLINK) $(LIBSPLUTO)

%.i: %.c
	$(CC) $(MK_DEPEND_CFLAGS) -E -o $@ $<

MK_DEPEND_FILES = $(sort $(OBJSCAVP) $(OBJSPLUTO))
MK_DEPEND_CFLAGS = $(USERLAND_CFLAGS) ${PORTINCLUDE} $(COPTS) $(HDRDIRS) $(DEFINES) $(NSSFLAGS) $(CFLAGS) ${CROSSFLAGS}
include $(top_srcdir)/mk/depend.mk
