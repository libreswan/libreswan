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

# Object files required by this pluto build.

OBJS =

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
OBJS += kernel_pfkey.o
endif

ifeq ($(USE_NETKEY),true)
NETKEY_DEFS=-DNETKEY_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES -DPFKEY
OBJS += kernel_netlink.o
endif

ifeq ($(USE_KLIPS),true)
KLIPS_DEFS=-DKLIPS -DPFKEY
OBJS += kernel_klips.o
endif

ifeq ($(USE_MAST),true)
MAST_DEFS=-DKLIPS_MAST
OBJS += kernel_mast.o
endif

ifeq ($(USE_WIN2K_NATIVE),true)
WIN2K_DEFS=-DWIN2K_NATIVE_IPSEC
OBJS += kernel_win2k.o
endif

ifeq ($(USE_BSDKAME),true)
BSDKAME_DEFS=-DBSD_KAME
OBJS += kernel_bsdkame.o
# LIBBSDPFKEY is presumably passed in.
LDFLAGS += ${LIBBSDPFKEY}
endif

OBJS += x509.o
OBJS += fetch.o

ifeq ($(USE_IPSEC_CONNECTION_LIMIT),true)
IPSEC_CONNECTION_LIMIT_DEFS=-DIPSEC_CONNECTION_LIMIT=$(IPSEC_CONNECTION_LIMIT)
endif

# pam_conv.c is wrapped in #ifdef XAUTH_HAVE_PAM
OBJS += ikev1_xauth.o addresspool.o pam_conv.o
LDFLAGS += $(XAUTHPAM_LDFLAGS)
ifneq ($(BUILDENV), darwin)
LDFLAGS += -lcrypt
endif

OBJS += ikev1_aggr.o

# LABELED IPSEC support - requires SElinux
ifeq ($(USE_LABELED_IPSEC),true)
OBJS += security_selinux.o
LDFLAGS += -lselinux
endif

ifeq ($(USE_SECCOMP),true)
OBJS += pluto_seccomp.o
endif

ifeq ($(USE_SYSTEMD_WATCHDOG),true)
SYSTEMD_NOTIFY_DEFS=-DUSE_SYSTEMD_WATCHDOG
OBJS += pluto_sd.o
LDFLAGS += -lsystemd
endif

LDFLAGS += $(CURL_LDFLAGS)

OBJS += ike_alg_nss_cbc.o
OBJS += ike_alg_nss_hash_ops.o
OBJS += ike_alg_hmac_prf_ops.o
OBJS += ike_alg_nss_prf_ops.o
OBJS += ike_alg_nss_gcm.o
OBJS += ike_alg_null.o

ifeq ($(USE_SERPENT),true)
OBJS += ike_alg_serpent.o
# an archive
OBJS += $(LIBSERPENT)
endif

ifeq ($(USE_TWOFISH),true)
OBJS += ike_alg_twofish.o
# an archive
OBJS += $(LIBTWOFISH)
endif

ifeq ($(USE_CAST),true)
OBJS += ike_alg_cast.o
endif

ifeq ($(USE_RIPEMD),true)
OBJS += ike_alg_ripemd.o
endif

OBJS += ike_alg_sha1.o
OBJS += ike_alg_md5.o

ifeq ($(USE_3DES),true)
OBJS += ike_alg_3des.o
endif

OBJS += ike_alg_aes.o
OBJS += ike_alg_dh.o
OBJS += ike_alg_camellia.o
OBJS += ike_alg_sha2.o
OBJS += ike_alg.o db_ops.o

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
LDFLAGS += $(SECCOMP_LDFLAGS)
LDFLAGS += $(NSS_LDFLAGS)

# For avoiding implicit DSO linking
LDFLAGS += -lpthread

LDFLAGS += $(FIPSCHECK_LDFLAGS)

ifeq ($(USE_LIBCAP_NG),true)
DEFINES+=-DHAVE_LIBCAP_NG
LDFLAGS += -lcap-ng
endif

BINNAMEPLUTO = pluto

# OSDEP already set in objdir.mk?
OSDEP?=$(shell uname -s | tr 'A-Z' 'a-z')
OBJS += sysdep_${OSDEP}.o

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

LDFLAGS += -lrt
LDFLAGS += $(UNBOUND_LDFLAGS)

ifeq ($(USE_LINUX_AUDIT),true)
LDFLAGS += -laudit
endif

LDFLAGS += -levent
LDFLAGS += -levent_pthreads

LDFLAGS += $(LDAP_LDFLAGS)

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
OBJS += $(UDPFROMTO_SRCS:.c=.o)

RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

OBJS += connections.o initiate.o terminate.o
OBJS += cbc_test_vectors.o
OBJS += ctr_test_vectors.o
OBJS += gcm_test_vectors.o
OBJS += test_buffer.o
OBJS += pending.o cookie.o crypto.o defs.o
OBJS += foodgroups.o log.o state.o plutomain.o plutoalg.o server.o
OBJS += state_entry.o
OBJS += timer.o hmac.o hostpair.o
OBJS += myid.o ipsec_doi.o
OBJS += ikev1.o ikev1_main.o ikev1_quick.o ikev1_dpd.o ikev1_spdb_struct.o ikev1_msgid.o
OBJS += ikev2.o ikev2_parent.o ikev2_child.o ikev2_spdb_struct.o
OBJS += ikev2_rsa.o ikev2_psk.o ikev2_crypto.o
OBJS += crypt_dbg.o
OBJS += crypt_symkey.o crypt_prf.o ikev1_prf.o ikev2_prf.o
OBJS += crypt_hash.o
OBJS += kernel.o
OBJS += kernel_noklips.o rcv_whack.o
OBJS += demux.o msgdigest.o keys.o
OBJS += pluto_crypt.o crypt_utils.o crypt_ke.o crypt_dh.o crypt_start_dh.o
OBJS += rnd.o spdb.o spdb_struct.o
OBJS += vendor.o nat_traversal.o virtual.o
OBJS += packet.o pluto_constants.o readwhackmsg.o
OBJS += nss_cert_load.o pem.o nss_cert_vfy.o
OBJS += nss_ocsp.o nss_crl_import.o
OBJS += nss_err.o

# Archives
OBJS += $(LIBRESWANLIB)
OBJS += $(WHACKLIB)
OBJS += $(IPSECCONFLIB)
OBJS += $(LIBRESWANLIB)

CAVP += cavp

local-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) buildall

local-clean-base: $(builddir)/Makefile
	$(RM) $(RMFLAGS) *.core core *~ a.out ktrace.out \
		$(foreach f,$(OBJS) $(BINNAMEPLUTO) $(OBJSCAVP) $(CAVP), $(builddir)/$(f))

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

$(BINNAMEPLUTO): $(OBJS)
	$(CC) -o $(BINNAMEPLUTO) $(OBJS) $(LDFLAGS) $(USERLINK)

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
OBJSCAVP += $(filter-out plutomain.o, $(OBJS))
cavp: $(OBJSCAVP)
	$(CC) -o $@ $(OBJSCAVP) $(LDFLAGS) $(USERLINK)

%.i: %.c
	$(CC) $(MK_DEPEND_CFLAGS) -E -o $@ $<

MK_DEPEND_FILES = $(sort $(OBJSCAVP) $(OBJS))
MK_DEPEND_CFLAGS = $(USERLAND_CFLAGS) ${PORTINCLUDE} $(COPTS) $(HDRDIRS) $(DEFINES) $(NSSFLAGS) $(CFLAGS) ${CROSSFLAGS}
include $(top_srcdir)/mk/depend.mk
