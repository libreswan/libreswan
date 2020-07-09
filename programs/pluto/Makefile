# Pluto Makefile
#
# Copyright (C) 1997 Angelos D. Keromytis.
# Copyright (C) 1998-2001 D. Hugh Redelmeier
# Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
# Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
# Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
# Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
# Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015-2017 Andrew Cagney
# Copyright (C) 2016-2017 Paul Wouters <pwouters@redhat.com>
# Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

PROGRAM = pluto

# XXX: Pluto doesn't include mk/program.mk and define PROGRAM
PROGRAM_MANPAGE = ipsec_pluto.8

#
# XXX:
#
# Because pluto's Makefile tests USE_... variables, defined in
# config.mk, using "ifeq", it needs to include that file early.
#
# Instead:
#
# - replace the code with '$(call if-enabled)'.
#
# - move the optional files to their own library?
#

ifndef top_srcdir
include ../../mk/dirs.mk
endif
include $(top_srcdir)/mk/config.mk

# Object files required by this pluto build.

OBJS =

OBJS += send.o
OBJS += ikev1_send.o

OBJS += ikev2_notify.o
OBJS += ikev2_send.o
OBJS += ikev2_message.o
OBJS += ikev2_cookie.o
OBJS += ikev2_ts.o
OBJS += ikev2_msgid.o
OBJS += ikev2_auth.o
OBJS += ikev2_auth_helper.o
OBJS += ikev2_delete.o
OBJS += ikev2_rekey.o
OBJS += ikev2_liveness.o

OBJS += state_db.o
OBJS += show.o
OBJS += retransmit.o

# local (possibly more up to date) copy of <linux/xfrm.h>
ifeq ($(USE_XFRM_HEADER_COPY),true)
USERLAND_INCLUDES += -I${LIBRESWANSRCDIR}/programs/pluto/linux-copy
endif

ifeq ($(USE_XFRM_INTERFACE), true)
ifeq ($(USE_XFRM_INTERFACE_IFLA_HEADER), true)
USERLAND_CFLAGS += -DUSE_XFRM_INTERFACE_IFLA_HEADER
USERLAND_INCLUDES += -I${LIBRESWANSRCDIR}/programs/pluto/linux-extra-if-link
endif
endif

ifeq ($(USE_GLIBC_KERN_FLIP_HEADERS),true)
USERLAND_CFLAGS += -DGLIBC_KERN_FLIP_HEADERS
endif

ifeq ($(USE_XFRM),true)
OBJS += kernel_xfrm.o
ifeq ($(USE_XFRM_INTERFACE),true)
OBJS += kernel_xfrm_interface.o
endif
endif

ifeq ($(USE_BSDKAME),true)
OBJS += kernel_bsdkame.o
endif

OBJS += x509.o
OBJS += fetch.o
OBJS += crl_queue.o

ifeq ($(USE_IPSEC_CONNECTION_LIMIT),true)
USERLAND_CFLAGS += -DIPSEC_CONNECTION_LIMIT=$(IPSEC_CONNECTION_LIMIT)
endif

OBJS += addresspool.o

# ikev1_xauth.c calls crypt(), link it in.
OBJS += ikev1_xauth.o
USERLAND_LDFLAGS += $(CRYPT_LDFLAGS)

ifeq ($(USE_XAUTHPAM),true)
OBJS += xauth.o
OBJS += pam_conv.o
endif
USERLAND_LDFLAGS += $(XAUTHPAM_LDFLAGS)

OBJS += ikev1_aggr.o

# LABELED IPSEC support - requires SElinux
ifeq ($(USE_LABELED_IPSEC),true)
OBJS += security_selinux.o
USERLAND_LDFLAGS += -lselinux
endif

ifeq ($(USE_SECCOMP),true)
OBJS += pluto_seccomp.o
endif

OBJS += $(call if-enabled, USE_SYSTEMD_WATCHDOG, pluto_sd.o)
USERLAND_LDFLAGS += $(SYSTEMD_WATCHDOG_LDFLAGS)

USERLAND_LDFLAGS += $(CURL_LDFLAGS)

ifeq ($(USE_UNBOUND_EVENT_H_COPY),true)
USERLAND_INCLUDES += -I${LIBRESWANSRCDIR}/include/unbound
endif

OBJS += db_ops.o

# libefence is a free memory allocation debugger
# Solaris 2 needs -lsocket -lnsl
USERLAND_LDFLAGS += $(SECCOMP_LDFLAGS)
USERLAND_LDFLAGS += $(NSS_SMIME_LDFLAGS)
USERLAND_LDFLAGS += $(NSS_LDFLAGS)
USERLAND_LDFLAGS += $(NSPR_LDFLAGS)

# For avoiding implicit DSO linking
USERLAND_LDFLAGS += -lpthread

USERLAND_LDFLAGS += $(FIPSCHECK_LDFLAGS)
USERLAND_LDFLAGS += $(LIBCAP_NG_LDFLAGS)

# Add RT_LDFLAGS for glibc < 2.17
USERLAND_LDFLAGS += $(RT_LDFLAGS)

ifeq ($(USE_BSDKAME),true)
OBJS += kernel_bsd.o
else
OBJS += kernel_linux.o
endif

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

USERLAND_LDFLAGS += $(UNBOUND_LDFLAGS)
USERLAND_LDFLAGS += $(LINUX_AUDIT_LDFLAGS)

OBJS += linux_audit.o

USERLAND_LDFLAGS += -levent
USERLAND_LDFLAGS += -levent_pthreads

USERLAND_LDFLAGS += $(LDAP_LDFLAGS)

OBJS += connections.o
OBJS += connection_db.o
OBJS += initiate.o terminate.o ikev2_rekey_now.o
OBJS += cbc_test_vectors.o
OBJS += ctr_test_vectors.o
OBJS += gcm_test_vectors.o
OBJS += prf_test_vectors.o
OBJS += test_buffer.o
OBJS += pending.o crypto.o defs.o
OBJS += ike_spi.o
OBJS += foodgroups.o log.o state.o plutomain.o plutoalg.o server.o
OBJS += iface.o
OBJS += iface_udp.o
OBJS += iface_tcp.o
OBJS += peerlog.o
OBJS += hash_table.o list_entry.o
OBJS += timer.o hostpair.o
OBJS += retry.o
OBJS += ipsec_doi.o
ifeq ($(USE_DNSSEC),true)
OBJS += ikev2_ipseckey.o
endif
OBJS += ikev1.o ikev1_main.o ikev1_quick.o ikev1_dpd.o ikev1_spdb_struct.o ikev1_msgid.o
OBJS += ikev1_states.o
OBJS += ikev1_hash.o
OBJS += ikev1_message.o
OBJS += ikev2.o ikev2_parent.o ikev2_child.o ikev2_spdb_struct.o
OBJS += ikev2_states.o
OBJS += ikev2_ecdsa.o ikev2_rsa.o ikev2_psk.o ikev2_ppk.o ikev2_crypto.o
OBJS += ikev2_redirect.o
OBJS += ikev1_prf.o
OBJS += ikev2_prf.o
OBJS += cert_decode_helper.o
OBJS += kernel.o
OBJS += rcv_whack.o pluto_stats.o
OBJS += demux.o msgdigest.o keys.o
OBJS += pluto_crypt.o crypt_utils.o crypt_ke.o crypt_dh.o
OBJS += crypt_dh_v1.o
OBJS += crypt_dh_v2.o
OBJS += rnd.o spdb.o spdb_struct.o
OBJS += vendor.o nat_traversal.o virtual.o
OBJS += packet.o pluto_constants.o
OBJS += pem.o nss_cert_verify.o
OBJS += nss_ocsp.o nss_crl_import.o
OBJS += nss_err.o
OBJS += root_certs.o
OBJS += pluto_timing.o
OBJS += nss_cert_reread.o

# Archives
OBJS += $(LIBRESWANLIB)
OBJS += $(WHACKLIB)
OBJS += $(IPSECCONFLIB)
OBJS += $(LIBRESWANLIB)
ifeq ($(USE_BSDKAME),true)
OBJS += $(BSDPFKEYLIB)
endif

include $(top_srcdir)/mk/program.mk
