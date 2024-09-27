# Pluto Makefile, for libreswan
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
PROGRAM_MANPAGE = # suppress default
MANPAGES += libreswan.7
MANPAGES += ipsec-pluto.8

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
OBJS += ipsec_interface.o
OBJS += kernel_ipsec_interface.o
ifeq ($(USE_PFKEYV2),true)
OBJS += kernel_ipsec_interface_ifconfig.o
endif

ifeq ($(USE_IKEv1),true)
OBJS += ikev1_cert.o
OBJS += ikev1_send.o
OBJS += ikev1_peer_id.o
endif

OBJS += unpack.o
OBJS += impair_message.o
# exchanges
OBJS += ikev2_ike_sa_init.o
OBJS += ikev2_ike_intermediate.o
OBJS += ikev2_ike_auth.o
OBJS += ikev2_create_child_sa.o
OBJS += ikev2_informational.o
# payloads
OBJS += ikev2_cert.o
OBJS += ikev2_certreq.o
OBJS += ikev2_notify.o
OBJS += ikev2_cp.o
OBJS += ikev2_ts.o

OBJS += ikev2_peer_id.o
OBJS += peer_id.o

OBJS += ikev2_mobike.o
OBJS += ikev2_send.o
OBJS += ikev2_message.o
OBJS += ikev2_cookie.o
OBJS += ikev2_msgid.o
OBJS += ikev2_auth.o
OBJS += ikev2_auth_helper.o
OBJS += ikev2_delete.o
OBJS += ikev2_liveness.o
OBJS += ikev2_eap.o

OBJS += state_db.o
OBJS += show.o
OBJS += binlog.o
OBJS += retransmit.o

OBJS += rcv_whack.o
OBJS += whack_add.o
OBJS += whack_connection.o
OBJS += whack_connectionstatus.o
OBJS += whack_crash.o
OBJS += whack_briefconnectionstatus.o
OBJS += whack_debug.o
OBJS += whack_delete.o
OBJS += whack_deleteid.o
OBJS += whack_deletestate.o
OBJS += whack_deleteuser.o
OBJS += whack_down.o
OBJS += whack_impair.o
OBJS += whack_initiate.o
OBJS += whack_sa.o
OBJS += whack_route.o
OBJS += whack_showstates.o
OBJS += whack_shutdown.o
OBJS += whack_status.o
OBJS += whack_trafficstatus.o
OBJS += whack_unroute.o

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

# kernel

OBJS += kernel.o
OBJS += kernel_policy.o
OBJS += kernel_ops.o
OBJS += kernel_alg.o

OBJS += updown.o

ifeq ($(USE_PFKEYV2),true)
OBJS += kernel_sadb.o
OBJS += kernel_sadb_names.o
OBJS += kernel_sadb_logger.o
endif

ifeq ($(USE_XFRM),true)
OBJS += kernel_xfrm.o
ifeq ($(USE_XFRM_INTERFACE),true)
OBJS += kernel_xfrm_interface.o
endif
endif

ifeq ($(USE_PFKEYV2),true)
OBJS += kernel_pfkeyv2.o
endif

# PKIX: Public-Key Infrastructure using X.509
OBJS += x509.o
OBJS += fetch.o
OBJS += crl_queue.o

OBJS += addresspool.o

ifeq ($(USE_IKEv1),true)
# ikev1_xauth.c calls crypt(), link it in.
OBJS += ikev1_xauth.o
USERLAND_LDFLAGS += $(CRYPT_LDFLAGS)
endif

ifeq ($(USE_AUTHPAM),true)
OBJS += pam_auth.o
OBJS += pam_conv.o
endif
USERLAND_LDFLAGS += $(AUTHPAM_LDFLAGS)

# LABELED IPSEC support - requires SElinux
OBJS += labeled_ipsec.o
ifeq ($(USE_LABELED_IPSEC),true)
USERLAND_LDFLAGS += -lselinux
endif

ifeq ($(USE_SECCOMP),true)
OBJS += pluto_seccomp.o
endif

ifeq ($(USE_SYSTEMD_WATCHDOG),true)
OBJS += pluto_sd.o
endif

USERLAND_LDFLAGS += $(CURL_LDFLAGS)

OBJS += ikev1_db_ops.o

# libefence is a free memory allocation debugger
# Solaris 2 needs -lsocket -lnsl
USERLAND_LDFLAGS += $(SECCOMP_LDFLAGS)
USERLAND_LDFLAGS += $(SSL_LDFLAGS)
USERLAND_LDFLAGS += $(NSS_SMIME_LDFLAGS)
USERLAND_LDFLAGS += $(NSS_UTIL_LDFLAGS)
USERLAND_LDFLAGS += $(NSS_LDFLAGS)
USERLAND_LDFLAGS += $(NSPR_LDFLAGS)

# For avoiding implicit DSO linking
USERLAND_LDFLAGS += -lpthread

USERLAND_LDFLAGS += $(LIBCAP_NG_LDFLAGS)

# Add RT_LDFLAGS for glibc < 2.17
USERLAND_LDFLAGS += $(RT_LDFLAGS)

# interface detection code
OBJS += iface.o
OBJS += iface_udp.o
OBJS += iface_tcp.o
OBJS += kernel_iface.o
# implement kernel_iface.h
ifneq ($(LINUX_VARIANT),)
OBJS += kernel_iface_linux.o
endif
ifneq ($(BSD_VARIANT),)
OBJS += kernel_iface_bsd.o
endif

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

USERLAND_LDFLAGS += $(UNBOUND_LDFLAGS)
USERLAND_LDFLAGS += $(LINUX_AUDIT_LDFLAGS)

OBJS += linux_audit.o

USERLAND_LDFLAGS += $(LIBEVENT_LDFLAGS)
USERLAND_LDFLAGS += $(LDAP_LDFLAGS)

OBJS += connections.o
OBJS += instantiate.o
OBJS += connection_db.o
OBJS += connection_event.o
OBJS += spd_db.o

OBJS += routing.o
OBJS += routing_names.o
OBJS += routing_story.o

OBJS += acquire.o
OBJS += initiate.o
OBJS += ddns.o
OBJS += terminate.o
OBJS += pending.o crypto.o defs.o
OBJS += ike_spi.o
OBJS += foodgroups.o
OBJS += log.o
OBJS += log_limiter.o
OBJS += state.o plutomain.o plutoalg.o
OBJS += revival.o
OBJS += orient.o
OBJS += server.o
OBJS += server_fork.o
OBJS += server_pool.o
OBJS += server_run.o
OBJS += hash_table.o list_entry.o
OBJS += timer.o
OBJS += ikev2_host_pair.o
OBJS += ikev2_retransmit.o
OBJS += ipsec_doi.o
ifeq ($(USE_DNSSEC),true)
OBJS += ikev2_ipseckey.o ikev2_ipseckey_dnsr.o
endif
ifeq ($(USE_IKEv1),true)
OBJS += ikev1.o ikev1_aggr.o ikev1_quick.o ikev1_dpd.o ikev1_spdb_struct.o ikev1_msgid.o
OBJS += ikev1_states.o ikev1_hash.o ikev1_message.o ikev1_nat.o
OBJS += ikev1_main.o
OBJS += ikev1_delete.o
OBJS += crypt_dh_v1.o
OBJS += ikev1_retransmit.o
OBJS += ikev1_replace.o
OBJS += ikev1_host_pair.o
OBJS += ikev1_spdb.o
endif
OBJS += ikev2.o ikev2_parent.o ikev2_child.o
OBJS += ikev2_replace.o
OBJS += ikev2_proposals.o
OBJS += ikev2_states.o
OBJS += ikev2_psk.o ikev2_ppk.o ikev2_crypto.o
OBJS += ikev2_redirect.o
OBJS += cert_decode_helper.o
OBJS += pluto_stats.o
OBJS += demux.o msgdigest.o keys.o
OBJS += crypt_ke.o crypt_dh.o
OBJS += crypt_dh_v2.o
OBJS += hourly.o
OBJS += ikev1_vendorid.o
OBJS += ikev2_vendorid.o
OBJS += nat_traversal.o
OBJS += ikev2_nat.o
OBJS += virtual_ip.o
OBJS += packet.o pluto_constants.o
OBJS += pem.o nss_cert_verify.o
OBJS += nss_ocsp.o nss_crl_import.o
OBJS += root_certs.o
OBJS += pluto_timing.o
OBJS += nss_cert_reread.o
OBJS += rekeyfuzz.o


# Archives

ifeq ($(USE_SYSTEMD_WATCHDOG),true)
# uses stuff from libswan
OBJS += $(LSWSDLIB)
endif

OBJS += $(LIBRESWANLIB)
OBJS += $(WHACKLIB)
OBJS += $(IPSECCONFLIB)
OBJS += $(LIBRESWANLIB)

include $(top_srcdir)/mk/program.mk
