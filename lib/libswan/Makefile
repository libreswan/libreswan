# Libreswan library

# Copyright (C) 1998-2001  Henry Spencer.
# Copyright (C) 2003, 2004 Xelerance Corporation
# Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
# Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
# Copyright (C) 2015-2022 Andrew Cagney
# Copyright (C) 2019 Tuomo Soini <tis@foobar.fi>
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

#
# XXX:
#
# Because libswan's Makefile tests USE_... variables, defined in
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

LIB = libswan.a

OBJS += x509dn.o asn1.o oid.o

OBJS += authby.o
OBJS += rnd.o
OBJS += option_names.o
OBJS += encap_type_names.o
OBJS += encap_mode_names.o
OBJS += encap_proto_names.o
OBJS += initiated_by_names.o
OBJS += connection_owner_names.o
OBJS += sa_type.o
OBJS += fips_mode.o
OBJS += fips_mode_names.o
OBJS += state_category_names.o

OBJS += constants.o \
	id.o \
	initaddr.o \
	lex.o \
	lswconf.o \
	sameaddr.o \
	subnettypeof.o ttodata.o \
	ttosaid.o \
	secitem_chunk.o \
	lswnss.o \
	alg_byname.o

OBJS += cloexec_socket.o
OBJS += secret_pubkey_stuff_to_pubkey_der.o
OBJS += pubkey_der_to_pubkey_content.o
OBJS += clone_shunk_tokens.o
OBJS += secrets.o
OBJS += pubkey_rsa.o
OBJS += pubkey_ecdsa.o

OBJS += sparse_names.o
OBJS += ttoaddress_dns.o
OBJS += ttoaddress_num.o
OBJS += ttoaddresses_num.o
OBJS += ttoprotocol.o
OBJS += ttorange_num.o
OBJS += ttoranges_num.o
OBJS += ttoselector_num.o
OBJS += ttoselectors_num.o
OBJS += ttosubnet_num.o
OBJS += ttosubnets_num.o
OBJS += ttoips_num.o
OBJS += ttobool.o
OBJS += ttobinary-iec-60027-2.o
OBJS += ttoport.o
OBJS += binaryscale-iec-60027-2.o
OBJS += alloc.o
OBJS += alloc_printf.o

OBJS += diag.o
OBJS += passert.o
OBJS += pexpect.o
OBJS += nss_cert_load.o
OBJS += certs.o
OBJS += reqid.o
OBJS += keyid.o

OBJS += kernel_mode.o

ifneq ($(LINUX_VARIANT),)
OBJS += kernel_netlink_reply.o
OBJS += kernel_netlink_query.o
OBJS += linux_netlink.o
ifeq ($(USE_XFRM_INTERFACE), true)
OBJS += netlink_attrib.o
endif
endif

# implement resolve_default_route()
ifneq ($(LINUX_VARIANT),)
OBJS += resolve_default_route_linux.o
endif
ifneq ($(BSD_VARIANT),)
OBJS += resolve_default_route_bsd.o
endif

OBJS += log_ip.o
OBJS += fd.o
OBJS += message_role.o
OBJS += sa_role.o

OBJS += datatot.o

OBJS += vendorid.o

OBJS += proposals.o
OBJS += v1_proposals.o
OBJS += v2_proposals.o
OBJS += esp_info.o
OBJS += ah_info.o
OBJS += ike_info.o

OBJS += ckaid.o

OBJS += chunk.o
OBJS += shunk.o
OBJS += hunk.o

OBJS += ip_bytes.o
OBJS += ip_address.o
OBJS += ip_cidr.o
OBJS += ip_encap.o
OBJS += ip_endpoint.o
OBJS += ip_info.o
OBJS += ip_port.o
OBJS += ip_port_range.o
OBJS += ip_protocol.o
OBJS += ip_protoport.o
OBJS += ip_range.o
OBJS += ip_said.o
OBJS += ip_selector.o
OBJS += ip_sockaddr.o
OBJS += ip_subnet.o
OBJS += ip_packet.o

OBJS += lmod.o
OBJS += lset.o
OBJS += timescale.o
OBJS += deltatime.o
OBJS += realtime.o
OBJS += monotime.o
OBJS += ttodeltatime.o
OBJS += ttorealtime.o

OBJS += refcnt.o
OBJS += debug.o
OBJS += impair.o
OBJS += keywords.o

OBJS += ldbg.o
OBJS += DBG_dump.o
OBJS += DBG_log.o

OBJS += llog_base64_bytes.o
OBJS += llog_pem_bytes.o
OBJS += llog_errno.o
OBJS += log_error.o
OBJS += fatal.o
OBJS += bad_enum_where.o
OBJS += bad_case_where.o
OBJS += bad_sparse_where.o

OBJS += lswglob.o

OBJS += global_logger.o
OBJS += jambuf.o
OBJS += jam_humber.o
OBJS += jam_bytes.o
OBJS += jam_base64_bytes.o
OBJS += llog.o
OBJS += llog_dump.o
OBJS += llog_va_list.o
OBJS += log_nss_error.o
OBJS += jam_logger_rc_prefix.o
OBJS += jam_logger.o
OBJS += logjam.o

OBJS += jam_nss_cka.o
OBJS += jam_nss_ckf.o
OBJS += jam_nss_ckm.o
OBJS += jam_nss_error.o
OBJS += jam_nss_oid.o
OBJS += jam_nss_secitem.o

# Crypto code:

OBJS += test_buffer.o
OBJS += ike_alg.o
OBJS += ike_alg_dh.o
OBJS += ike_alg_hash_identity.o
OBJS += ike_alg_ipcomp.o
OBJS += ike_alg_test.o
OBJS += ike_alg_dh_nss_ecp_ops.o
OBJS += ike_alg_dh_nss_modp_ops.o
OBJS += ike_alg_hash_nss_ops.o
OBJS += ike_alg_prf_mac_hmac_ops.o
OBJS += ike_alg_prf_mac_nss_ops.o
OBJS += ike_alg_prf_mac_xcbc_ops.o
OBJS += ike_alg_prf_ikev1_mac_ops.o
OBJS += ike_alg_prf_ikev2_mac_ops.o
ifeq ($(USE_NSS_KDF),true)
OBJS += ike_alg_prf_ikev1_nss_ops.o
OBJS += ike_alg_prf_ikev2_nss_ops.o
endif
OBJS += ike_alg_encrypt_null_ops.o
OBJS += ike_alg_encrypt_chacha20_poly1305.o
OBJS += ike_alg_encrypt_nss_aead_ops.o
OBJS += ike_alg_encrypt_nss_cbc_ops.o
OBJS += ike_alg_encrypt_nss_ctr_ops.o
OBJS += ike_alg_encrypt_nss_gcm_ops.o
OBJS += ike_alg_desc.o
ifeq ($(USE_3DES),true)
OBJS += ike_alg_3des.o
endif
ifeq ($(USE_AES),true)
OBJS += ike_alg_aes.o
endif
ifeq ($(USE_CAMELLIA),true)
OBJS += ike_alg_camellia.o
endif

# used by Vendor ID
OBJS += ike_alg_hash_md5.o
ifeq ($(USE_MD5),true)
OBJS += ike_alg_md5.o
endif

OBJS += ike_alg_none.o

# used by NAT
OBJS += ike_alg_hash_sha1.o
ifeq ($(USE_SHA1),true)
OBJS += ike_alg_sha1.o
endif

# used by Cookies
OBJS += ike_alg_hash_sha2_256.o
ifeq ($(USE_SHA2),true)
OBJS += ike_alg_sha2.o
endif

OBJS += ike_alg_encrypt_cbc_test_vectors.o
OBJS += ike_alg_encrypt_ctr_test_vectors.o
OBJS += ike_alg_encrypt_gcm_test_vectors.o
OBJS += ike_alg_prf_test_vectors.o

OBJS += crypt_mac.o
OBJS += crypt_hash.o
OBJS += crypt_prf.o
OBJS += crypt_symkey.o

ifeq ($(USE_IKEv1),true)
OBJS += ikev1_prf.o
endif
OBJS += ikev2_prf.o

ifeq ($(USE_NSS_AVA_COPY),true)
OBJS += nss_copies.o
endif

ifeq ($(USE_DNSSEC),true)
OBJS += unbound.o
endif

OBJS += enum_names.o
OBJS += pluto_exit_code_names.o
OBJS += ipseckey_algorithm_type_names.o
OBJS += ipseckey_algorithm_config_names.o
ifneq ($(LINUX_VARIANT),)
OBJS += xfrm_policy_names.o
endif

OBJS += autostart_names.o

OBJS += $(abs_builddir)/version.o

#
# Build version.c using version number from git repo or mk/version.mk
#

IPSECVIDVERSION ?= $(shell echo ${IPSECVERSION} | sed 's/^\([^-]*\)-\([^-]*\)-.*/\1-\2/')

$(abs_builddir)/version.c: $(srcdir)/version.in.c $(top_srcdir)/mk/version.mk
	rm -f $@.tmp
	sed -e '/"/s/@@IPSECVERSION@@/$(subst /,_,$(IPSECVERSION))/' \
	    -e '/"/s/@IPSECVIDVERSION@/$(subst /,_,$(IPSECVIDVERSION))/' \
	    $(srcdir)/version.in.c \
	    > $@.tmp
	mv $@.tmp $@


# generate enum name checklists

ENUM_INCLUDES += $(wildcard $(top_srcdir)/include/*.h)
ENUM_INCLUDES += $(wildcard $(top_srcdir)/include/*/*.h)

OBJS += $(abs_builddir)/enum_names_checklist.o

$(abs_builddir)/enum_names_checklist.c: $(srcdir)/Makefile $(srcdir)/enum_checklist.sh $(ENUM_INCLUDES)
	rm -f $@.tmp
	$(srcdir)/enum_checklist.sh enum_names $(ENUM_INCLUDES) >$@.tmp
	mv $@.tmp $@

OBJS += $(abs_builddir)/enum_enum_names_checklist.o

$(abs_builddir)/enum_enum_names_checklist.c: $(srcdir)/Makefile $(srcdir)/enum_checklist.sh $(ENUM_INCLUDES)
	rm -f $@.tmp
	$(srcdir)/enum_checklist.sh enum_enum_names $(ENUM_INCLUDES) >$@.tmp
	mv $@.tmp $@

include $(top_srcdir)/mk/library.mk
