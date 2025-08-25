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

include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

LIB = libswan.a

OBJS += x509dn.o asn1.o oid.o

OBJS += authby.o
OBJS += rnd.o

OBJS += ddos_mode_names.o
OBJS += connection_kind_names.o
OBJS += option_names.o
OBJS += encap_type_names.o
OBJS += encap_mode_names.o
OBJS += encap_proto_names.o
OBJS += initiated_by_names.o
OBJS += ocsp_method_names.o
OBJS += connection_owner_names.o
OBJS += sa_kind_names.o
OBJS += keyword_host_names.o
OBJS += shunt_names.o
OBJS += global_redirect_names.o
OBJS += send_ca_policy_names.o
OBJS += sendcert_policy_names.o
OBJS += xauthby_names.o
OBJS += xauthfail_names.o

OBJS += fips_mode.o
OBJS += fips_mode_names.o
OBJS += state_category_names.o
OBJS += end_names.o
OBJS += terminate_reason_names.o

OBJS += constants.o \
	id.o \
	lex.o \
	sameaddr.o \
	ttodata.o \
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
OBJS += ttobool.o
OBJS += ttocidr_num.o
OBJS += ttoips_num.o
OBJS += ttoport.o
OBJS += ttoprotocol.o
OBJS += ttoprotoport.o
OBJS += ttorange_num.o
OBJS += ttoranges_num.o
OBJS += ttoselector_num.o
OBJS += ttoselectors_num.o
OBJS += ttosubnet_num.o
OBJS += ttosubnets_num.o

OBJS += binaryscale-iec-60027-2.o
OBJS += alloc.o
OBJS += alloc_printf.o
OBJS += pem.o
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

OBJS += ip_address.o
OBJS += ip_base.o
OBJS += ip_bytes.o
OBJS += ip_cidr.o
OBJS += ip_encap.o
OBJS += ip_endpoint.o
OBJS += ip_info.o
OBJS += ip_packet.o
OBJS += ip_port.o
OBJS += ip_port_range.o
OBJS += ip_protocol.o
OBJS += ip_protoport.o
OBJS += ip_range.o
OBJS += ip_said.o
OBJS += ip_selector.o
OBJS += ip_sockaddr.o
OBJS += ip_subnet.o

OBJS += lmod.o
OBJS += lset.o
OBJS += scale.o
OBJS += timescale.o
OBJS += deltatime.o
OBJS += realtime.o
OBJS += monotime.o
OBJS += ttodeltatime.o
OBJS += ttorealtime.o

OBJS += refcnt.o
OBJS += debug.o
OBJS += impair.o

OBJS += cur_debugging.o
OBJS += ldbg.o
OBJS += cur_debugging.o

OBJS += llog_base64_bytes.o
OBJS += llog_pem_bytes.o
OBJS += log_errno.o
OBJS += fatal.o
OBJS += bad_enum_where.o
OBJS += bad_case_where.o
OBJS += bad_sparse_where.o

OBJS += lswglob.o

OBJS += optarg.o

OBJS += global_logger.o
OBJS += jambuf.o
OBJS += jam_humber.o
OBJS += jam_bytes.o
OBJS += jam_base64_bytes.o
OBJS += llog.o
OBJS += llog_dump.o
OBJS += llog_va_list.o
OBJS += log_nss_error.o
OBJS += jam_logger.o
OBJS += logjam.o

OBJS += jam_nss_cka.o
OBJS += jam_nss_ckg.o
OBJS += jam_nss_ckf.o
OBJS += jam_nss_ckm.o
OBJS += jam_nss_error.o
OBJS += jam_nss_oid.o
OBJS += jam_nss_secitem.o

# Crypto code:

OBJS += test_buffer.o
OBJS += ike_alg.o
OBJS += ike_alg_hash_identity.o
OBJS += ike_alg_ipcomp.o
OBJS += ike_alg_test.o
OBJS += ike_alg_hash_nss_ops.o
OBJS += ike_alg_kem.o
OBJS += ike_alg_kem_ecp_nss_ops.o
OBJS += ike_alg_kem_modp_nss_ops.o
ifeq ($(filter true, $(sort $(USE_ML_KEM_512) $(USE_ML_KEM_768) $(USE_ML_KEM_1024))),true)
OBJS += ike_alg_kem_ml_kem_nss_ops.o
endif
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

OBJS += crypt_cipher.o
OBJS += crypt_hash.o
OBJS += crypt_mac.o
OBJS += crypt_prf.o
OBJS += crypt_symkey.o
OBJS += crypt_kem.o

ifeq ($(USE_IKEv1),true)
OBJS += ikev1_prf.o
endif
OBJS += ikev2_prf.o

ifeq ($(USE_DNSSEC),true)
OBJS += unbound.o
endif

OBJS += names.o
OBJS += enum_names.o
OBJS += pluto_exit_code_names.o
OBJS += ipseckey_algorithm_type_names.o
OBJS += ipseckey_algorithm_config_names.o
ifneq ($(LINUX_VARIANT),)
OBJS += xfrm_policy_names.o
endif

OBJS += autostart_names.o

# always compile, won't be linked
OBJS += seccomp_mode_names.o

#
# whack stuff
#

$(OBJS): | $(builddir)/whack/
$(builddir)/%/:
	mkdir -p $@

OBJS += whack/pickle.o
OBJS += whack/send.o
OBJS += whack/aliascomp.o
OBJS += whack/whack_magic.o

whack/whack_magic.o: $(builddir)/whack/whack_magic.c

TRANSFORM_VARIABLES += -e "s/@@WHACK_MAGIC@@/$(word 1, $(shell echo $(IPSECVERSION) | cksum))/"

$(builddir)/whack/whack_magic.c: whack/whack_magic.in.c
	rm -f $@.tmp
	sed -e "s/@@WHACK_MAGIC@@/$$(echo $(IPSECVERSION) | cksum | { read s e ; echo $$s; })/" \
	    $< > $@.tmp
	mv $@.tmp $@

#
# ipsec.conf stuff
#

$(OBJS): | $(builddir)/ipsecconf/

OBJS += ipsecconf/confread.o
OBJS += ipsecconf/confwrite.o
OBJS += ipsecconf/starterwhack.o
OBJS += ipsecconf/keywords.o
OBJS += ipsecconf/interfaces.o
OBJS += ipsecconf/config_setup.o


# Avoid flex bugs:
#
# - flex 3.5.4 (centos 5) doesn't allow a space between the '-o'
#   option and the file name.
#
#   Fortunately later versions of flex seem to handle this.
#
# - flex < 2.5.35 generates an invalid extern
#
#   Use sed to strip this out.
#
# - flex on RHEL 7 generates code that provokes GCC to warn
#   about comparing a signed value with an unsigned value
#   (Combination of a new GCC and an old flex).
#
#   Adding one cast makes RHEL 6's GCC unhappy, so we add two.
#   On RHEL 6, i is int and _yybytes_len is int.
#   On RHEL 7, i is int and _yybytes_len is yy_size_t
#   On Fedora 21, i is yy_size_t and _yybytes_len is yy_size_t
#   On some architectures, yy_size_t is wider than int;
#   which makes a mixed comparison OK.
#
# - flex 2.6.0-11 and gcc 4:5.3.1-3 on debian testing (2016-06-18)
#   also warns about comparisons of different kinds, so we add a third
#   fix.
#
# - avoid sed -i which somehow causes unwritable files on fedora 20
#   with 9p filesystem mount.

LEX = flex

OBJS += ipsecconf/scanner.o

# point GMAKE at .c file on $(VPATH)
ipseconf/scanner.o: $(builddir)/ipsecconf/scanner.c

$(builddir)/ipsecconf/scanner.c: ipsecconf/scanner.lex
	: no space between -o and scratch output file
	$(LEX) -o$@ --stdout $< | sed \
		-e 's/for ( i = 0; i < _yybytes_len; ++i )$$/for ( i = 0; (yy_size_t)i < (yy_size_t)_yybytes_len; ++i )/' \
		-e '/^extern int isatty.*$$/d' \
		-e 's/if ((int) ((yy_n_chars) + number_to_move) > YY_CURRENT_BUFFER_LVALUE->yy_buf_size) {$$/if (((yy_n_chars) + number_to_move) > YY_CURRENT_BUFFER_LVALUE->yy_buf_size) {/' \
		> $@.tmp
	: install result
	mv $@.tmp $@


# Use wild card rule so that GNU Make knows that both are output from
# a single recipe.
# - sed command for workaround for older bison vs GCC warning
# - avoid sed -i which somehow causes unwritable files
#   on fedora 20 with 9p filesystem mount
# - avoid creating the target file until it is done
# - $* matches %
#
# - run bison from the builddir so that parser.tab.h defines
#   YY_YY_PARSER_TAB_H_INCLUDED and not a macro containing the
#   buildpath.  See parser-controls.h for why.

ifeq ($(USE_YACC),true)
BISON=yacc -b parser
else
BISON=bison
BISONOSFLAGS=-g --verbose
endif

OBJS += ipsecconf/parser.tab.o

# Hack to force the generated files to be built first.  Not too bad
# since all the $(OBJS) indirectly depend on the header anyway.
#
# Point GMAKE at .[hc] file on $(VPATH)
$(OBJS): $(builddir)/ipsecconf/parser.tab.h
ipsecconf/parser.tab.o: $(builddir)/ipsecconf/parser.tab.c

$(builddir)/ipsecconf/parser.tab.c: ipsecconf/parser.y
	$(BISON) ${BISONOSFLAGS} -v --defines=$(@D)/parser.tab.h -o $(@D)/parser.tab.c.tmp $<
	sed -i -e '/^#line/ s;".*parser.tab.h";"$(@D)/parser.tab.h";' $(@D)/parser.tab.h
	sed -i -e '/^#line/ s;".*parser.tab.c.tmp";"$(@D)/parser.tab.c";' $(@D)/parser.tab.c.tmp
	sed -i -e '/^ *#/ s/if YYENABLE_NLS/if defined(YYENABLE_NLS) \&\& YYENABLE_NLS/' $(@D)/parser.tab.c.tmp
	sed -i -e '/^ *#/ s/if YYLTYPE_IS_TRIVIAL/if defined(YYLTYPE_IS_TRIVIAL) \&\& YYLTYPE_IS_TRIVIAL/' $(@D)/parser.tab.c.tmp
	mv $(@D)/parser.tab.c.tmp $(@D)/parser.tab.c
$(builddir)/ipsecconf/parser.tab.h: $(builddir)/ipsecconf/parser.tab.c
	touch $@

#
# Build version.c using version number from git repo or mk/version.mk
#

OBJS += version.o
version.o: $(builddir)/version.c

IPSECVIDVERSION ?= $(shell echo ${IPSECVERSION} | sed 's/^\([^-]*\)-\([^-]*\)-.*/\1-\2/')

$(builddir)/version.c: version.in.c $(top_srcdir)/mk/version.mk
	rm -f $@.tmp
	sed -e '/"/s/@@IPSECVERSION@@/$(subst /,_,$(IPSECVERSION))/' \
	    -e '/"/s/@IPSECVIDVERSION@/$(subst /,_,$(IPSECVIDVERSION))/' \
	    $(srcdir)/version.in.c \
	    > $@.tmp
	mv $@.tmp $@

#
# generate enum name checklists
#

ENUM_INCLUDES += $(wildcard $(top_srcdir)/include/*.h)
ENUM_INCLUDES += $(wildcard $(top_srcdir)/include/*/*.h)

OBJS += enum_names_checklist.o
enum_names_checklist.o: $(builddir)/enum_names_checklist.c

$(builddir)/enum_names_checklist.c: Makefile enum_checklist.sh $(ENUM_INCLUDES)
	rm -f $@.tmp
	$(srcdir)/enum_checklist.sh enum_names $(ENUM_INCLUDES) >$@.tmp
	mv $@.tmp $@

OBJS += enum_enum_names_checklist.o
enum_enum_names_checklist.o: $(builddir)/enum_enum_names_checklist.c

$(builddir)/enum_enum_names_checklist.c: Makefile enum_checklist.sh $(ENUM_INCLUDES)
	rm -f $@.tmp
	$(srcdir)/enum_checklist.sh enum_enum_names $(ENUM_INCLUDES) >$@.tmp
	mv $@.tmp $@

include $(top_srcdir)/mk/library.mk
