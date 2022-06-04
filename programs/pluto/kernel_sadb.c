/* Interface to the PF_KEY v2 IPsec mechanism, for Libreswan
 *
 * Copyright (C)  2022  Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "kernel_sadb.h"

#include "lswlog.h"
#include "ip_protocol.h"
#include "ip_sockaddr.h"
#include "ip_info.h"

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef uint64_t u64_t;

/*
 * XXX: the double macro is so that the parameters (which might be
 * defines) are expanded before being passed on.  For instance, given:
 *
 *   #define foo bar
 *   J(P, foo, F)
 *
 * will expand to:
 *
 *   J2(P, bar, F)
 */

#define J(P, T, F) J2(P, T, F)
#define J2(P, T, F) jam(buf, " "#F"=%"PRI##P, (P##_t)m->T##_##F)

#define JX(T, F) JX2(T, F)
#define JX2(T, F)							\
	{								\
		jam(buf, " "#F"=");					\
		jam_hex_bytes(buf, &m->T##_##F, sizeof(m->T##_##F));	\
	}

#define JAM_SPARSE(E, T, F)						\
	{								\
		jam(buf, " "#F"=%lu", (long unsigned)m->T##_##F);	\
		const char *name = sparse_name(E, m->T##_##F);		\
		if (name != NULL) {					\
			jam(buf, "(%s)", name);				\
		}							\
	}

#define JAM_SPARSE_SPARSE(NAMES, I0, T, F)				\
	{								\
		jam(buf, " "#F"=%lu", (long unsigned)m->T##_##F);	\
		const char *name = sparse_sparse_name(NAMES, I0, m->T##_##F); \
		if (name != NULL) {					\
			jam(buf, "(%s)", name);				\
		}							\
	}

#define JAM_SPARSE_LSET(NAMES, T, F)					\
	{								\
		jam(buf, " "#F"=%lu=", (long unsigned)m->T##_##F);	\
		jam_sparse_lset(buf, NAMES, m->T##_##F);		\
	}

#define JAM_SADB(T, F)							\
	JAM_SPARSE(sadb_##F##_names, T, F)

#define JAM_IPSEC(T, F)							\
	JAM_SPARSE(ipsec_##F##_names, T, F)

#define JAM_LEN_MULTIPLIER(T, F, LEN_MULTIPLIER)			\
	jam(buf, " "#F"=%"PRIu16"(%zu)",				\
	    m->T##_##F, m->T##_##F * LEN_MULTIPLIER)
#define JAM_LEN(T, F)					\
	JAM_LEN_MULTIPLIER(T, F, sizeof(uint64_t))

void DBG_sadb_alg(struct logger *logger,
		  enum sadb_exttype exttype,
		  const struct sadb_alg *m,
		  const char *what)
{
	char tmp[200];
	struct jambuf buf = ARRAY_AS_JAMBUF(tmp);
	jam_string(&buf, what);
	jam_sadb_alg(&buf, exttype, m);
	jambuf_to_logger(&buf, logger, DEBUG_STREAM);
}

void DBG_sadb_sa(struct logger *logger,
		 enum sadb_satype satype,
		 const struct sadb_sa *m,
		 const char *what)
{
	char tmp[200];
	struct jambuf buf = ARRAY_AS_JAMBUF(tmp);
	jam_string(&buf, what);
	jam_sadb_sa(&buf, satype, m);
	jambuf_to_logger(&buf, logger, DEBUG_STREAM);
}

#define S(E) { #E, E }

sparse_names sadb_proto_names = {
	SPARSE_NULL
};

sparse_names sadb_type_names = {
	S(SADB_RESERVED),
	S(SADB_GETSPI),
	S(SADB_UPDATE),
	S(SADB_ADD),
	S(SADB_DELETE),
	S(SADB_GET),
	S(SADB_ACQUIRE),
	S(SADB_REGISTER),
	S(SADB_EXPIRE),
	S(SADB_FLUSH),
	S(SADB_DUMP),
#ifdef SADB_X_ADDFLOW
	S(SADB_X_ADDFLOW),
#endif
#ifdef SADB_X_ASKPOLICY
	S(SADB_X_ASKPOLICY),
#endif
#ifdef SADB_X_DELFLOW
	S(SADB_X_DELFLOW),
#endif
#ifdef SADB_X_GRPSPIS
	S(SADB_X_GRPSPIS),
#endif
#ifdef SADB_X_MIGRATE
	S(SADB_X_MIGRATE),
#endif
#ifdef SADB_X_NAT_T_NEW_MAPPING
	S(SADB_X_NAT_T_NEW_MAPPING),
#endif
#ifdef SADB_X_PCHANGE
	S(SADB_X_PCHANGE),
#endif
#ifdef SADB_X_PROMISC
	S(SADB_X_PROMISC),
#endif
#ifdef SADB_X_SPDACQUIRE
	S(SADB_X_SPDACQUIRE),
#endif
#ifdef SADB_X_SPDADD
	S(SADB_X_SPDADD),
#endif
#ifdef SADB_X_SPDDELETE
	S(SADB_X_SPDDELETE),
#endif
#ifdef SADB_X_SPDDELETE2
	S(SADB_X_SPDDELETE2),
#endif
#ifdef SADB_X_SPDDUMP
	S(SADB_X_SPDDUMP),
#endif
#ifdef SADB_X_SPDEXPIRE
	S(SADB_X_SPDEXPIRE),
#endif
#ifdef SADB_X_SPDFLUSH
	S(SADB_X_SPDFLUSH),
#endif
#ifdef SADB_X_SPDGET
	S(SADB_X_SPDGET),
#endif
#ifdef SADB_X_SPDSETIDX
	S(SADB_X_SPDSETIDX),
#endif
#ifdef SADB_X_SPDUPDATE
	S(SADB_X_SPDUPDATE),
#endif
	SPARSE_NULL
};

sparse_names sadb_exttype_names = {
	S(SADB_EXT_RESERVED),
	S(SADB_EXT_SA),
	S(SADB_EXT_LIFETIME_CURRENT),
	S(SADB_EXT_LIFETIME_HARD),
	S(SADB_EXT_LIFETIME_SOFT),
	S(SADB_EXT_ADDRESS_SRC),
	S(SADB_EXT_ADDRESS_DST),
	S(SADB_EXT_ADDRESS_PROXY),
	S(SADB_EXT_KEY_AUTH),
	S(SADB_EXT_KEY_ENCRYPT),
	S(SADB_EXT_IDENTITY_SRC),
	S(SADB_EXT_IDENTITY_DST),
	S(SADB_EXT_SENSITIVITY),
	S(SADB_EXT_PROPOSAL),
	S(SADB_EXT_SUPPORTED_AUTH),
	S(SADB_EXT_SUPPORTED_ENCRYPT),
	S(SADB_EXT_SPIRANGE),
#ifdef SADB_X_EXT_COUNTER
	S(SADB_X_EXT_COUNTER),
#endif
#ifdef SADB_X_EXT_CYCSEQ
	S(SADB_X_EXT_CYCSEQ),
#endif
#ifdef SADB_X_EXT_DERIV
	S(SADB_X_EXT_DERIV),
#endif
#ifdef SADB_X_EXT_DST2
	S(SADB_X_EXT_DST2),
#endif
#ifdef SADB_X_EXT_DST_FLOW
	S(SADB_X_EXT_DST_FLOW),
#endif
#ifdef SADB_X_EXT_DST_MASK
	S(SADB_X_EXT_DST_MASK),
#endif
#ifdef SADB_X_EXT_FLOW_TYPE
	S(SADB_X_EXT_FLOW_TYPE),
#endif
#ifdef SADB_X_EXT_IV4B
	S(SADB_X_EXT_IV4B),
#endif
#ifdef SADB_X_EXT_KMPRIVATE
	S(SADB_X_EXT_KMPRIVATE),
#endif
#ifdef SADB_X_EXT_LIFETIME_LASTUSE
	S(SADB_X_EXT_LIFETIME_LASTUSE),
#endif
#ifdef SADB_X_EXT_LOCAL_AUTH
	S(SADB_X_EXT_LOCAL_AUTH),
#endif
#ifdef SADB_X_EXT_LOCAL_CREDENTIALS
	S(SADB_X_EXT_LOCAL_CREDENTIALS),
#endif
#ifdef SADB_X_EXT_MTU
	S(SADB_X_EXT_MTU),
#endif
#ifdef SADB_X_EXT_NAT_T_DPORT
	S(SADB_X_EXT_NAT_T_DPORT),
#endif
#ifdef SADB_X_EXT_NAT_T_FRAG
	S(SADB_X_EXT_NAT_T_FRAG),
#endif
#ifdef SADB_X_EXT_NAT_T_OA
	S(SADB_X_EXT_NAT_T_OA),
#endif
#ifdef SADB_X_EXT_NAT_T_OAI
	S(SADB_X_EXT_NAT_T_OAI),
#endif
#ifdef SADB_X_EXT_NAT_T_OAR
	S(SADB_X_EXT_NAT_T_OAR),
#endif
#ifdef SADB_X_EXT_NAT_T_SPORT
	S(SADB_X_EXT_NAT_T_SPORT),
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
	S(SADB_X_EXT_NAT_T_TYPE),
#endif
#ifdef SADB_X_EXT_NEW_ADDRESS_DST
	S(SADB_X_EXT_NEW_ADDRESS_DST),
#endif
#ifdef SADB_X_EXT_NEW_ADDRESS_SRC
	S(SADB_X_EXT_NEW_ADDRESS_SRC),
#endif
#ifdef SADB_X_EXT_NONE
	S(SADB_X_EXT_NONE),
#endif
#ifdef SADB_X_EXT_OLD
	S(SADB_X_EXT_OLD),
#endif
#ifdef SADB_X_EXT_PACKET
	S(SADB_X_EXT_PACKET),
#endif
#ifdef SADB_X_EXT_PMASK
	S(SADB_X_EXT_PMASK),
#endif
#ifdef SADB_X_EXT_POLICY
	S(SADB_X_EXT_POLICY),
#endif
#ifdef SADB_X_EXT_PRAND
	S(SADB_X_EXT_PRAND),
#endif
#ifdef SADB_X_EXT_PROTOCOL
	S(SADB_X_EXT_PROTOCOL),
#endif
#ifdef SADB_X_EXT_PSEQ
	S(SADB_X_EXT_PSEQ),
#endif
#ifdef SADB_X_EXT_PZERO
	S(SADB_X_EXT_PZERO),
#endif
#ifdef SADB_X_EXT_RAWCPI
	S(SADB_X_EXT_RAWCPI),
#endif
#ifdef SADB_X_EXT_RDOMAIN
	S(SADB_X_EXT_RDOMAIN),
#endif
#ifdef SADB_X_EXT_REMOTE_AUTH
	S(SADB_X_EXT_REMOTE_AUTH),
#endif
#ifdef SADB_X_EXT_REMOTE_CREDENTIALS
	S(SADB_X_EXT_REMOTE_CREDENTIALS),
#endif
#ifdef SADB_X_EXT_REPLAY
	S(SADB_X_EXT_REPLAY),
#endif
#ifdef SADB_X_EXT_SA2
	S(SADB_X_EXT_SA2),
#endif
#ifdef SADB_X_EXT_SA3
	S(SADB_X_EXT_SA3),
#endif
#ifdef SADB_X_EXT_SA_REPLAY
	S(SADB_X_EXT_SA_REPLAY),
#endif
#ifdef SADB_X_EXT_SATYPE2
	S(SADB_X_EXT_SATYPE2),
#endif
#ifdef SADB_X_EXT_SRC_FLOW
	S(SADB_X_EXT_SRC_FLOW),
#endif
#ifdef SADB_X_EXT_SRC_MASK
	S(SADB_X_EXT_SRC_MASK),
#endif
#ifdef SADB_X_EXT_SUPPORTED_COMP
	S(SADB_X_EXT_SUPPORTED_COMP),
#endif
#ifdef SADB_X_EXT_TAG
	S(SADB_X_EXT_TAG),
#endif
#ifdef SADB_X_EXT_TAG
	S(SADB_X_EXT_TAG),
#endif
#ifdef SADB_X_EXT_TAP
	S(SADB_X_EXT_TAP),
#endif
#ifdef SADB_X_EXT_UDPENCAP
	S(SADB_X_EXT_UDPENCAP),
#endif
	SPARSE_NULL
};

sparse_names sadb_satype_names = {
	S(SADB_SATYPE_UNSPEC),
	S(SADB_SATYPE_AH),
	S(SADB_SATYPE_ESP),
	S(SADB_SATYPE_RSVP),
	S(SADB_SATYPE_OSPFV2),
	S(SADB_SATYPE_RIPV2),
	S(SADB_SATYPE_MIP),
#ifdef SADB_X_SATYPE_IPCOMP
	S(SADB_X_SATYPE_IPCOMP),
#endif
#ifdef SADB_X_SATYPE_POLICY
	S(SADB_X_SATYPE_POLICY),
#endif
#ifdef SADB_X_SATYPE_TCPSIGNATURE
	S(SADB_X_SATYPE_TCPSIGNATURE),
#endif
#ifdef SADB_X_SATYPE_IPIP
	S(SADB_X_SATYPE_IPIP),
#endif
	SPARSE_NULL
};

sparse_names sadb_sastate_names = {
	S(SADB_SASTATE_LARVAL),
	S(SADB_SASTATE_MATURE),
	S(SADB_SASTATE_DYING),
	S(SADB_SASTATE_DEAD),
	SPARSE_NULL
};

sparse_names sadb_saflag_names = {
	S(SADB_SAFLAGS_PFS),
#ifdef SADB_X_SAFLAGS_CHAINDEL
	S(SADB_X_SAFLAGS_CHAINDEL),
#endif
#ifdef SADB_X_SAFLAGS_ESN
	S(SADB_X_SAFLAGS_ESN),
#endif
#ifdef SADB_X_SAFLAGS_TUNNEL
	S(SADB_X_SAFLAGS_TUNNEL),
#endif
#ifdef SADB_X_SAFLAGS_UDPENCAP
	S(SADB_X_SAFLAGS_UDPENCAP),
#endif
	SPARSE_NULL
};

sparse_names sadb_policyflag_names = {
#ifdef SADB_X_POLICYFLAGS_POLICY
	S(SADB_X_POLICYFLAGS_POLICY), /* OpenBSD */
#endif
	SPARSE_NULL
};

sparse_names sadb_aalg_names = {
	S(SADB_AALG_NONE),
	S(SADB_AALG_MD5HMAC),
	S(SADB_AALG_SHA1HMAC),
#ifdef SADB_X_AALG_SHA2_256
	S(SADB_X_AALG_SHA2_256),
#endif
#ifdef SADB_X_AALG_SHA2_384
	S(SADB_X_AALG_SHA2_384),
#endif
#ifdef SADB_X_AALG_SHA2_512
	S(SADB_X_AALG_SHA2_512),
#endif
#ifdef SADB_X_AALG_RIPEMD160HMAC
	S(SADB_X_AALG_RIPEMD160HMAC),
#endif
#ifdef SADB_X_AALG_AES_XCBC_MAC
	S(SADB_X_AALG_AES_XCBC_MAC),
#endif
#ifdef SADB_X_AALG_AES128GMAC
	S(SADB_X_AALG_AES128GMAC),
#endif
#ifdef SADB_X_AALG_AES192GMAC
	S(SADB_X_AALG_AES192GMAC),
#endif
#ifdef SADB_X_AALG_AES256GMAC
	S(SADB_X_AALG_AES256GMAC),
#endif
#ifdef SADB_X_AALG_MD5
	S(SADB_X_AALG_MD5),
#endif
#ifdef SADB_X_AALG_SHA
	S(SADB_X_AALG_SHA),
#endif
#ifdef SADB_X_AALG_NULL
	S(SADB_X_AALG_NULL),
#endif
#ifdef SADB_X_AALG_TCP_MD5
	S(SADB_X_AALG_TCP_MD5),
#endif
#ifdef SADB_X_AALG_CHACHA20POLY1305
	S(SADB_X_AALG_CHACHA20POLY1305),
#endif
	SPARSE_NULL
};

sparse_names sadb_calg_names = {
#ifdef SADB_X_CALG_NONE
	S(SADB_X_CALG_NONE),
#endif
#ifdef SADB_X_CALG_OUI
	S(SADB_X_CALG_OUI),
#endif
#ifdef SADB_X_CALG_DEFLATE
	S(SADB_X_CALG_DEFLATE),
#endif
#ifdef SADB_X_CALG_LZS
	S(SADB_X_CALG_LZS),
#endif
#ifdef SADB_X_CALG_LZJH
	S(SADB_X_CALG_LZJH),
#endif
	SPARSE_NULL
};

sparse_names sadb_ealg_names = {
	S(SADB_EALG_NULL),
#ifdef SADB_EALG_DESCBC
	S(SADB_EALG_DESCBC),
#endif
	S(SADB_EALG_3DESCBC),
	S(SADB_EALG_NULL),
#ifdef SADB_X_EALG_BLF
	S(SADB_X_EALG_BLF),
#endif
#ifdef SADB_X_EALG_CHACHA20POLY1305
	S(SADB_X_EALG_CHACHA20POLY1305),
#endif
#ifdef SADB_X_EALG_CAST
	S(SADB_X_EALG_CAST),
#endif
#ifdef SADB_X_EALG_CAST128CBC
	S(SADB_X_EALG_CAST128CBC),
#endif
#ifdef SADB_X_EALG_BLOWFISHCBC
	S(SADB_X_EALG_BLOWFISHCBC),
#endif
#ifdef SADB_X_EALG_RIJNDAELCBC
	S(SADB_X_EALG_RIJNDAELCBC),
#endif
#ifdef SADB_X_EALG_AES
	S(SADB_X_EALG_AES),
#endif
#ifdef SADB_X_EALG_AESCTR
	S(SADB_X_EALG_AESCTR),
#endif
#ifdef SADB_X_EALG_AESGCM8
	S(SADB_X_EALG_AESGCM8),
#endif
#ifdef SADB_X_EALG_AESGCM12
	S(SADB_X_EALG_AESGCM12),
#endif
#ifdef SADB_X_EALG_AESGCM16
	S(SADB_X_EALG_AESGCM16),
#endif
#ifdef SADB_X_EALG_CAMELLIACBC
	S(SADB_X_EALG_CAMELLIACBC),
#endif
#ifdef SADB_X_EALG_AESGMAC
	S(SADB_X_EALG_AESGMAC),
#endif
#ifdef SADB_X_EALG_SKIPJACK
	S(SADB_X_EALG_SKIPJACK),
#endif
#ifdef SADB_X_EALG_AESCBC
	S(SADB_X_EALG_AESCBC),
#endif
	SPARSE_NULL
};

sparse_names sadb_identtype_names = {
	S(SADB_IDENTTYPE_RESERVED),
	S(SADB_IDENTTYPE_PREFIX),
	S(SADB_IDENTTYPE_FQDN),
	S(SADB_IDENTTYPE_USERFQDN),
#ifdef SADB_IDENTTYPE_ASN1_DN
	S(SADB_IDENTTYPE_ASN1_DN), /* OpenBSD SNAFU */
#endif
#ifdef SADB_X_IDENTTYPE_ADDR
	S(SADB_X_IDENTTYPE_ADDR),
#endif
	SPARSE_NULL
};

sparse_names sadb_flow_type_names = {
#ifdef SADB_X_FLOW_TYPE_ACQUIRE
	S(SADB_X_FLOW_TYPE_ACQUIRE),
#endif
#ifdef SADB_X_FLOW_TYPE_BYPASS
	S(SADB_X_FLOW_TYPE_BYPASS),
#endif
#ifdef SADB_X_FLOW_TYPE_DENY
	S(SADB_X_FLOW_TYPE_DENY),
#endif
#ifdef SADB_X_FLOW_TYPE_DONTACQ
	S(SADB_X_FLOW_TYPE_DONTACQ),
#endif
#ifdef SADB_X_FLOW_TYPE_REQUIRE
	S(SADB_X_FLOW_TYPE_REQUIRE),
#endif
#ifdef SADB_X_FLOW_TYPE_USE
	S(SADB_X_FLOW_TYPE_USE),
#endif
	SPARSE_NULL
};

sparse_names sadb_lifetime_names = {
#ifdef SADB_X_LIFETIME_ADDTIME
	S(SADB_X_LIFETIME_ADDTIME),
#endif
#ifdef SADB_X_LIFETIME_ALLOCATIONS
	S(SADB_X_LIFETIME_ALLOCATIONS),
#endif
#ifdef SADB_X_LIFETIME_BYTES
	S(SADB_X_LIFETIME_BYTES),
#endif
#ifdef SADB_X_LIFETIME_USETIME
	S(SADB_X_LIFETIME_USETIME),
#endif
	SPARSE_NULL
};

sparse_sparse_names sadb_alg_names = {
	{ sadb_ext_supported_auth, sadb_aalg_names, },
	{ sadb_ext_supported_encrypt, sadb_ealg_names, },
	{ 0, NULL, },
};

sparse_sparse_names sadb_satype_ealg_names = {
	{ sadb_satype_esp, sadb_ealg_names, },
	{ sadb_x_satype_ipcomp, sadb_calg_names, },
	{ 0, NULL, }
};

sparse_sparse_names sadb_satype_aalg_names = {
	{ sadb_satype_esp, sadb_aalg_names, },
	{ sadb_satype_ah, sadb_aalg_names, },
	{ 0, NULL, }
};

#ifdef SADB_X_EXT_POLICY
sparse_names ipsec_policy_names = {
	S(IPSEC_POLICY_DISCARD),
	S(IPSEC_POLICY_NONE),
	S(IPSEC_POLICY_IPSEC),
	S(IPSEC_POLICY_ENTRUST),
	S(IPSEC_POLICY_BYPASS),
	SPARSE_NULL
};
#endif

#ifdef SADB_X_EXT_POLICY
sparse_names ipsec_dir_names = {
	S(IPSEC_DIR_ANY),
	S(IPSEC_DIR_INBOUND),
	S(IPSEC_DIR_OUTBOUND),
	S(IPSEC_DIR_MAX),
	S(IPSEC_DIR_INVALID),
	SPARSE_NULL
};
#endif

#ifdef SADB_X_EXT_POLICY
sparse_names ipsec_mode_names = {
	{ "any!?!", ipsec_mode_any, },
	S(IPSEC_MODE_TRANSPORT),
	S(IPSEC_MODE_TUNNEL),
	SPARSE_NULL
};
#endif

sparse_names ipsec_level_names = {
	S(IPSEC_LEVEL_REQUIRE),
	SPARSE_NULL
};

sparse_names ipsec_proto_names = {
	S(IPPROTO_AH),
	S(IPPROTO_ESP),
	S(IPPROTO_IPIP),
#ifdef IPSEC_PROTO_ANY
	S(IPSEC_PROTO_ANY), /* 255, aka IPSEC_ULPROTO_ANY */
#endif
#ifdef IPPROTO_IPCOMP
	S(IPPROTO_IPCOMP),
#endif
#ifdef IPPROTO_COMP
	S(IPPROTO_COMP),
#endif
	SPARSE_NULL
};


void jam_sadb_address(struct jambuf *buf, const struct sadb_address *m)
{
	jam(buf, "sadb_address @%p:", m);
	JAM_LEN(sadb_address, len);
	JAM_SADB(sadb_address, exttype);
#ifdef __OpenBSD__
	JX(sadb_address, reserved);
#else
	JAM_SADB(sadb_address, proto);
	J(u8, sadb_address, prefixlen);
#endif
}

void jam_sadb_alg(struct jambuf *buf, enum sadb_exttype exttype, const struct sadb_alg *m)
{
	jam(buf, "sadb_alg @%p", m);
	JAM_SPARSE_SPARSE(sadb_alg_names, exttype, sadb_alg, id);
	J(u8, sadb_alg, ivlen);
	J(u16, sadb_alg, minbits);
	J(u16, sadb_alg, maxbits);
	JX(sadb_alg, reserved);
}

void jam_sadb_comb(struct jambuf *buf, const struct sadb_comb *m)
{
	jam(buf, "sadb_comb @%p", m);
	JAM_SPARSE(sadb_aalg_names, sadb_comb, auth);
	JAM_SPARSE(sadb_ealg_names, sadb_comb, encrypt);
	J(u16, sadb_comb, flags);
	J(u16, sadb_comb, auth_minbits);
	J(u16, sadb_comb, auth_maxbits);
	J(u16, sadb_comb, encrypt_minbits);
	J(u16, sadb_comb, encrypt_maxbits);
	JX(sadb_comb, reserved);
	J(u32, sadb_comb, soft_allocations);
	J(u32, sadb_comb, hard_allocations);
	J(u64, sadb_comb, soft_bytes);
	J(u64, sadb_comb, hard_bytes);
	J(u64, sadb_comb, soft_addtime);
	J(u64, sadb_comb, hard_addtime);
	J(u64, sadb_comb, soft_usetime);
	J(u64, sadb_comb, hard_usetime);
}

void jam_sadb_ext(struct jambuf *buf, const struct sadb_ext *m)
{
	jam(buf, "sadb_ext @%p", m);
	JAM_LEN(sadb_ext, len);
	JAM_SPARSE(sadb_exttype_names, sadb_ext, type);
}

void jam_sadb_ident(struct jambuf *buf, const struct sadb_ident *m)
{
	jam(buf, "sadb_ident @%p", m);
	JAM_LEN(sadb_ident, len);
	JAM_SADB(sadb_ident, exttype);
	J(u16, sadb_ident, type);
	JX(sadb_ident, reserved);
	J(u64, sadb_ident, id);
}

void jam_sadb_key(struct jambuf *buf, const struct sadb_key *m)
{
	jam(buf, "sadb_key @%p", m);
	JAM_LEN(sadb_key, len);
	JAM_SADB(sadb_key, exttype);
	J(u16, sadb_key, bits);
	JX(sadb_key, reserved);
}

void jam_sadb_lifetime(struct jambuf *buf, const struct sadb_lifetime *m)
{
	jam(buf, "sadb_lifetime @%p:", m);
	JAM_LEN(sadb_lifetime, len);
	JAM_SADB(sadb_lifetime, exttype);
	J(u32, sadb_lifetime, allocations);
	J(u64, sadb_lifetime, bytes);
	J(u64, sadb_lifetime, addtime);
	J(u64, sadb_lifetime, usetime);
}

void jam_sadb_msg(struct jambuf *buf, const struct sadb_msg *m)
{
	jam(buf, "sadb_msg @%p:", m);
	J(u8, sadb_msg, version);
	JAM_SADB(sadb_msg, type);
	J(u8, sadb_msg, errno);
	JAM_SADB(sadb_msg, satype);
	JAM_LEN(sadb_msg, len);
	JX(sadb_msg, reserved);
	J(u32, sadb_msg, seq);
	J(u32, sadb_msg, pid);
}

void jam_sadb_prop(struct jambuf *buf, const struct sadb_prop *m)
{
	jam(buf, "sadb_prop @%p", m);
	JAM_LEN(sadb_prop, len);
	JAM_SADB(sadb_prop, exttype);
#ifdef sadb_prop_num
	J(u8, sadb_prop, num);
#endif
	J(u8, sadb_prop, replay);
	JX(sadb_prop, reserved);
}

void jam_sadb_sa(struct jambuf *buf, enum sadb_satype satype, const struct sadb_sa *m)
{
	jam(buf, "sadb_sa @%p:", m);
	JAM_LEN(sadb_sa, len);
	JAM_SADB(sadb_sa, exttype);
	jam(buf, " spi=%u(%x)", ntohl(m->sadb_sa_spi), ntohl(m->sadb_sa_spi));
	J(u8, sadb_sa, replay);
	JAM_SPARSE(sadb_sastate_names, sadb_sa, state);
	JAM_SPARSE_SPARSE(sadb_satype_aalg_names, satype, sadb_sa, auth);
	JAM_SPARSE_SPARSE(sadb_satype_ealg_names, satype, sadb_sa, encrypt);
	JAM_SPARSE_LSET(sadb_saflag_names, sadb_sa, flags);
}

void jam_sadb_sens(struct jambuf *buf, const struct sadb_sens *m)
{
	jam(buf, "sadb_sens @%p", m);
	JAM_LEN(sadb_sens, len);
	JAM_SADB(sadb_sens, exttype);
	J(u32, sadb_sens, dpd);
	J(u8, sadb_sens, sens_level);
	J(u8, sadb_sens, sens_len);
	J(u8, sadb_sens, integ_level);
	J(u8, sadb_sens, integ_len);
	JX(sadb_sens, reserved);
}

void jam_sadb_spirange(struct jambuf *buf, const struct sadb_spirange *m)
{
	jam(buf, "sadb_spirange @%p", m);
	JAM_LEN(sadb_spirange, len);
	JAM_SADB(sadb_spirange, exttype);
	J(u32, sadb_spirange, min);
	J(u32, sadb_spirange, max);
	JX(sadb_spirange, reserved);
}

void jam_sadb_supported(struct jambuf *buf, const struct sadb_supported *m)
{
	jam(buf, "sadb_supported @%p", m);
	JAM_LEN(sadb_supported, len);
	JAM_SADB(sadb_supported, exttype);
	JX(sadb_supported, reserved);
}

#ifdef SADB_X_EXT_POLICY
void jam_sadb_x_ipsecrequest(struct jambuf *buf, const struct sadb_x_ipsecrequest *m)
{
	jam(buf, "sadb_x_ipsecrequest @%p", m);
	JAM_LEN_MULTIPLIER(sadb_x_ipsecrequest, len, sizeof(uint8_t)); /* XXX: screwup */
	JAM_IPSEC(sadb_x_ipsecrequest, proto);
	JAM_IPSEC(sadb_x_ipsecrequest, mode);
	JAM_IPSEC(sadb_x_ipsecrequest, level);
#ifdef sadb_x_ipsecrequest_reserved1
	J(u16, sadb_x_ipsecrequest, reserved1);
#endif
	J(u16, sadb_x_ipsecrequest, reqid);
#ifdef sadb_x_ipsecrequest_reserved1
	J(u16, sadb_x_ipsecrequest, reserved2);
#endif
}
#endif

#ifdef SADB_X_EXT_NAT_T_FRAG
void jam_sadb_x_nat_t_frag(struct jambuf *buf, const struct sadb_x_nat_t_frag *m)
{
	jam(buf, "sadb_x_nat_t_frag @%p", m);
	JAM_LEN(sadb_x_nat_t_frag, len);
	JAM_SADB(sadb_x_nat_t_frag, exttype);
	J(u16, sadb_x_nat_t_frag, fraglen);
	JX(sadb_x_nat_t_frag, reserved);
}
#endif

#ifdef SADB_X_EXT_NAT_T_PORT
void jam_sadb_x_nat_t_port(struct jambuf *buf, const struct sadb_x_nat_t_port *m)
{
	jam(buf, "sadb_x_nat_t_port @%p", m);
	JAM_LEN(sadb_x_nat_t_port, len);
	JAM_SADB(sadb_x_nat_t_port, exttype);
	J(u16, sadb_x_nat_t_port, port);
	JX(sadb_x_nat_t_port, reserved);
}
#endif

#ifdef SADB_X_EXT_NAT_T_TYPE
void jam_sadb_x_nat_t_type(struct jambuf *buf, const struct sadb_x_nat_t_type *m)
{
	jam(buf, "sadb_x_nat_t_type @%p", m);
	JAM_LEN(sadb_x_nat_t_type, len);
	JAM_SADB(sadb_x_nat_t_type, exttype);
	J(u8, sadb_x_nat_t_type, type);
	JX(sadb_x_nat_t_type, reserved);
}
#endif

#ifdef SADB_X_EXT_POLICY
void jam_sadb_x_policy(struct jambuf *buf, const struct sadb_x_policy *m)
{
	jam(buf, "sadb_x_policy @%p:", m);
	JAM_LEN(sadb_x_policy, len);
	JAM_SADB(sadb_x_policy, exttype);
	JAM_SPARSE(ipsec_policy_names, sadb_x_policy, type); /* POLICY <> TYPE */
	/* XXX: broken; needs sparse_sparse_names; */
	JAM_IPSEC(sadb_x_policy, dir);
#ifdef sadb_x_policy_scope
	J(u8, sadb_x_policy, scope);
#else
	JX(sadb_x_policy, reserved);
#endif
	J(u32, sadb_x_policy, id);
#ifdef sadb_x_policy_priority
	J(u32, sadb_x_policy, priority);
#else
	JX(sadb_x_policy, reserved2);
#endif
}
#endif

#ifdef SADB_X_EXT_SA2
void jam_sadb_x_sa2(struct jambuf *buf, const struct sadb_x_sa2 *m)
{
	jam(buf, "sadb_x_sa2 @%p:", m);
	JAM_LEN(sadb_x_sa2, len);
	JAM_SADB(sadb_x_sa2, exttype);
	JAM_IPSEC(sadb_x_sa2, mode);
	J(u8,  sadb_x_sa2, reserved1);
	J(u16, sadb_x_sa2, reserved2);
	J(u32, sadb_x_sa2, sequence);
	J(u32, sadb_x_sa2, reqid);
}
#endif

#ifdef SADB_X_EXT_SA_REPLAY
void jam_sadb_x_sa_replay(struct jambuf *buf, const struct sadb_x_sa_replay *m)
{
	jam(buf, "sadb_x_sa_replay @%p:", m);
	JAM_LEN(sadb_x_sa_replay, len);
	JAM_SADB(sadb_x_sa_replay, exttype);
	J(u32, sadb_x_sa_replay, replay);
}
#endif

bool get_sadb_sockaddr_address_port(shunk_t *cursor,
				    ip_address *address,
				    ip_port *port,
				    struct logger *logger)
{
	err_t err = sockaddr_to_address_port(cursor->ptr, cursor->len,
					     address, port);
	if (err != NULL) {
		llog_pexpect(logger, HERE, "invalid sockaddr: %s", err);
		return false;
	}
	const struct ip_info *afi = address_type(address);
	cursor->ptr += afi->sockaddr_size;
	cursor->len -= afi->sockaddr_size;
	return true;
}

void DBG_msg(struct logger *logger, const void *ptr, size_t len, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	DBG_va_list(fmt, ap);
	va_end(ap);

	shunk_t msg_cursor = shunk2(ptr, len);

	shunk_t base_cursor;
	const struct sadb_msg *base = get_sadb_msg(&msg_cursor, &base_cursor, logger);
	if (base == NULL) {
		llog_passert(logger, HERE, "wrong base");
	}

	DBG_sadb_msg(logger, base, " ");

	while (base_cursor.len > 0) {

		shunk_t ext_cursor; /* includes SADB_EXT */
		const struct sadb_ext *ext =
			get_sadb_ext(&base_cursor, &ext_cursor, logger);
		if (ext == NULL) {
			llog_passert(logger, HERE, "bad ext");
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {

		case sadb_ext_address_src:
		case sadb_ext_address_dst:
		{
			shunk_t address_cursor;
			const struct sadb_address *address =
				get_sadb_address(&ext_cursor, &address_cursor, logger);
			if (address == NULL) {
				return;
			}
			DBG_sadb_address(logger, address, "  ");
			ip_address addr;
			ip_port port;
			if (!get_sadb_sockaddr_address_port(&address_cursor, &addr, &port, logger)) {
				return;
			}
			address_buf ab;
			port_buf pb;
			DBG_log("    %s:%s", str_address_wrapped(&addr, &ab), str_hport(port, &pb));
			/* no PEXPECT(logger, address_cursor.len == 0); may be padded */
			break;
		}

		case sadb_ext_key_encrypt:
		case sadb_ext_key_auth:
		{
			shunk_t key_cursor;
			const struct sadb_key *key =
				get_sadb_key(&ext_cursor, &key_cursor, logger);
			if (key == NULL) {
				return;
			}
			DBG_sadb_key(logger, key, "  ");
			LDBGP(logger, DBG_CRYPT, buf) {
				jam(buf, "   ");
				jam_dump_hunk(buf, key_cursor);
			}
			/* no PEXPECT(logger, address_cursor.len == 0); allow any length+padding */
			break;
		}

		case sadb_ext_lifetime_soft:
		case sadb_ext_lifetime_hard:
		case sadb_ext_lifetime_current:
		{
			shunk_t lifetime_cursor;
			const struct sadb_lifetime *lifetime =
				get_sadb_lifetime(&ext_cursor, &lifetime_cursor, logger);
			if (lifetime == NULL) {
				return;
			}
			DBG_sadb_lifetime(logger, lifetime, "  ");
			PEXPECT(logger, lifetime_cursor.len == 0); /* nothing following */
			break;
		}

		case sadb_ext_proposal:
		{
			shunk_t prop_cursor;
			const struct sadb_prop *prop =
				get_sadb_prop(&ext_cursor, &prop_cursor, logger);
			if (prop == NULL) {
				return;
			}
			DBG_sadb_prop(logger, prop, "  ");

			unsigned nr_comb = 0;
			while (prop_cursor.len > 0) {
				const struct sadb_comb *comb =
					hunk_get_thing(&prop_cursor, const struct sadb_comb);
				if (comb == NULL) {
					break;
				}
				nr_comb++;
				DBG_sadb_comb(logger, comb, "   ");
			}
			PEXPECT(logger, prop_cursor.len == 0); /* nothing left */
			/* from the RFC */
			PEXPECT(logger,
				nr_comb == ((prop->sadb_prop_len * sizeof(uint64_t) -
					     sizeof(struct sadb_prop)) /
					    sizeof(struct sadb_comb)));
			break;
		}

		case sadb_ext_sa:
		{
			shunk_t sa_cursor;
			const struct sadb_sa *sa =
				get_sadb_sa(&ext_cursor, &sa_cursor, logger);
			if (sa == NULL) {
				return;
			}
			DBG_sadb_sa(logger, base->sadb_msg_satype, sa, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}

		case sadb_ext_spirange:
		{
			shunk_t spirange_cursor;
			const struct sadb_spirange *spirange =
				get_sadb_spirange(&ext_cursor, &spirange_cursor, logger);
			if (spirange == NULL) {
				return;
			}
			DBG_sadb_spirange(logger, spirange, "  ");
			PEXPECT(logger, spirange_cursor.len == 0); /* nothing following */
			break;
		}

		case sadb_ext_supported_auth:
		case sadb_ext_supported_encrypt:
		{
			shunk_t supported_cursor;
			const struct sadb_supported *supported =
				get_sadb_supported(&ext_cursor, &supported_cursor, logger);
			if (supported == NULL) {
				return;
			}
			DBG_sadb_supported(logger, supported, "  ");

			unsigned nr_algs = 0;
			while (supported_cursor.len > 0) {
				const struct sadb_alg *alg =
					hunk_get_thing(&supported_cursor, const struct sadb_alg);
				if (alg == NULL) {
					break;
				}
				nr_algs++;
				DBG_sadb_alg(logger, exttype, alg, "   ");
			}
			PEXPECT(logger, supported_cursor.len == 0); /* nothing left */
			/* from the RFC */
			PEXPECT(logger,
				nr_algs == ((supported->sadb_supported_len * sizeof(uint64_t) -
					     sizeof(struct sadb_supported)) / sizeof(struct sadb_alg)));
			break;
		}

#ifdef SADB_X_EXT_POLICY
		case sadb_x_ext_policy:
		{
			shunk_t x_policy_cursor;
			const struct sadb_x_policy *x_policy =
				get_sadb_x_policy(&ext_cursor, &x_policy_cursor, logger);
			if (x_policy == NULL) {
				return;
			}
			DBG_sadb_x_policy(logger, x_policy, "  ");

			while (x_policy_cursor.len > 0) {
				shunk_t x_ipsecrequest_cursor;
				const struct sadb_x_ipsecrequest *x_ipsecrequest =
					get_sadb_x_ipsecrequest(&x_policy_cursor, &x_ipsecrequest_cursor, logger);
				if (x_ipsecrequest == NULL) {
					break;
				}
				DBG_sadb_x_ipsecrequest(logger, x_ipsecrequest, "   ");
				while (x_ipsecrequest_cursor.len > 0) {
					/* can't assume sockaddr is aligned */
					ip_address address;
					ip_port port;
					if (!get_sadb_sockaddr_address_port(&x_ipsecrequest_cursor,
									    &address, &port, logger)) {
						break;
					}
					address_buf ab;
					port_buf pb;
					DBG_log("     %s:%s", str_address_wrapped(&address, &ab), str_hport(port, &pb));
				}
			}
			PEXPECT(logger, ext_cursor.len == 0);
			break;
		}
#endif

#ifdef SADB_X_EXT_NAT_T_TYPE
		case sadb_x_ext_nat_t_type:
		{
			shunk_t x_nat_t_type_cursor;
			const struct sadb_x_nat_t_type *x_nat_t_type =
				get_sadb_x_nat_t_type(&ext_cursor, &x_nat_t_type_cursor, logger);
			if (x_nat_t_type == NULL) {
				return;
			}
			DBG_sadb_x_nat_t_type(logger, x_nat_t_type, "  ");
			PEXPECT(logger, x_nat_t_type_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_SA2
		case sadb_x_ext_sa2:
		{
			shunk_t x_sa2_cursor;
			const struct sadb_x_sa2 *x_sa2 =
				get_sadb_x_sa2(&ext_cursor, &x_sa2_cursor, logger);
			if (x_sa2 == NULL) {
				return;
			}
			DBG_sadb_x_sa2(logger, x_sa2, "  ");
			PEXPECT(logger, x_sa2_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_SA_REPLAY
		case sadb_x_ext_sa_replay:
		{
			shunk_t sa_cursor;
			const struct sadb_x_sa_replay *x_sa_replay =
				get_sadb_x_sa_replay(&ext_cursor, &sa_cursor, logger);
			if (x_sa_replay == NULL) {
				return;
			}
			DBG_sadb_x_sa_replay(logger, x_sa_replay, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

		default:
		{
			LLOG_JAMBUF(ERROR_FLAGS, logger, buf) {
				jam_string(buf, "EXPECTATION FAILED: unexpected payload: ");
				jam_logger_prefix(buf, logger);
				jam_sadb_ext(buf, ext);
				jam(buf, " "PRI_WHERE, pri_where(HERE));
			}
			break;
		}
		}
	}
}

const struct sadb_ext *get_sadb_ext(shunk_t *msgbase,
				    shunk_t *msgext,
				    struct logger *logger)
{
	shunk_t tmp = *msgbase;
	const struct sadb_ext *ext =
		hunk_get_thing(&tmp, const struct sadb_ext);
	PASSERT(logger, ext != NULL);

	size_t len = ext->sadb_ext_len * sizeof(uint64_t);
	if (len == 0) {
		llog_passert(logger, HERE, "have zero bytes");
	}
	if (msgbase->len < len) {
		llog_passert(logger, HERE, "have %zu bytes but should be %zu",
			     msgbase->len, len);
	}

	/* note: include EXT read above; will re-read */
	*msgext = shunk2(msgbase->ptr, len);

	/* then advance */
	msgbase->ptr += len;
	msgbase->len -= len;

	return ext;
}

/*
 * XXX: the x_ipsecrequest extension messed up the convention by
 * storing the nr-bytes in len.  Hence LEN_MULTIPLIER.
 */

#define GET_SADB(TYPE, LEN_MULTIPLIER) X_GET_SADB(TYPE, LEN_MULTIPLIER)
#define X_GET_SADB(TYPE, LEN_MULTIPLIER)				\
	const struct TYPE *get_##TYPE(shunk_t *cursor,			\
				      shunk_t *type_cursor,		\
				      struct logger *logger)		\
	{								\
		*type_cursor = null_shunk;				\
		if (sizeof(struct TYPE) > cursor->len) {		\
			llog_pexpect(logger, HERE,			\
				     "%zu-byte buffer too small for %zu-byte "#TYPE, \
				     cursor->len, sizeof(struct TYPE));	\
			return NULL;					\
		}							\
		/* SADB stream is aligned */				\
		const struct TYPE *type = cursor->ptr;			\
		size_t type_len = type->TYPE##_len * LEN_MULTIPLIER;	\
		if (type_len < sizeof(struct TYPE)) {			\
			llog_pexpect(logger, HERE,			\
				     "%zu-byte "#TYPE" bigger than "#TYPE"_len=%u(%zu-bytes)", \
				     sizeof(struct TYPE), type->TYPE##_len, type_len); \
			return NULL;					\
		}							\
		if (type_len > (cursor)->len) {				\
			llog_pexpect(logger, HERE,			\
				     "%zu-byte buffer too small for "#TYPE"_len=%u(%zu-bytes)", \
				     cursor->len, type->TYPE##_len, type_len); \
			return NULL;					\
		}							\
		/* type_cursor */					\
		(type_cursor)->ptr = (cursor)->ptr + sizeof(struct TYPE); \
		(type_cursor)->len = type_len - sizeof(struct TYPE);	\
		/* now skip to next field */				\
		(cursor)->ptr += type_len;				\
		(cursor)->len -= type_len;				\
		return type;						\
	}

GET_SADB(sadb_address, sizeof(uint64_t));
GET_SADB(sadb_key, sizeof(uint64_t));
GET_SADB(sadb_lifetime, sizeof(uint64_t));
GET_SADB(sadb_msg, sizeof(uint64_t));
GET_SADB(sadb_prop, sizeof(uint64_t));
GET_SADB(sadb_sa, sizeof(uint64_t));
GET_SADB(sadb_spirange, sizeof(uint64_t));
GET_SADB(sadb_supported, sizeof(uint64_t));
#ifdef SADB_X_EXT_POLICY
GET_SADB(sadb_x_ipsecrequest, sizeof(uint8_t)); /* XXX: see rfc, screwup */
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
GET_SADB(sadb_x_nat_t_type, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_POLICY
GET_SADB(sadb_x_policy, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_SA2
GET_SADB(sadb_x_sa2, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_SA_REPLAY
GET_SADB(sadb_x_sa_replay, sizeof(uint64_t));
#endif

#define DD(TYPE, ...)						\
	void DBG_##TYPE(struct logger *logger,			\
			const struct TYPE *m,			\
			const char *what)			\
	{							\
		char tmp[200];					\
		struct jambuf buf = ARRAY_AS_JAMBUF(tmp);	\
		jam_string(&buf, what);				\
		jam_##TYPE(&buf, m);				\
		jambuf_to_logger(&buf, logger, DEBUG_STREAM);	\
	}							\
								\
	void ldbg_##TYPE(struct logger *logger,			\
			 const struct TYPE *m,			\
			 const char *what)			\
	{							\
		if (DBGP(DBG_BASE)) {				\
			DBG_##TYPE(logger, m, what);		\
		}						\
	}

DD(sadb_address);
DD(sadb_comb);
DD(sadb_ext);
DD(sadb_key);
DD(sadb_lifetime);
DD(sadb_msg);
DD(sadb_prop);
DD(sadb_spirange);
DD(sadb_supported);
#ifdef SADB_X_EXT_POLICY
DD(sadb_x_ipsecrequest);
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
DD(sadb_x_nat_t_type);
#endif
#ifdef SADB_X_EXT_POLICY
DD(sadb_x_policy);
#endif
#ifdef SADB_X_EXT_SA2
DD(sadb_x_sa2);
#endif
#ifdef SADB_X_EXT_SA_REPLAY
DD(sadb_x_sa_replay)
#endif

#undef DD
