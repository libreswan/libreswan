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

#define S(E) { .name = #E, .value = E, }

const struct sparse_names sadb_type_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_names sadb_exttype_names = {
        .prefix = "SADB_",
        .list = {
		S(SADB_EXT_RESERVED),
		S(SADB_EXT_SA),
		S(SADB_EXT_LIFETIME_CURRENT),
		S(SADB_EXT_LIFETIME_HARD),
		S(SADB_EXT_LIFETIME_SOFT),
#ifdef SADB_X_EXT_LIFETIME_LASTUSE
		S(SADB_X_EXT_LIFETIME_LASTUSE),
#endif
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
#ifdef SADB_X_EXT_REPLAY /* OpenBSD */
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
	},
};

const struct sparse_names sadb_satype_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_names sadb_sastate_names = {
        .prefix = "SADB_",
        .list = {
		S(SADB_SASTATE_LARVAL),
		S(SADB_SASTATE_MATURE),
		S(SADB_SASTATE_DYING),
		S(SADB_SASTATE_DEAD),
		SPARSE_NULL
	},
};

const struct sparse_names sadb_saflag_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_names sadb_policyflag_names = {
        .prefix = "SADB_",
        .list = {
#ifdef SADB_X_POLICYFLAGS_POLICY
		S(SADB_X_POLICYFLAGS_POLICY), /* OpenBSD */
#endif
		SPARSE_NULL
	},
};

#ifdef SADB_X_EXT_PROTOCOL
const struct sparse_sparse_names sadb_protocol_proto_names = {
        .list = {
#ifdef SADB_X_EXT_FLOW_TYPE
		{ SADB_X_EXT_FLOW_TYPE, &sadb_x_flow_type_names, },
#endif
		{ SADB_X_EXT_PROTOCOL, &ipsec_proto_names, },
		{ 0, NULL, },
	},
};
#endif

#ifdef SADB_X_EXT_PROTOCOL
const struct sparse_names sadb_protocol_direction_names = {
        .prefix = "SADB_",
        .list = {
		S(IPSP_DIRECTION_IN),
		S(IPSP_DIRECTION_OUT),
		SPARSE_NULL,
	},
};
#endif

const struct sparse_names sadb_aalg_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_names sadb_calg_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_names sadb_ealg_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_names sadb_identtype_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_names sadb_flow_type_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_names sadb_lifetime_names = {
        .prefix = "SADB_",
        .list = {
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
	},
};

const struct sparse_sparse_names sadb_alg_names = {
        .list = {
		{ SADB_EXT_SUPPORTED_AUTH, &sadb_aalg_names, },
		{ SADB_EXT_SUPPORTED_ENCRYPT, &sadb_ealg_names, },
#ifdef SADB_X_EXT_SUPPORTED_COMP
		{ SADB_X_EXT_SUPPORTED_COMP, &sadb_calg_names, },
#endif
		{ 0, NULL, },
	},
};

const struct sparse_sparse_names sadb_satype_ealg_names = {
        .list = {
		{ SADB_SATYPE_ESP, &sadb_ealg_names, },
		{ SADB_X_SATYPE_IPCOMP, &sadb_calg_names, },
		{ 0, NULL, },
	}
};

const struct sparse_sparse_names sadb_satype_aalg_names = {
        .list = {
		{ SADB_SATYPE_ESP, &sadb_aalg_names, },
		{ SADB_SATYPE_AH, &sadb_aalg_names, },
		{ 0, NULL, }
	},
};

#ifdef SADB_X_EXT_POLICY
const struct sparse_names ipsec_policy_names = {
        .prefix = "IPSEC_",
        .list = {
		S(IPSEC_POLICY_DISCARD),
		S(IPSEC_POLICY_NONE),
		S(IPSEC_POLICY_IPSEC),
		S(IPSEC_POLICY_ENTRUST),
		S(IPSEC_POLICY_BYPASS),
		SPARSE_NULL
	},
};
#endif

#ifdef SADB_X_EXT_POLICY
const struct sparse_names ipsec_dir_names = {
        .prefix = "IPSEC_",
        .list = {
		S(IPSEC_DIR_ANY),
		S(IPSEC_DIR_INBOUND),
		S(IPSEC_DIR_OUTBOUND),
		S(IPSEC_DIR_MAX),
		S(IPSEC_DIR_INVALID),
		SPARSE_NULL,
	},
};
#endif

#ifdef SADB_X_EXT_POLICY
const struct sparse_names ipsec_mode_names = {
        .prefix = "IPSEC_",
        .list = {
		{ .name = "any!?!", .value = IPSEC_MODE_ANY, },
		S(IPSEC_MODE_TRANSPORT),
		S(IPSEC_MODE_TUNNEL),
		SPARSE_NULL
	},
};
#endif

const struct sparse_names ipsec_level_names = {
        .prefix = "IPSEC_",
        .list = {
		S(IPSEC_LEVEL_DEFAULT),
		S(IPSEC_LEVEL_USE),
		S(IPSEC_LEVEL_REQUIRE),
		S(IPSEC_LEVEL_UNIQUE),
		SPARSE_NULL,
	},
};

const struct sparse_names ipsec_proto_names = {
        .prefix = "IPSEC_",
        .list = {
		S(IPSEC_PROTO_AH),
		S(IPSEC_PROTO_ESP),
		S(IPSEC_PROTO_IPIP),
		S(IPSEC_PROTO_IPV6),
#ifdef IPSEC_PROTO_IPCOMP
		S(IPSEC_PROTO_IPCOMP),
#endif
#ifdef IPSEC_PROTO_COMP
		S(IPSEC_PROTO_COMP),
#endif
#ifdef IPSEC_PROTO_ANY
		S(IPSEC_PROTO_ANY), /* 255, aka IPSEC_ULPROTO_ANY */
#endif
		SPARSE_NULL
	},
};

#ifdef SADB_X_EXT_FLOW_TYPE
const struct sparse_names sadb_x_flow_type_names = {
        .prefix = "SADB_",
        .list = {
		S(SADB_X_FLOW_TYPE_USE),
		S(SADB_X_FLOW_TYPE_ACQUIRE),
		S(SADB_X_FLOW_TYPE_REQUIRE),
		S(SADB_X_FLOW_TYPE_BYPASS),
		S(SADB_X_FLOW_TYPE_DENY),
		S(SADB_X_FLOW_TYPE_DONTACQ),
		SPARSE_NULL,
	},
};
#endif
