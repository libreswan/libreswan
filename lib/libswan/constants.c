/*
 * tables of names for values defined in constants.h
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/*
 * Note that the array sizes are all specified; this is to enable range
 * checking by code that only includes constants.h.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <netinet/in.h>

#include <libreswan.h>
#include <ietf_constants.h>
#include <libreswan/passert.h>

#include "constants.h"
#include "enum_names.h"
#include "lswlog.h"

/*
 * Jam a string into a buffer of limited size.
 *
 * This does something like what people mistakenly think strncpy does
 * but the parameter order is like snprintf.
 * OpenBSD's strlcpy serves the same purpose.
 *
 * The buffer bound (size) must be greater than 0.
 * That allows a guarantee that the result is NUL-terminated.
 *
 * The result is a pointer to the NUL at the end of the string in dest.
 *
 * Warning: no indication of truncation is returned.
 * An earlier version did indicate truncation, but that feature was never used.
 * This version is more robust and has a simpler contract.
 */
char *jam_str(char *dest, size_t size, const char *src)
{
	passert(size > 0);	/* need space for at least NUL */

	{
		size_t full_len = strlen(src);
		size_t copy_len = size - 1 < full_len ? size - 1 : full_len;

		memcpy(dest, src, copy_len);
		dest[copy_len] = '\0';
		return dest + copy_len;
	}
}

/*
 * Add a string to a partially filled buffer of limited size
 *
 * This is similar to what people mistakenly think strncat does
 * but add_str matches jam_str so the arguments are quite different.
 * OpenBSD's strlcat serves the same purpose.
 *
 * The buffer bound (size) must be greater than 0.
 * That allows a guarantee that the result is NUL-terminated.
 *
 * The hint argument allows code that knows the end of the
 * The string in dest to be more efficient.  If it is unknown,
 * just pass a pointer to a character within the string such as
 * the first one.
 *
 * The result is a pointer:
 *   if the string fits, to the NUL at the end of the string in dest;
 *   if the string was truncated, to the roof of dest.
 *
 * The results of jam_str and add_str provide suitable values for hint
 * for subsequent calls.
 *
 * If the hint points at the roof of dest, add_str does nothing and
 * returns that as the result (thus overflow will be sticky).
 *
 * For example
 *	(void)add_str(buf, sizeof(buf), jam_str(buf, sizeof(buf), "first"),
 *		" second");
 * That is slightly more efficient than
 *	(void)jam_str(buf, sizeof(buf), "first");
 *	(void)add_str(buf, sizeof(buf), buf, " second");
 *
 * Warning: strncat's bound is NOT on the whole buffer!
 * strncat(dest, src, n) adds at most n+1 bytes after the contents of dest.
 * Many people think that the limit is n bytes.
 *
 * Warning: Is it really wise to silently truncate?  Only the caller knows.
 * The caller SHOULD check by seeing if the result equals dest's roof.
 * Overflow at any point in a chain of jam_str and add_str calls will
 * be reflected in the final return result so checking of intermediate
 * return values is not required.
 */
char *add_str(char *buf, size_t size, char *hint, const char *src)
{
	passert(size > 0 && buf <= hint && hint <= buf + size);
	if (hint == buf + size)
		return hint;	/* already full */

	/*
	 * skip to end of existing string (if we're not already there)
	 */
	hint += strlen(hint);

	passert(hint < buf + size);	/* must be within buffer */
	return jam_str(hint, size - (hint-buf), src);
}

/* version */
static const char *const version_name_1[] = {
	"ISAKMP Version 1.0 (rfc2407)",
};
static const char *const version_name_2[] = {
	"IKEv2 version 2.0 (rfc4306/rfc5996)",
};

static enum_names version_names_1 = {
	ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION,
	ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION,
	ARRAY_REF(version_name_1),
	NULL
};

enum_names version_names = {
	IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION,
	IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION,
	ARRAY_REF(version_name_2),
	&version_names_1
};

/* Domain of Interpretation */
static const char *const doi_name[] = {
	"ISAKMP_DOI_ISAKMP",
	"ISAKMP_DOI_IPSEC",
};

enum_names doi_names = {
	ISAKMP_DOI_ISAKMP,
	ISAKMP_DOI_IPSEC,
	ARRAY_REF(doi_name),
	NULL
};

/*
 * debugging settings: a set of selections for reporting
 * These would be more naturally situated in log.h,
 * but they are shared with whack.
 * It turns out that "debug-" is clutter in all contexts this is used,
 * so we leave it off.
 */
const char *const debug_bit_names[] = {
	"raw",
	"crypt",
	"parsing",
	"emitting",
	"control",
	"lifecycle",
	"kernel",
	"dns",
	"oppo",
	"controlmore",
	"pfkey",
	"nattraversal",
	"x509",	/* 12 */
	"dpd",
	"oppoinfo",	/* 14 */
	"whackwatch",
	"private",
	"impair-bust-mi2",
	"impair-bust-mr2",
	"impair-sa-creation",
	"impair-die-oninfo",
	"impair-jacob-two-two",
	"impair-major-version-bump",
	"impair-minor-version-bump",
	"impair-retransmits",
	"impair-send-bogus-payload-flag",
	"impair-send-bogus-isakmp-flag",
	"impair-send-ikev2-ke",
	"impair-send-no-delete",
	"impair-send-no-ikev2-auth",
	"impair-force-fips",
	"impair-send-key-size-check",
	"impair-send-zero-gx",
	"impair-send-bogus-dcookie",
	NULL	/* termination for bitnamesof() */
};

/* kind of struct connection */
static const char *const connection_kind_name[] = {
	"CK_GROUP",	/* policy group: instantiates to template */
	"CK_TEMPLATE",	/* abstract connection, with wildcard */
	"CK_PERMANENT",	/* normal connection */
	"CK_INSTANCE",	/* instance of template */
	"CK_GOING_AWAY"	/* instance being deleted -- don't delete again */
};

enum_names connection_kind_names = {
	CK_GROUP,
	CK_GOING_AWAY,
	ARRAY_REF(connection_kind_name),
	NULL
};

/* Payload types (RFC 2408 "ISAKMP" section 3.1) */
const char *const payload_name_ikev1[] = {
	"ISAKMP_NEXT_NONE",
	"ISAKMP_NEXT_SA",	/* 1 */
	"ISAKMP_NEXT_P",
	"ISAKMP_NEXT_T",
	"ISAKMP_NEXT_KE",
	"ISAKMP_NEXT_ID",	/* 5 */
	"ISAKMP_NEXT_CERT",
	"ISAKMP_NEXT_CR",
	"ISAKMP_NEXT_HASH",
	"ISAKMP_NEXT_SIG",
	"ISAKMP_NEXT_NONCE",	/* 10 */
	"ISAKMP_NEXT_N",
	"ISAKMP_NEXT_D",
	"ISAKMP_NEXT_VID",
	"ISAKMP_NEXT_MODECFG",	/* 14 */
	"ISAKMP_NEXT_SAK",	/* 15 was ISAKMP_NEXT_NATD_BADDRAFTS */
	"ISAKMP_NEXT_TEK",
	"ISAKMP_NEXT_KD",
	"ISAKMP_NEXT_SEQ",
	"ISAKMP_NEXT_POP",
	"ISAKMP_NEXT_NATD_RFC",
	"ISAKMP_NEXT_NATOA_RFC",
	"ISAKMP_NEXT_GAP",
	NULL	/* termination for bitnamesof() */
};

static const char *const payload_name_ikev1_private_use[] = {
	"ISAKMP_NEXT_NATD_DRAFTS",
	"ISAKMP_NEXT_NATOA_DRAFTS",
	"ISAKMP_NEXT_IKE_FRAGMENTATION",	/*
						 * proprietary Cisco/Microsoft
						 * IKE fragmented payload
						 */
};
static enum_names payload_names_ikev1_private_use = {
	ISAKMP_NEXT_NATD_DRAFTS,
	ISAKMP_NEXT_IKE_FRAGMENTATION,
	ARRAY_REF(payload_name_ikev1_private_use),
	NULL
};

enum_names ikev1_payload_names = {
	ISAKMP_NEXT_NONE,
	ISAKMP_NEXT_GAP,
	ARRAY_REF(payload_name_ikev1)-1,	/* don't count NULL */
	&payload_names_ikev1_private_use
};

static const char *const payload_name_ikev2[] = {
	"ISAKMP_NEXT_v2NONE", /* same for IKEv1 */
};

/* http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-2 */
/* dual-use: for enum_name and for bitnamesof */
const char *const payload_name_ikev2_main[] = {
	"ISAKMP_NEXT_v2SA",	/* 33 */
	"ISAKMP_NEXT_v2KE",
	"ISAKMP_NEXT_v2IDi",
	"ISAKMP_NEXT_v2IDr",
	"ISAKMP_NEXT_v2CERT",
	"ISAKMP_NEXT_v2CERTREQ",
	"ISAKMP_NEXT_v2AUTH",
	"ISAKMP_NEXT_v2Ni",
	"ISAKMP_NEXT_v2N",
	"ISAKMP_NEXT_v2D",
	"ISAKMP_NEXT_v2V",
	"ISAKMP_NEXT_v2TSi",
	"ISAKMP_NEXT_v2TSr",
	"ISAKMP_NEXT_v2SK",
	"ISAKMP_NEXT_v2CP",
	"ISAKMP_NEXT_v2EAP",
	"ISAKMP_NEXT_v2GSPM", /* RFC 6467 */
	"ISAKMP_NEXT_v2IDG", /* [draft-yeung-g-ikev2] */
	"ISAKMP_NEXT_v2GSA", /* [draft-yeung-g-ikev2] */
	"ISAKMP_NEXT_v2KD", /* [draft-yeung-g-ikev2] */
	"ISAKMP_NEXT_v2SKF", /* RFC 7383 */
	NULL	/* termination for bitnamesof() */
};

/*
 * Old IKEv1 method applied to IKEv2, different from IKEv2's RFC7383
 * Can be removed
 */
static const char *const payload_name_ikev2_private_use[] = {
	"ISAKMP_NEXT_v2IKE_FRAGMENTATION",
};

static enum_names payload_names_ikev2_private_use = {
	ISAKMP_NEXT_v2IKE_FRAGMENTATION,
	ISAKMP_NEXT_v2IKE_FRAGMENTATION,
	ARRAY_REF(payload_name_ikev2_private_use),
	NULL
};

static enum_names payload_names_ikev2_main = {
	ISAKMP_NEXT_v2SA,
	ISAKMP_NEXT_v2SKF,
	ARRAY_REF(payload_name_ikev2_main)-1,
	&payload_names_ikev2_private_use
};

enum_names ikev2_payload_names = {
	ISAKMP_NEXT_v2NONE,
	ISAKMP_NEXT_v2NONE,
	ARRAY_REF(payload_name_ikev2),
	&payload_names_ikev2_main
};

/* either V1 or V2 payload kind */
static enum_names payload_names_ikev2copy_main = {
	ISAKMP_NEXT_v2SA,
	ISAKMP_NEXT_v2SKF,
	ARRAY_REF(payload_name_ikev2_main)-1,
	&payload_names_ikev1_private_use
};

enum_names payload_names_ikev1orv2 = {
	ISAKMP_NEXT_NONE,
	ISAKMP_NEXT_GAP,
	ARRAY_REF(payload_name_ikev1)-1,
	&payload_names_ikev2copy_main
};


static const char *const ikev2_last_proposal_names[] = {
	"v2_PROPOSAL_LAST",
	NULL,
	"v2_PROPOSAL_NON_LAST",
};

enum_names ikev2_last_proposal_desc = {
	v2_PROPOSAL_LAST,
	v2_PROPOSAL_NON_LAST,
	ARRAY_REF(ikev2_last_proposal_names),
	NULL
};

static const char *const ikev2_last_transform_names[] = {
	"v2_TRANSFORM_LAST",
	NULL,
	NULL,
	"v2_TRANSFORM_NON_LAST",
};

enum_names ikev2_last_transform_desc = {
	v2_TRANSFORM_LAST,
	v2_TRANSFORM_NON_LAST,
	ARRAY_REF(ikev2_last_transform_names),
	NULL
};

/* Exchange types (note: two discontinuous ranges) */
static const char *const exchange_name_ikev1[] = {
	"ISAKMP_XCHG_NONE",
	"ISAKMP_XCHG_BASE",
	"ISAKMP_XCHG_IDPROT",
	"ISAKMP_XCHG_AO",
	"ISAKMP_XCHG_AGGR",
	"ISAKMP_XCHG_INFO",
	"ISAKMP_XCHG_MODE_CFG",	/* 6 - draft, not RFC */
};

static const char *const exchange_name_doi[] = {
	/* 30 - Echo request */
	"ISAKMP_XCHG_STOLEN_BY_OPENSWAN_FOR_ECHOREQUEST",
	"ISAKMP_XCHG_STOLEN_BY_OPENSWAN_FOR_ECHOREPLY",	/* 31 - Echo reply */
	"ISAKMP_XCHG_QUICK",	/* 32 */
	"ISAKMP_XCHG_NGRP",
};

/* http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-1 */
static const char *const exchange_name_ikev2[] = {
	"ISAKMP_v2_SA_INIT", /* RFC 7296 */
	"ISAKMP_v2_AUTH",
	"ISAKMP_v2_CREATE_CHILD_SA",
	"ISAKMP_v2_INFORMATIONAL",
	"ISAKMP_v2_IKE_SESSION_RESUME", /* RFC 5753 */
#if 0	/* we don't recognize these yet */
	"ISAKMP_v2_GSA_AUTH", /* draft-yeung-g-ikev2 */
	"ISAKMP_v2_GSA_REGISTRATION", /* draft-yeung-g-ikev2 */
	"ISAKMP_v2_GSA_REKEY", /* draft-yeung-g-ikev2 */
#endif
};

static const char *const exchange_name_private_use[] = {
	"ISAKMP_XCHG_ECHOREQUEST_PRIVATE",	/* 244 - Used by libreswan  */
	"ISAKMP_XCHG_ECHOREPLY_PRIVATE",	/* 245 - Used by libreswan  */
};

static enum_names exchange_names_private_use = {
	ISAKMP_XCHG_ECHOREQUEST_PRIVATE,
	ISAKMP_XCHG_ECHOREPLY_PRIVATE,
	ARRAY_REF(exchange_name_private_use),
	NULL
};

static enum_names exchange_names_doi = {
	ISAKMP_XCHG_STOLEN_BY_OPENSWAN_FOR_ECHOREQUEST,
	ISAKMP_XCHG_NGRP,
	ARRAY_REF(exchange_name_doi),
	&exchange_names_private_use
};

enum_names ikev1_exchange_names = {
	ISAKMP_XCHG_NONE,
	ISAKMP_XCHG_MODE_CFG,
	ARRAY_REF(exchange_name_ikev1),
	&exchange_names_doi
};

enum_names ikev2_exchange_names = {
	ISAKMP_v2_SA_INIT,
	ISAKMP_v2_IKE_SESSION_RESUME,
	ARRAY_REF(exchange_name_ikev2),
	&exchange_names_private_use
};

static enum_names exchange_names_doi_and_v2 = {
	ISAKMP_XCHG_STOLEN_BY_OPENSWAN_FOR_ECHOREQUEST,
	ISAKMP_XCHG_NGRP,
	ARRAY_REF(exchange_name_doi),
	&ikev2_exchange_names
};

enum_names exchange_names_ikev1orv2 = {
	ISAKMP_XCHG_NONE,
	ISAKMP_XCHG_MODE_CFG,
	ARRAY_REF(exchange_name_ikev1),
	&exchange_names_doi_and_v2
};

/* Flag BITS */
const char *const isakmp_flag_names[] = {
	"ISAKMP_FLAG_v1_ENCRYPTION", /* IKEv1 only bit 0 */
	"ISAKMP_FLAG_v1_COMMIT", /* IKEv1 only bit 1 */
	"ISAKMP_FLAG_v1_AUTHONLY", /* IKEv1 only bit 2 */
	"ISAKMP_FLAG_v2_IKE_INIT", /* IKEv2 only bit 3 */
	"ISAKMP_FLAG_v2_VERSION", /* IKEv2 only bit 4 */
	"ISAKMP_FLAG_v2_MSG_RESPONSE", /* IKEv2 only bit 5 */
	"ISAKMP_FLAG_MSG_RESERVED_BIT6",
	"ISAKMP_FLAG_MSG_RESERVED_BIT7",
	NULL	/* termination for bitnamesof() */
};

/* Situation BITS definition for IPsec DOI */
const char *const sit_bit_names[] = {
	"SIT_IDENTITY_ONLY",
	"SIT_SECRECY",
	"SIT_INTEGRITY",
	NULL	/* termination for bitnamesof() */
};

/* Protocol IDs (RFC 2407 "IPsec DOI" section 4.4.1) */
static const char *const ikev1_protocol_name[] = {
	"PROTO_RESERVED",
	"PROTO_ISAKMP",
	"PROTO_IPSEC_AH",
	"PROTO_IPSEC_ESP",
	"PROTO_IPCOMP",
};

enum_names ikev1_protocol_names = {
	PROTO_RESERVED,
	PROTO_IPCOMP,
	ARRAY_REF(ikev1_protocol_name),
	NULL
};

static const char *const ikev2_protocol_name[] = {
	"PROTO_v2_RESERVED",
	"PROTO_v2_IKE",
	"PROTO_v2_AH",
	"PROTO_v2_ESP",
};

enum_names ikev2_protocol_names = {
	PROTO_v2_RESERVED,
	PROTO_v2_ESP,
	ARRAY_REF(ikev2_protocol_name),
	NULL
};

/* subset of protocol names accepted by IKEv2 Delete */
enum_names ikev2_del_protocol_names = {
	PROTO_ISAKMP,
	PROTO_IPSEC_ESP,
	&ikev2_protocol_name[PROTO_ISAKMP], elemsof(ikev2_protocol_name) - PROTO_ISAKMP,
	NULL
};

/* IPsec ISAKMP transform values */
static const char *const isakmp_transform_name[] = {
	"KEY_IKE",
};

enum_names isakmp_transformid_names = {
	KEY_IKE,
	KEY_IKE,
	ARRAY_REF(isakmp_transform_name),
	NULL
};

/* IPsec AH transform values */

static const char *const ah_transform_name_private_use[] = {
	"AH_NULL",	/* verify with kame source? 251 */
	"AH_SHA2_256_TRUNC",	/* our own to signal bad truncation to kernel */
};

static enum_names ah_transformid_names_private_use = {
	AH_NULL,
	AH_SHA2_256_TRUNC,
	ARRAY_REF(ah_transform_name_private_use),
	NULL
};

static const char *const ah_transform_name[] = {
	/* 0-1 RESERVED */
	"AH_MD5",
	"AH_SHA",
	"AH_DES",
	"AH_SHA2_256",
	"AH_SHA2_384",
	"AH_SHA2_512",
	"AH_RIPEMD",
	"AH_AES_XCBC_MAC",
	"AH_RSA",
	"AH_AES_128_GMAC",	/* RFC4543 Errata1821  */
	"AH_AES_192_GMAC",	/* RFC4543 Errata1821  */
	"AH_AES_256_GMAC",	/* RFC4543 Errata1821  */
	/* 14-248 Unassigned */
	/* 249-255 Reserved for private use */
};

enum_names ah_transformid_names = {
	AH_MD5, AH_AES_256_GMAC,
	ARRAY_REF(ah_transform_name),
	&ah_transformid_names_private_use
};

/*
 * IPsec ESP transform values
 *
 * ipsec drafts suggest "high" ESP ids values for testing,
 * assign generic ESP_ID<num> if not officially defined
 */
static const char *const esp_transform_name_private_use[] = {
	/* id=249 */
	"ESP_MARS",
	"ESP_RC6",
	"ESP_KAME_NULL",
	"ESP_SERPENT",
	"ESP_TWOFISH",
	"ESP_ID254",
	"ESP_ID255",
};

static enum_names esp_transformid_names_private_use = {
	ESP_MARS,
	ESP_ID255,
	ARRAY_REF(esp_transform_name_private_use),
	NULL
};

/* This tracks the IKEv2 registry now! see ietf_constants.h */
static const char *const esp_transform_name[] = {
	"ESP_DES_IV64",	/* 1 - old DES */
	"ESP_DES",	/* obsoleted */
	"ESP_3DES",
	"ESP_RC5",
	"ESP_IDEA",
	"ESP_CAST",
	"ESP_BLOWFISH",	/* obsoleted */
	"ESP_3IDEA",
	"ESP_DES_IV32",
	"ESP_RC4",
	"ESP_NULL",
	"ESP_AES",
	"ESP_AES_CTR",
	"ESP_AES_CCM_A",
	"ESP_AES_CCM_B",
	"ESP_AES_CCM_C",
	"ESP_UNASSIGNED_ID17",
	"ESP_AES_GCM_A",
	"ESP_AES_GCM_B",
	"ESP_AES_GCM_C",
	"ESP_NULL_AUTH_AES_GMAC", /* IKEv1 ESP_SEED_CBC */
	/*
	 * From here, IKEv1 and IKEv2 registries for ESP_ algorithms become
	 * inconsistant. The linux PF_KEY API returns 22 in the IKEv1 registry
	 * meaning (camellia), so we need to lie here.
	 */
	/* "ESP_RESERVED_FOR_IEEE_P1619_XTS_AES" */
	"ESP_CAMELLIA", /* IKEv1, but kernel tells us this */
	"ESP_CAMELLIA", /* IKEv2, IKEv1 entry is ESP_NULL_AUTH_AES-GMAC */
	"ESP_CAMELLIA_CTR", /* not assigned in/for IKEv1 */
	"ESP_CAMELLIA_CCM_A", /* not assigned in/for IKEv1 */
	"ESP_CAMELLIA_CCM_B", /* not assigned in/for IKEv1 */
	"ESP_CAMELLIA_CCM_C", /* not assigned in/for IKEv1 */
	/* IKEv1: 24-248 Unassigned */
	/* IKEv1: 249-255 reserved for private use */
	/* IKEv2: 28-1023 Unassigned */
	/* IKEv2: 1024-65535 reserved for private use */
};

enum_names esp_transformid_names = {
	ESP_DES_IV64,
	ESP_CAMELLIA_CCM_16,
	ARRAY_REF(esp_transform_name),
	&esp_transformid_names_private_use
};

/* IPCOMP transform values */
static const char *const ipcomp_transform_name[] = {
	"IPCOMP_OUI",
	"IPCOMP_DEFLAT",
	"IPCOMP_LZS",
	"IPCOMP_LZJH",
	/* 5-47 Reserved for approved algorithms */
	/* 48-63 Reserved for private use */
	/* 64-255 Unassigned */
};

enum_names ipcomp_transformid_names = {
	IPCOMP_OUI,
	IPCOMP_LZJH,
	ARRAY_REF(ipcomp_transform_name),
	NULL
};

/* Identification type values */
static const char *const ike_idtype_name[] = {
	/* ID_FROMCERT = (-3), taken from certificate - private to Pluto */
	/* ID_IMPOSSIBLE = (-2), private to Pluto */
	/* ID_MYID = (-1), private to Pluto */

	"ID_NONE", /* = 0, private to Pluto */

	"ID_IPV4_ADDR",	/* 1 */
	"ID_FQDN",
	"ID_USER_FQDN",
	"ID_USER_FQDN",	/* v1 only */
	"ID_IPV6_ADDR",
	"ID_IPV6_ADDR_SUBNET",	/* v1 only */
	"ID_IPV4_ADDR_RANGE",	/* v1 only */
	"ID_IPV6_ADDR_RANGE",	/* v1 only */
	"ID_DER_ASN1_DN",
	"ID_DER_ASN1_GN",
	"ID_KEY_ID",
	"ID_FC_NAME", /* RFC 3554 */
	"ID_NULL", /* draft-ietf-ipsecme-ikev2-null-auth */
};

/* IKEv1 */
enum_names ike_idtype_names = {
	ID_IPV4_ADDR, ID_FC_NAME,
	&ike_idtype_name[ID_IPV4_ADDR], ID_FC_NAME-ID_IPV4_ADDR+1,
	NULL
};

static enum_names ikev2_idtype_names_3 = {
	ID_DER_ASN1_DN, ID_NULL,
	&ike_idtype_name[ID_DER_ASN1_DN], elemsof(ike_idtype_name)-ID_DER_ASN1_DN,
	NULL
};

static enum_names ikev2_idtype_names_2 = {
	ID_IPV6_ADDR, ID_IPV6_ADDR,
	&ike_idtype_name[ID_IPV6_ADDR], 1,
	&ikev2_idtype_names_3
};

enum_names ikev2_idtype_names = {
	ID_IPV4_ADDR, ID_RFC822_ADDR,
	&ike_idtype_name[ID_IPV4_ADDR], ID_RFC822_ADDR-ID_IPV4_ADDR+1,
	&ikev2_idtype_names_2
};

/* Certificate type values */
static const char *const ike_cert_type_name[] = {
	"CERT_PKCS7_WRAPPED_X509",
	"CERT_PGP",
	"CERT_DNS_SIGNED_KEY",
	"CERT_X509_SIGNATURE",
	"CERT_X509_KEY_EXCHANGE",	/* v1 only */
	"CERT_KERBEROS_TOKENS",
	"CERT_CRL",
	"CERT_ARL",
	"CERT_SPKI",
	"CERT_X509_ATTRIBUTE",

	/* IKEv2 only from here */
	"CERT_RAW_RSA",
	"CERT_X509_CERT_URL",
	"CERT_X509_BUNDLE_URL",
	"CERT_OCSP_CONTENT", /* 14 */
	"CERT_RAW_PUBLIC_KEY",

	/* 16 - 200 Reserved */
	/* 201 - 255 Private use */
};

enum_names ike_cert_type_names = {
	CERT_PKCS7_WRAPPED_X509, CERT_X509_ATTRIBUTE,
	/* only first part of ike_cert_type_name */
	ike_cert_type_name, CERT_X509_ATTRIBUTE - CERT_PKCS7_WRAPPED_X509 + 1,
	NULL
};


static enum_names ikev2_cert_type_names_2 = {
	CERT_KERBEROS_TOKENS, CERT_RAW_PUBLIC_KEY,
	&ike_cert_type_name[CERT_KERBEROS_TOKENS-CERT_PKCS7_WRAPPED_X509],
	CERT_RAW_PUBLIC_KEY-CERT_KERBEROS_TOKENS+1,
	NULL
};

enum_names ikev2_cert_type_names = {
	CERT_PKCS7_WRAPPED_X509, CERT_X509_SIGNATURE,
	ike_cert_type_name,
	CERT_X509_SIGNATURE-CERT_PKCS7_WRAPPED_X509+1,
	&ikev2_cert_type_names_2
};

/*
 * certificate request payload policy
 */
static const char *const certpolicy_type_name[] = {
	"cert_neversend",
	"cert_sendifasked",
	"cert_alwayssend",
};

enum_names certpolicy_type_names = {
	cert_neversend,
	cert_alwayssend,
	ARRAY_REF(certpolicy_type_name),
	NULL
};

/*
 * Oakley transform attributes
 * oakley_attr_bit_names does double duty: it is used for enum names
 * and bit names.
 * https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-2
 */
const char *const oakley_attr_bit_names[] = {
	"OAKLEY_ENCRYPTION_ALGORITHM",
	"OAKLEY_HASH_ALGORITHM",
	"OAKLEY_AUTHENTICATION_METHOD",
	"OAKLEY_GROUP_DESCRIPTION",
	"OAKLEY_GROUP_TYPE",
	"OAKLEY_GROUP_PRIME",
	"OAKLEY_GROUP_GENERATOR_ONE",
	"OAKLEY_GROUP_GENERATOR_TWO",
	"OAKLEY_GROUP_CURVE_A",
	"OAKLEY_GROUP_CURVE_B",
	"OAKLEY_LIFE_TYPE",
	"OAKLEY_LIFE_DURATION",
	"OAKLEY_PRF",
	"OAKLEY_KEY_LENGTH",
	"OAKLEY_FIELD_SIZE",
	"OAKLEY_GROUP_ORDER",
	NULL	/* termination for bitnamesof() */
};

static const char *const oakley_var_attr_name[] = {
	"OAKLEY_GROUP_PRIME (variable length)",
	"OAKLEY_GROUP_GENERATOR_ONE (variable length)",
	"OAKLEY_GROUP_GENERATOR_TWO (variable length)",
	"OAKLEY_GROUP_CURVE_A (variable length)",
	"OAKLEY_GROUP_CURVE_B (variable length)",
	NULL,
	"OAKLEY_LIFE_DURATION (variable length)",
	NULL,
	NULL,
	NULL,
	"OAKLEY_GROUP_ORDER (variable length)",
};

static enum_names oakley_attr_desc_tv = {
	OAKLEY_ENCRYPTION_ALGORITHM + ISAKMP_ATTR_AF_TV,
	OAKLEY_GROUP_ORDER + ISAKMP_ATTR_AF_TV,
	ARRAY_REF(oakley_attr_bit_names)-1,
	NULL
};

enum_names oakley_attr_names = {
	OAKLEY_GROUP_PRIME,
	OAKLEY_GROUP_ORDER,
	ARRAY_REF(oakley_var_attr_name),
	&oakley_attr_desc_tv
};

/* for each Oakley attribute, which enum_names describes its values? */
static enum_names oakley_prf_names;	/* forward declaration */
static enum_names oakley_group_type_names;	/* forward declaration */

enum_names *const oakley_attr_val_descs[] = {
	NULL,	/* (none) */
	&oakley_enc_names,	/* OAKLEY_ENCRYPTION_ALGORITHM */
	&oakley_hash_names,	/* OAKLEY_HASH_ALGORITHM */
	&oakley_auth_names,	/* OAKLEY_AUTHENTICATION_METHOD */
	&oakley_group_names,	/* OAKLEY_GROUP_DESCRIPTION */
	&oakley_group_type_names,	/* OAKLEY_GROUP_TYPE */
	NULL,	/* OAKLEY_GROUP_PRIME */
	NULL,	/* OAKLEY_GROUP_GENERATOR_ONE */
	NULL,	/* OAKLEY_GROUP_GENERATOR_TWO */
	NULL,	/* OAKLEY_GROUP_CURVE_A */
	NULL,	/* OAKLEY_GROUP_CURVE_B */
	&oakley_lifetime_names,	/* OAKLEY_LIFE_TYPE */
	NULL,	/* OAKLEY_LIFE_DURATION */
	&oakley_prf_names,	/* OAKLEY_PRF */
	NULL,	/* OAKLEY_KEY_LENGTH */
	NULL,	/* OAKLEY_FIELD_SIZE */
	NULL,	/* OAKLEY_GROUP_ORDER */
};

const unsigned int oakley_attr_val_descs_roof = elemsof(oakley_attr_val_descs);

/* IPsec DOI attributes (RFC 2407 "IPsec DOI" section 4.5) */
static const char *const ipsec_attr_name[] = {
	"SA_LIFE_TYPE",
	"SA_LIFE_DURATION",
	"GROUP_DESCRIPTION",
	"ENCAPSULATION_MODE",
	"AUTH_ALGORITHM",
	"KEY_LENGTH",
	"KEY_ROUNDS",
	"COMPRESS_DICT_SIZE",
	"COMPRESS_PRIVATE_ALG",
#ifdef HAVE_LABELED_IPSEC
	"ECN_TUNNEL or old SECCTX",
#endif
};

/*
 * These are attributes with variable length values (TLV).
 * The ones we actually support have non-NULL entries.
 */
static const char *const ipsec_var_attr_name[] = {
	NULL,	/* SA_LIFE_TYPE */
	"SA_LIFE_DURATION (variable length)",
	NULL,	/* GROUP_DESCRIPTION */
	NULL,	/* ENCAPSULATION_MODE */
	NULL,	/* AUTH_ALGORITHM */
	NULL,	/* KEY_LENGTH */
	NULL,	/* KEY_ROUNDS */
	NULL,	/* COMPRESS_DICT_SIZE */
	"COMPRESS_PRIVATE_ALG (variable length)",
#ifdef HAVE_LABELED_IPSEC
	"NULL", /* ECN_TUNNEL_or_old_SECCTX */
#endif
};

#ifdef HAVE_LABELED_IPSEC
static const char *const ipsec_private_attr_name[] = {
	"SECCTX" /* 32001 */
};

static enum_names ipsec_private_attr_names_tv = {
	SECCTX + ISAKMP_ATTR_AF_TV,
	SECCTX + ISAKMP_ATTR_AF_TV,
	ARRAY_REF(ipsec_private_attr_name),
	NULL
};

static enum_names ipsec_private_attr_names = {
	SECCTX,
	SECCTX,
	ARRAY_REF(ipsec_private_attr_name),
	&ipsec_private_attr_names_tv
};
#endif

static enum_names ipsec_attr_desc_tv = {
	SA_LIFE_TYPE + ISAKMP_ATTR_AF_TV,
#ifdef HAVE_LABELED_IPSEC
	ECN_TUNNEL_or_old_SECCTX + ISAKMP_ATTR_AF_TV,
#else
	COMPRESS_PRIVATE_ALG + ISAKMP_ATTR_AF_TV,
#endif
	ARRAY_REF(ipsec_attr_name),
#ifdef HAVE_LABELED_IPSEC
	&ipsec_private_attr_names
#else
	NULL
#endif
};

enum_names ipsec_attr_names = {
	SA_LIFE_TYPE,
#ifdef HAVE_LABELED_IPSEC
	ECN_TUNNEL_or_old_SECCTX,
#else
	COMPRESS_PRIVATE_ALG,
#endif
	ARRAY_REF(ipsec_var_attr_name),
	&ipsec_attr_desc_tv
};

/* for each IPsec attribute, which enum_names describes its values? */
enum_names *const ipsec_attr_val_descs[] = {
	NULL,	/* (none) */
	&sa_lifetime_names,	/* SA_LIFE_TYPE */
	NULL,	/* SA_LIFE_DURATION */
	&oakley_group_names,	/* GROUP_DESCRIPTION */
	&enc_mode_names,	/* ENCAPSULATION_MODE */
	&auth_alg_names,	/* AUTH_ALGORITHM */
	NULL,	/* KEY_LENGTH */
	NULL,	/* KEY_ROUNDS */
	NULL,	/* COMPRESS_DICT_SIZE */
	NULL,	/* COMPRESS_PRIVATE_ALG */
#ifdef HAVE_LABELED_IPSEC
	NULL,	/* ECN_TUNNEL_or_old_SECCTX */
#endif
};

const unsigned int ipsec_attr_val_descs_roof = elemsof(ipsec_attr_val_descs);

/* SA Lifetime Type attribute */
static const char *const sa_lifetime_name[] = {
	"SA_LIFE_TYPE_SECONDS",
	"SA_LIFE_TYPE_KBYTES",
};

enum_names sa_lifetime_names = {
	SA_LIFE_TYPE_SECONDS,
	SA_LIFE_TYPE_KBYTES,
	ARRAY_REF(sa_lifetime_name),
	NULL
};

/* Encapsulation Mode attribute */
static const char *const enc_rfc_mode_name[] = {
	"ENCAPSULATION_MODE_TUNNEL",
	"ENCAPSULATION_MODE_TRANSPORT",
	"ENCAPSULATION_MODE_UDP_TUNNEL_RFC",
	"ENCAPSULATION_MODE_UDP_TRANSPORT_RFC",
};

static const char *const enc_draft_mode_name[] = {
	"ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS",
	"ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS",
};

static enum_names enc_rfc_mode_names = {
	ENCAPSULATION_MODE_TUNNEL,
	ENCAPSULATION_MODE_UDP_TRANSPORT_RFC,
	ARRAY_REF(enc_rfc_mode_name),
	NULL
};

enum_names enc_mode_names = {
	ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS,
	ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS,
	ARRAY_REF(enc_draft_mode_name),
	&enc_rfc_mode_names
};

/* Auth Algorithm attribute */

static const char *const auth_alg_name_stolen_use[] = {
	"AUTH_ALGORITHM_NULL_KAME",	/*
					 * according to our source code
					 * comments from jjo, needs
					 * verification
					 */
};

static enum_names auth_alg_names_stolen_use = {
	AUTH_ALGORITHM_NULL_KAME,
	AUTH_ALGORITHM_NULL_KAME,
	ARRAY_REF(auth_alg_name_stolen_use),
	NULL
};

/* these string names map via a lookup function to configuration sttrings */
static const char *const auth_alg_name[] = {
	"AUTH_ALGORITHM_NONE",	/* our own value, not standard */
	"AUTH_ALGORITHM_HMAC_MD5",
	"AUTH_ALGORITHM_HMAC_SHA1",
	"AUTH_ALGORITHM_DES_MAC",
	"AUTH_ALGORITHM_KPDK",
	"AUTH_ALGORITHM_HMAC_SHA2_256",
	"AUTH_ALGORITHM_HMAC_SHA2_384",
	"AUTH_ALGORITHM_HMAC_SHA2_512",
	"AUTH_ALGORITHM_HMAC_RIPEMD",
	"AUTH_ALGORITHM_AES_XCBC",
	"AUTH_ALGORITHM_SIG_RSA",	/* RFC4359 */
	"AUTH_ALGORITHM_AES_128_GMAC",	/* RFC4543 [Errata1821] */
	"AUTH_ALGORITHM_AES_192_GMAC",	/* RFC4543 [Errata1821] */
	"AUTH_ALGORITHM_AES_256_GMAC",	/* RFC4543 [Errata1821] */
	/* 14-61439 Unassigned */
	/* 61440-65535 Reserved for private use */
};

enum_names auth_alg_names = {
	AUTH_ALGORITHM_NONE,
	AUTH_ALGORITHM_AES_256_GMAC,
	ARRAY_REF(auth_alg_name),
	&auth_alg_names_stolen_use
};

/*
 * From https://tools.ietf.org/html/draft-ietf-ipsec-isakmp-xauth-06
 * The draft did not make it to an RFC
 */

/* for XAUTH-TYPE attribute */
static const char *const xauth_type_name[] = {
	"Generic",
	"RADIUS-CHAP",
	"OTP",
	"S/KEY",
};
enum_names xauth_type_names = {
	XAUTH_TYPE_GENERIC,
	XAUTH_TYPE_SKEY,
	ARRAY_REF(xauth_type_name),
	NULL
};

/* IKEv1 XAUTH-STATUS attribute names  */
static const char *const modecfg_attr_name_draft[] = {
	"INTERNAL_IP4_ADDRESS",	/* 1 */
	"INTERNAL_IP4_NETMASK",
	"INTERNAL_IP4_DNS",
	"INTERNAL_IP4_NBNS",
	"INTERNAL_ADDRESS_EXPIRY",
	"INTERNAL_IP4_DHCP",
	"APPLICATION_VERSION",
	"INTERNAL_IP6_ADDRESS",
	"INTERNAL_IP6_NETMASK",
	"INTERNAL_IP6_DNS",
	"INTERNAL_IP6_NBNS",
	"INTERNAL_IP6_DHCP",
	"INTERNAL_IP4_SUBNET",	/* 13 */
	"SUPPORTED_ATTRIBUTES",
	"INTERNAL_IP6_SUBNET",
	"MIP6_HOME_PREFIX",
	"INTERNAL_IP6_LINK",
	"INTERNAL_IP6_PREFIX",
	"HOME_AGENT_ADDRESS",	/* 19 */
};

#if 0
/* this is not used - which is a little strange */
static enum_names modecfg_attr_names_draft = {
	INTERNAL_IP4_ADDRESS,
	HOME_AGENT_ADDRESS,
	modecfg_attr_name_draft,
	NULL
};
#endif

static const char *const modecfg_cisco_attr_name[] = {
	"MODECFG_BANNER",	/* 28672 */
	"CISCO_SAVE_PW",
	"MODECFG_DOMAIN",
	"CISCO_SPLIT_DNS",
	"CISCO_SPLIT_INC",
	"CISCO_UDP_ENCAP_PORT",
	"CISCO_SPLIT_EXCLUDE",
	"CISCO_DO_PFS",
	"CISCO_FW_TYPE",
	"CISCO_BACKUP_SERVER",
	"CISCO_DDNS_HOSTNAME",
	"CISCO_UNKNOWN_SEEN_ON_IPHONE",	/* 28683 */
};

static enum_names modecfg_cisco_attr_names = {
	MODECFG_BANNER,
	CISCO_UNKNOWN_SEEN_ON_IPHONE,
	ARRAY_REF(modecfg_cisco_attr_name),
	NULL
};

static const char *const modecfg_microsoft_attr_name[] = {
	"INTERNAL_IP4_SERVER",	/* 23456 */
	"INTERNAL_IP6_SERVER",
};
static enum_names modecfg_microsoft_attr_names = {
	INTERNAL_IP4_SERVER,
	INTERNAL_IP6_SERVER,
	ARRAY_REF(modecfg_microsoft_attr_name),
	&modecfg_cisco_attr_names
};

enum_names modecfg_attr_names = {
	INTERNAL_IP4_ADDRESS,
	HOME_AGENT_ADDRESS,
	ARRAY_REF(modecfg_attr_name_draft),
	&xauth_attr_names
};

static const char *const xauth_attr_name[] = {
	"XAUTH-TYPE", /* 16520 */
	"XAUTH-USER-NAME",
	"XAUTH-USER-PASSWORD",
	"XAUTH-PASSCODE",
	"XAUTH-MESSAGE",
	"XAUTH-CHALLENGE",
	"XAUTH-DOMAIN",
	"XAUTH-STATUS",
	"XAUTH-NEXT-PIN",
	"XAUTH-ANSWER", /* 16529 */
};

/*
 * Note XAUTH and MODECFG are the same xauth attribute list in the registry
 * but we treat these as two completely separate lists
 */
enum_names xauth_attr_names = {
	XAUTH_TYPE,
	XAUTH_ANSWER,
	ARRAY_REF(xauth_attr_name),
	&modecfg_microsoft_attr_names
};

/* Oakley Lifetime Type attribute */
static const char *const oakley_lifetime_name[] = {
	"OAKLEY_LIFE_SECONDS",
	"OAKLEY_LIFE_KILOBYTES",
};

enum_names oakley_lifetime_names = {
	OAKLEY_LIFE_SECONDS,
	OAKLEY_LIFE_KILOBYTES,
	ARRAY_REF(oakley_lifetime_name),
	NULL
};

/* Oakley PRF attribute (none defined) */
static enum_names oakley_prf_names = {
	1,
	0,
	NULL, 0,
	NULL
};

/*
 * IKEv1 Oakley Encryption Algorithm attribute
 * www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-4
 */

static const char *const oakley_enc_name[] = {
	"OAKLEY_DES_CBC", /* obsoleted */
	"OAKLEY_IDEA_CBC",
	"OAKLEY_BLOWFISH_CBC", /* obsoleted */
	"OAKLEY_RC5_R16_B64_CBC",
	"OAKLEY_3DES_CBC",
	"OAKLEY_CAST_CBC",
	"OAKLEY_AES_CBC",
	"OAKLEY_CAMELLIA_CBC", /* 8 */
	"UNUSED_9",
	"UNUSED_10",
	"UNUSED_11",
	"UNUSED_12",
	"OAKLEY_AES_CTR", /* stolen from IKEv2 */
	"OAKLEY_AES_CCM_A",
	"OAKLEY_AES_CCM_B",
	"OAKLEY_AES_CCM_16",
	"UNUSED_17",
	"OAKLEY_AES_GCM_A",
	"OAKLEY_AES_GCM_B",
	"OAKLEY_AES_GCM_C",
	"UNUSED_21",
	"UNUSED_22",
	"UNUSED_23",
	"OAKLEY_CAMELLIA_CTR",
	"OAKLEY_CAMELLIA_CCM_A",
	"OAKLEY_CAMELLIA_CCM_B",
	"OAKLEY_CAMELLIA_CCM_C",

	/* 9-65000 Unassigned */
	/* 65001-65535 Reserved for private use */
};

static const char *const oakley_enc_name_private_use[] = {
	"OAKLEY_MARS_CBC"	/* 65001 */,
	"OAKLEY_RC6_CBC"	/* 65002 */,
	"OAKLEY_ID_65003"	/* 65003 */,
	"OAKLEY_SERPENT_CBC"	/* 65004 */,
	"OAKLEY_TWOFISH_CBC"	/* 65005 */,
};

static const char *const oakley_enc_name_private_use_ssh[] = {
	"OAKLEY_TWOFISH_CBC_SSH",	/* 65289 */
};

static enum_names oakley_enc_names_private_use_ssh = {
	OAKLEY_TWOFISH_CBC_SSH,
	OAKLEY_TWOFISH_CBC_SSH,
	ARRAY_REF(oakley_enc_name_private_use_ssh),
	NULL
};

static enum_names oakley_enc_names_private_use = {
	OAKLEY_MARS_CBC,
	OAKLEY_TWOFISH_CBC,
	ARRAY_REF(oakley_enc_name_private_use),
	&oakley_enc_names_private_use_ssh
};

enum_names oakley_enc_names = {
	OAKLEY_DES_CBC,
	OAKLEY_CAMELLIA_CCM_C,
	ARRAY_REF(oakley_enc_name),
	&oakley_enc_names_private_use
};

/*
 * Oakley Hash Algorithm attribute
 * http://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
 */

/* these string names map via a lookup function to configuration sttrings */
static const char *const oakley_hash_name[] = {
	/* 0 - RESERVED */
	"OAKLEY_MD5",
	"OAKLEY_SHA1",
	"OAKLEY_TIGER",
	"OAKLEY_SHA2_256",	/* RFC 4878 */
	"OAKLEY_SHA2_384",	/* RFC 4878 */
	"OAKLEY_SHA2_512",	/* RFC 4878 */
	"UNUSED_7",
	"UNUSED_8",
	"DISABLED-OAKLEY_AES_XCBC" /* stolen from ikev2 */
	/* 7-65000 Unassigned */
	/* 65001-65535 Reserved for private use */
};

enum_names oakley_hash_names = {
	OAKLEY_MD5,
	OAKLEY_AES_XCBC, /* waiting on NSS support */
	ARRAY_REF(oakley_hash_name),
	NULL
};

/* Oakley Authentication Method attribute */
static const char *const oakley_auth_name[] = {
	"OAKLEY_PRESHARED_KEY",
	"OAKLEY_DSS_SIG",
	"OAKLEY_RSA_SIG",
	"OAKLEY_RSA_ENC",
	"OAKLEY_RSA_REVISED_MODE",
	"OAKLEY_RESERVED_6",
	"OAKLEY_RESERVED_7",
	"OAKLEY_RESERVED_8",
	"OAKLEY_ECDSA_P256", /* RFC 4754 */
	"OAKLEY_ECDSA_P384", /* RFC 4754 */
	"OAKLEY_ECDSA_P521", /* RFC 4754 */
};

static const char *const oakley_auth_name_private_use2[] = {
	"HybridInitRSA", /* 64221 */
	"HybridRespRSA",
	"HybridInitDSS",
	"HybridRespDSS",
};

static const char *const oakley_auth_name_private_use[] = {
	"XAUTHInitPreShared", /* 65001 */
	"XAUTHRespPreShared",
	"XAUTHInitDSS",
	"XAUTHRespDSS",
	"XAUTHInitRSA",
	"XAUTHRespRSA",
	"XAUTHInitRSAEncryption",
	"XAUTHRespRSAEncryption",
	"XAUTHInitRSARevisedEncryption",
	"XAUTHRespRSARevisedEncryption", /* 65010 */
};

static enum_names oakley_auth_names_private_use2 = {
	HybridInitRSA,
	HybridRespDSS,
	ARRAY_REF(oakley_auth_name_private_use2),
	NULL
};

static enum_names oakley_auth_names_private_use = {
	XAUTHInitPreShared,
	XAUTHRespRSARevisedEncryption,
	ARRAY_REF(oakley_auth_name_private_use),
	&oakley_auth_names_private_use2
};

enum_names oakley_auth_names = {
	OAKLEY_PRESHARED_KEY,
	OAKLEY_ECDSA_P521,
	ARRAY_REF(oakley_auth_name),
	&oakley_auth_names_private_use
};

/*
 * IKEv2 CP attribute name. Some of them are shared with XAUTH Attrib names.
 * http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-21
 */
static const char *const ikev2_cp_attribute_type_name[] = {
	"IKEv2_CP_ATTR_RESERVED",
	"IKEv2_INTERNAL_IP4_ADDRESS",	/* 1 */
	"IKEv2_INTERNAL_IP4_NETMASK",
	"IKEv2_INTERNAL_IP4_DNS",
	"IKEv2_INTERNAL_IP4_NBNS",
	"IKEv2_CP_ATTRIBUTE_RESERVED_5",
	"IKEv2_INTERNAL_IP4_DHCP",
	"IKEv2_APPLICATION_VERSION",
	"IKEv2_INTERNAL_IP6_ADDRESS",
	"IKEv2_CP_ATTRIBUTE_RESERVED_9",
	"IKEv2_INTERNAL_IP6_DNS",
	"IKEv2_CP_ATTRIBUTE_RESERVED_11",
	"IKEv2_INTERNAL_IP6_DHCP",
	"IKEv2_INTERNAL_IP4_SUBNET",	/* 13 */
	"IKEv2_SUPPORTED_ATTRIBUTES",
	"IKEv2_INTERNAL_IP6_SUBNET",
	"IKEv2_MIP6_HOME_PREFIX",
	"IKEv2_INTERNAL_IP6_LINK",
	"IKEv2_INTERNAL_IP6_PREFIX",
	"IKEv2_HOME_AGENT_ADDRESS",
	"IKEv2_P_CSCF_IP4_ADDRESS", /* 20 */
	"IKEv2_P_CSCF_IP6_ADDRESS",
	"IKEv2_FTT_KAT",
	"IKEv2_EXTERNAL_SOURCE_IP4_NAT_INFO", /* 3gpp */
	"IKEv2_TIMEOUT_PERIOD_FOR_LIVENESS_CHECK" /* 3gpp */
};

enum_names ikev2_cp_attribute_type_names = {
	IKEv2_CP_ATTR_RESERVED,
	IKEv2_TIMEOUT_PERIOD_FOR_LIVENESS_CHECK,
	ARRAY_REF(ikev2_cp_attribute_type_name),
	NULL
};

static const char *const ikev2_cp_type_name[] = {
	"IKEv2_CP_CFG_REQUEST" , /* 1 */
	"IKEv2_CP_CFG_REPLY" ,
	"IKEv2_CP_CFG_SET" ,
	"IKEv2_CP_CFG_ACK"
};

enum_names ikev2_cp_type_names = {
	IKEv2_CP_CFG_REQUEST,
	IKEv2_CP_CFG_ACK,
	ARRAY_REF(ikev2_cp_type_name),
	NULL
};

/* ikev2 auth methods */
static const char *const ikev2_auth_name[] = {
	"IKEv2_AUTH_RSA", /* 1 */
	"IKEv2_AUTH_SHARED",
	"IKEv2_AUTH_DSA",
	"IKEv2_AUTH_UNASSIGNED_4",
	"IKEv2_AUTH_UNASSIGNED_5",
	"IKEv2_AUTH_UNASSIGNED_6",
	"IKEv2_AUTH_UNASSIGNED_7",
	"IKEv2_AUTH_UNASSIGNED_8",
	"IKEv2_AUTH_ECDSA_P256",
	"IKEv2_AUTH_ECDSA_P384",
	"IKEv2_AUTH_ECDSA_P521",
	"IKEv2_AUTH_GSPM", /* 12 - RFC 6467 */
	"IKEv2_AUTH_NULL",
};

enum_names ikev2_auth_names = {
	IKEv2_AUTH_RSA,
	IKEv2_AUTH_NULL,
	ARRAY_REF(ikev2_auth_name),
	NULL
};

/*
 * Oakley Group Description attribute
 * XXX: Shared for IKEv1 and IKEv2 (although technically there could
 * be differences we need to care about)
 */

/* these string names map via a lookup function to configuration sttrings */
static const char *const oakley_group_name[] = {
	"OAKLEY_GROUP_MODP768", /* 1 */
	"OAKLEY_GROUP_MODP1024",
	"OAKLEY_GROUP_GP155",
	"OAKLEY_GROUP_GP185",
	"OAKLEY_GROUP_MODP1536", /* RFC 3526 */
	"OAKLEY_GROUP_EC2N_2_1", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_2", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_3", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_4", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_5", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_6", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_7", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_8", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_MODP2048", /* RFC 3526 */
	"OAKLEY_GROUP_MODP3072", /* RFC 3526 */
	"OAKLEY_GROUP_MODP4096", /* RFC 3526 */
	"OAKLEY_GROUP_MODP6144", /* RFC 3526 */
	"OAKLEY_GROUP_MODP8192", /* RFC 3526 */
	"OAKLEY_GROUP_ECP_256", /* RFC 5903 */
	"OAKLEY_GROUP_ECP_384", /* RFC 5903 */
	"OAKLEY_GROUP_ECP_512", /* RFC 5903 */
	"OAKLEY_GROUP_DH22", /* RFC 5114 */
	"OAKLEY_GROUP_DH23", /* RFC 5114 */
	"OAKLEY_GROUP_DH24", /* RFC 5114 */
	"OAKLEY_GROUP_ECP_192", /* RFC 5114 */
	"OAKLEY_GROUP_ECP_224", /* RFC 5114 */
	"OAKLEY_GROUP_NON_IKE_27", /* RFC 6932 - not for use with IKE/IPsec */
	"OAKLEY_GROUP_NON_IKE_28", /* RFC 6932 - not for use with IKE/IPsec */
	"OAKLEY_GROUP_NON_IKE_29", /* RFC 6932 - not for use with IKE/IPsec */
	"OAKLEY_GROUP_NON_IKE_30", /* RFC 6932 - not for use with IKE/IPsec */
	/* 31 - 32767 Unassigned */
	/* 32768 - 65535 Reserved for private use */
};

enum_names oakley_group_names = {
	OAKLEY_GROUP_MODP768,
	OAKLEY_GROUP_NON_IKE_30,
	ARRAY_REF(oakley_group_name),
	NULL
};

/* Oakley Group Type attribute */
static const char *const oakley_group_type_name[] = {
	"OAKLEY_GROUP_TYPE_MODP",
	"OAKLEY_GROUP_TYPE_ECP",
	"OAKLEY_GROUP_TYPE_EC2N",
};

static enum_names oakley_group_type_names = {
	OAKLEY_GROUP_TYPE_MODP,
	OAKLEY_GROUP_TYPE_EC2N,
	ARRAY_REF(oakley_group_type_name),
	NULL
};

/* Notify message type -- RFC2408 3.14.1 */
static const char *const ikev1_notify_name[] = {
	"INVALID_PAYLOAD_TYPE", /* 1 */
	"DOI_NOT_SUPPORTED",
	"SITUATION_NOT_SUPPORTED",
	"INVALID_COOKIE",
	"INVALID_MAJOR_VERSION",
	"INVALID_MINOR_VERSION",
	"INVALID_EXCHANGE_TYPE",
	"INVALID_FLAGS",
	"INVALID_MESSAGE_ID",
	"INVALID_PROTOCOL_ID",
	"INVALID_SPI",
	"INVALID_TRANSFORM_ID",
	"ATTRIBUTES_NOT_SUPPORTED",
	"NO_PROPOSAL_CHOSEN",
	"BAD_PROPOSAL_SYNTAX",
	"PAYLOAD_MALFORMED",
	"INVALID_KEY_INFORMATION",
	"INVALID_ID_INFORMATION",
	"INVALID_CERT_ENCODING",
	"INVALID_CERTIFICATE",
	"CERT_TYPE_UNSUPPORTED",
	"INVALID_CERT_AUTHORITY",
	"INVALID_HASH_INFORMATION",
	"AUTHENTICATION_FAILED",
	"INVALID_SIGNATURE",
	"ADDRESS_NOTIFICATION",
	"NOTIFY_SA_LIFETIME",
	"CERTIFICATE_UNAVAILABLE",
	"UNSUPPORTED_EXCHANGE_TYPE",
	"UNEQUAL_PAYLOAD_LENGTHS",
};

static const char *const ikev1_notify_status_name[] = {
	"CONNECTED", /* 16384 */
};

static const char *const ikev1_ipsec_notify_name[] = {
	"IPSEC_RESPONDER_LIFETIME", /* 24576 */
	"IPSEC_REPLAY_STATUS",
	"IPSEC_INITIAL_CONTACT",
};

static const char *const ikev1_notify_cisco_chatter_name[] = {
	"ISAKMP_N_CISCO_HELLO", /* 30000 */
	"ISAKMP_N_CISCO_WWTEBR",
	"ISAKMP_N_CISCO_SHUT_UP",
};

static const char *const ikev1_notify_ios_alives_name[] = {
	"ISAKMP_N_IOS_KEEP_ALIVE_REQ", /* 32768 */
	"ISAKMP_N_IOS_KEEP_ALIVE_ACK",
};

static const char *const ikev1_notify_dpd_name[] = {
	"R_U_THERE", /* 36136 */
	"R_U_THERE_ACK",
};

static const char *const ikev1_notify_juniper_name[] = {
	/* Next Hop Tunnel Binding */
	"NETSCREEN_NHTB_INFORM", /* 40001 */
};

static const char *const ikev1_notify_cisco_more_name[] = {
	"ISAKMP_N_CISCO_LOAD_BALANCE", /* 40501 */
	"ISAKMP_N_CISCO_UNKNOWN_40502",
	"ISAKMP_N_CISCO_PRESHARED_KEY_HASH",
};

static enum_names ikev1_notify_cisco_more_names = {
	ISAKMP_N_CISCO_LOAD_BALANCE,
	ISAKMP_N_CISCO_PRESHARED_KEY_HASH,
	ARRAY_REF(ikev1_notify_cisco_more_name),
	NULL
};

static enum_names ikev1_notify_juniper_names = {
	NETSCREEN_NHTB_INFORM,
	NETSCREEN_NHTB_INFORM,
	ARRAY_REF(ikev1_notify_juniper_name),
	&ikev1_notify_cisco_more_names
};

static enum_names ikev1_notify_dpd_names = {
	R_U_THERE, R_U_THERE_ACK,
	ARRAY_REF(ikev1_notify_dpd_name),
	&ikev1_notify_juniper_names
};

static enum_names ikev1_notify_ios_alives_names = {
	ISAKMP_N_IOS_KEEP_ALIVE_REQ,
	ISAKMP_N_IOS_KEEP_ALIVE_ACK,
	ARRAY_REF(ikev1_notify_ios_alives_name),
	&ikev1_notify_dpd_names
};

static enum_names ikev1_notify_cisco_chatter_names = {
	ISAKMP_N_CISCO_HELLO,
	ISAKMP_N_CISCO_SHUT_UP,
	ARRAY_REF(ikev1_notify_cisco_chatter_name),
	&ikev1_notify_ios_alives_names
};

static enum_names ikev1_ipsec_notify_names = {
	IPSEC_RESPONDER_LIFETIME,
	IPSEC_INITIAL_CONTACT,
	ARRAY_REF(ikev1_ipsec_notify_name),
	&ikev1_notify_cisco_chatter_names
};

static enum_names ikev1_notify_status_names = {
	CONNECTED,
	CONNECTED,
	ARRAY_REF(ikev1_notify_status_name),
	&ikev1_ipsec_notify_names
};

enum_names ikev1_notify_names = {
	INVALID_PAYLOAD_TYPE,
	UNEQUAL_PAYLOAD_LENGTHS,
	ARRAY_REF(ikev1_notify_name),
	&ikev1_notify_status_names
};

/* http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xml#ikev2-parameters-13 */
static const char *const ikev2_notify_name_16384[] = {
	"v2N_INITIAL_CONTACT",    /* 16384 */
	"v2N_SET_WINDOW_SIZE",
	"v2N_ADDITIONAL_TS_POSSIBLE",
	"v2N_IPCOMP_SUPPORTED",
	"v2N_NAT_DETECTION_SOURCE_IP",
	"v2N_NAT_DETECTION_DESTINATION_IP",
	"v2N_COOKIE",
	"v2N_USE_TRANSPORT_MODE",
	"v2N_HTTP_CERT_LOOKUP_SUPPORTED",
	"v2N_REKEY_SA",
	"v2N_ESP_TFC_PADDING_NOT_SUPPORTED",
	"v2N_NON_FIRST_FRAGMENTS_ALSO",
	"v2N_MOBIKE_SUPPORTED",
	"v2N_ADDITIONAL_IP4_ADDRESS",
	"v2N_ADDITIONAL_IP6_ADDRESS",
	"v2N_NO_ADDITIONAL_ADDRESSES",
	"v2N_UPDATE_SA_ADDRESSES",
	"v2N_COOKIE2",
	"v2N_NO_NATS_ALLOWED",
	"v2N_AUTH_LIFETIME",
	"v2N_MULTIPLE_AUTH_SUPPORTED",
	"v2N_ANOTHER_AUTH_FOLLOWS",
	"v2N_REDIRECT_SUPPORTED",
	"v2N_REDIRECT",
	"v2N_REDIRECTED_FROM",
	"v2N_TICKET_LT_OPAQUE",
	"v2N_TICKET_REQUEST",
	"v2N_TICKET_ACK",
	"v2N_TICKET_NACK",
	"v2N_TICKET_OPAQUE",
	"v2N_LINK_ID",
	"v2N_USE_WESP_MODE",
	"v2N_ROHC_SUPPORTED",
	"v2N_EAP_ONLY_AUTHENTICATION",
	"v2N_CHILDLESS_IKEV2_SUPPORTED",
	"v2N_QUICK_CRASH_DETECTION",
	"v2N_IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
	"v2N_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED",
	"v2N_IKEV2_MESSAGE_ID_SYNC",
	"v2N_IPSEC_REPLAY_COUNTER_SYNC",
	"v2N_SECURE_PASSWORD_METHODS",
	"v2N_PSK_PERSIST",
	"v2N_PSK_CONFIRM",
	"v2N_ERX_SUPPORTED",
	"v2N_IFOM_CAPABILITY",
	"v2N_SENDER_REQUEST_ID",
	"v2N_IKEV2_FRAGMENTATION_SUPPORTED",    /* 16430 */
	"v2N_SIGNATURE_HASH_ALGORITHMS",
};

static enum_names ikev2_notify_names_16384 = {
	v2N_INITIAL_CONTACT,
	v2N_SIGNATURE_HASH_ALGORITHMS,
	ARRAY_REF(ikev2_notify_name_16384),
	NULL
};

static const char *const ikev2_notify_name[] = {
	"v2N_RESERVED",    /* unofficial "OK" */
	"v2N_UNSUPPORTED_CRITICAL_PAYLOAD",
	"v2N_UNUSED_2",
	"v2N_UNUSED_3",
	"v2N_INVALID_IKE_SPI",
	"v2N_INVALID_MAJOR_VERSION",
	"v2N_UNUSED_6",
	"v2N_INVALID_SYNTAX",
	"v2N_UNUSED_8",
	"v2N_INVALID_MESSAGE_ID",
	"v2N_UNUSED_10",
	"v2N_INVALID_SPI",
	"v2N_UNUSED_12",
	"v2N_UNUSED_13",
	"v2N_NO_PROPOSAL_CHOSEN",
	"v2N_UNUSED_15",
	"v2N_UNUSED_16",
	"v2N_INVALID_KE_PAYLOAD",
	"v2N_UNUSED_18",
	"v2N_UNUSED_19",
	"v2N_UNUSED_20",
	"v2N_UNUSED_21",
	"v2N_UNUSED_22",
	"v2N_UNUSED_23",
	"v2N_AUTHENTICATION_FAILED",
	"v2N_UNUSED_25",
	"v2N_UNUSED_26",
	"v2N_UNUSED_27",
	"v2N_UNUSED_28",
	"v2N_UNUSED_29",
	"v2N_UNUSED_30",
	"v2N_UNUSED_31",
	"v2N_UNUSED_32",
	"v2N_UNUSED_33",
	"v2N_SINGLE_PAIR_REQUIRED",
	"v2N_NO_ADDITIONAL_SAS",
	"v2N_INTERNAL_ADDRESS_FAILURE",
	"v2N_FAILED_CP_REQUIRED",
	"v2N_TS_UNACCEPTABLE",
	"v2N_INVALID_SELECTORS",
	"v2N_UNACCEPTABLE_ADDRESSES",
	"v2N_UNEXPECTED_NAT_DETECTED",
	"v2N_USE_ASSIGNED_HoA",
	"v2N_TEMPORARY_FAILURE",
	"v2N_CHILD_SA_NOT_FOUND",
	"v2N_INVALID_GROUP_ID", /* 45 draft-yeung-g-ikev2 */
	"v2N_AUTHORIZATION_FAILED",
};

enum_names ikev2_notify_names = {
	v2N_NOTHING_WRONG,
	v2N_AUTHORIZATION_FAILED,
	ARRAY_REF(ikev2_notify_name),
	&ikev2_notify_names_16384
};

/* http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xml#ikev2-parameters-19 */
static const char *const ikev2_ts_type_name[] = {
	"IKEv2_TS_IPV4_ADDR_RANGE",
	"IKEv2_TS_IPV6_ADDR_RANGE",
	"IKEv2_TS_FC_ADDR_RANGE",	/* not implemented */
};

enum_names ikev2_ts_type_names = {
	IKEv2_TS_IPV4_ADDR_RANGE,
	IKEv2_TS_FC_ADDR_RANGE,
	ARRAY_REF(ikev2_ts_type_name),
	NULL
};

/*
 * MODECFG
 *
 * From draft-dukes-ike-mode-cfg
 */
static const char *const attr_msg_type_name[] = {
	"ISAKMP_CFG_REQUEST",	/* 1 */
	"ISAKMP_CFG_REPLY",
	"ISAKMP_CFG_SET",
	"ISAKMP_CFG_ACK",
};

enum_names attr_msg_type_names = {
	ISAKMP_CFG_REQUEST,
	ISAKMP_CFG_ACK,
	ARRAY_REF(attr_msg_type_name),
	NULL
};

/*
 * IKEv2 Critical bit and RESERVED (7) bits
 */
const char *const critical_names[] = {
	"RESERVED bit 0",	/* bit 0 */
	"RESERVED bit 1",	/* bit 1 */
	"RESERVED bit 2",	/* bit 2 */
	"RESERVED bit 3",	/* bit 3 */
	"RESERVED bit 4",	/* bit 4 */
	"RESERVED bit 5",	/* bit 5 */
	"RESERVED bit 6",	/* bit 6 */
	"PAYLOAD_CRITICAL",	/* bit 7 */
};

/*
 * IKEv2 Security Protocol Identifiers
 */
static const char *const ikev2_sec_proto_id_name[] = {
	/* 0 - Reserved */
	"IKEv2_SEC_PROTO_IKE",
	"IKEv2_SEC_PROTO_AH",
	"IKEv2_SEC_PROTO_ESP",
	"IKEv2_SEC_FC_ESP_HEADER",	/* RFC 4595 */
	"IKEv2_SEC_FC_CT_AUTHENTICATION",	/* RFC 4595 */
	/* 6 - 200 Unassigned */
	/* 201 - 255 Private use */
};

enum_names ikev2_sec_proto_id_names = {
	IKEv2_SEC_PROTO_IKE,
	IKEv2_SEC_FC_CT_AUTHENTICATION,
	ARRAY_REF(ikev2_sec_proto_id_name),
	NULL
};

/* Transform-type Encryption */
static const char *const ikev2_trans_type_encr_name_private_use2[] = {
	"TWOFISH_CBC_SSH",	/* 65289 */
};

static const char *const ikev2_trans_type_encr_name_private_use1[] = {
	"SERPENT_CBC",	/* 65004 */
	"TWOFISH_CBC",
};

static const char *const ikev2_trans_type_encr_name[] = {
	"DES-IV64(obsoleted)",	/* 1 */
	"DES(obsoleted)",
	"3DES",
	"RC5",
	"IDEA",
	"CAST",
	"BLOWFISH(obsoleted)",
	"3IDEA",
	"DES-IV32(obsoleted)",
	"RES10",
	"NULL",
	"AES_CBC",
	"AES_CTR",
	"AES_CCM_A",	/* AES-CCM_8 RFC 4309 */
	"AES_CCM_B",	/* AES-CCM_12 */
	"AES_CCM_C",	/* AES-CCM_16 */
	"UNASSIGNED",
	"AES_GCM_A",	/* AES-GCM_8 RFC 4106 */
	"AES_GCM_B",	/* AES-GCM_12 */
	"AES_GCM_C",	/* AES-GCM_16 */
	"NULL_AUTH_AES_GMAC",	/* RFC 4543 */
	"RESERVED_FOR_IEEE_P1619_XTS_AES",
	"CAMELLIA_CBC",	/* RFC 5529 */
	"CAMELLIA_CTR",	/* RFC 5529 */
	"CAMELLIA_CCM_A",	/* CAMELLIA_CCM_8 RFC 5529 */
	"CAMELLIA_CCM_B",	/* CAMELLIA_CCM_12 RFC 5529 */
	"CAMELLIA_CCM_C",	/* CAMELLIA_CCM_16 RFC 5529 */
	/* 28 - 1023 Unassigned */
	/* 1024 - 65535 Private use */
};

static enum_names ikev2_trans_type_encr_names_private_use2 = {
	OAKLEY_TWOFISH_CBC_SSH,
	OAKLEY_TWOFISH_CBC_SSH,
	ARRAY_REF(ikev2_trans_type_encr_name_private_use2),
	NULL
};

static enum_names ikev2_trans_type_encr_names_private_use1 = {
	OAKLEY_SERPENT_CBC,
	OAKLEY_TWOFISH_CBC,
	ARRAY_REF(ikev2_trans_type_encr_name_private_use1),
	&ikev2_trans_type_encr_names_private_use2
};

enum_names ikev2_trans_type_encr_names = {
	IKEv2_ENCR_DES_IV64,
	IKEv2_ENCR_CAMELLIA_CCM_C,
	ARRAY_REF(ikev2_trans_type_encr_name),
	&ikev2_trans_type_encr_names_private_use1
};

/* Transform-type PRF */
static const char *const ikev2_trans_type_prf_name[] = {
	"PRF_HMAC_MD5",
	"PRF_HMAC_SHA1",
	"PRF_HMAC_TIGER",
	"PRF_AES128-XCBC",
	/* RFC 4868 Section 4 */
	"PRF_HMAC_SHA2-256",
	"PRF_HMAC_SHA2-384",
	"PRF_HMAC_SHA2-512",
	"PRF_AES128_CMAC"
};
enum_names ikev2_trans_type_prf_names = {
	IKEv2_PRF_HMAC_MD5,
	IKEv2_PRF_AES128_CMAC,
	ARRAY_REF(ikev2_trans_type_prf_name),
	NULL
};

/* Transform-type Integrity */
static const char *const ikev2_trans_type_integ_name[] = {
	"AUTH_NONE",
	"AUTH_HMAC_MD5_96",
	"AUTH_HMAC_SHA1_96",
	"AUTH_DES_MAC",
	"AUTH_KPDK_MD5",
	"AUTH_AES_XCBC_96",
	"AUTH_HMAC_MD5_128",
	"AUTH_HMAC_SHA1_160",
	"AUTH_AES_CMAC_96",
	"AUTH_AES_128_GMAC",
	"AUTH_AES_192_GMAC",
	"AUTH_AES_256_GMAC",
	"AUTH_HMAC_SHA2_256_128",
	"AUTH_HMAC_SHA2_384_192",
	"AUTH_HMAC_SHA2_512_256",
};

enum_names ikev2_trans_type_integ_names = {
	IKEv2_AUTH_NONE,
	IKEv2_AUTH_HMAC_SHA2_512_256,
	ARRAY_REF(ikev2_trans_type_integ_name),
	NULL
};

/* Transform-type Integrity */
static const char *const ikev2_trans_type_esn_name[] = {
	"ESN_DISABLED",
	"ESN_ENABLED",
};

enum_names ikev2_trans_type_esn_names = {
	IKEv2_ESN_DISABLED,
	IKEv2_ESN_ENABLED,
	ARRAY_REF(ikev2_trans_type_esn_name),
	NULL
};

/* Transform Type */
static const char *const ikev2_trans_type_name[] = {
	"TRANS_TYPE_ENCR",
	"TRANS_TYPE_PRF",
	"TRANS_TYPE_INTEG",
	"TRANS_TYPE_DH",
	"TRANS_TYPE_ESN"
};

enum_names ikev2_trans_type_names = {
	IKEv2_TRANS_TYPE_ENCR,
	IKEv2_TRANS_TYPE_ESN,
	ARRAY_REF(ikev2_trans_type_name),
	NULL
};

/* for each IKEv2 transform attribute, which enum_names describes its values? */
static enum_names *const ikev2_transid_val_descs[] = {
	&ikev2_trans_type_encr_names,         /* 1 */
	&ikev2_trans_type_prf_names,          /* 2 */
	&ikev2_trans_type_integ_names,        /* 3 */
	&oakley_group_names,                  /* 4 */
	&ikev2_trans_type_esn_names,          /* 5 */
};

enum_enum_names v2_transform_ID_enums = {
	IKEv2_TRANS_TYPE_ENCR,	IKEv2_TRANS_TYPE_ESN,
	ARRAY_REF(ikev2_transid_val_descs)
};

/* Transform Attributes */
static const char *const ikev2_trans_attr_name[] = {
	"IKEv2_KEY_LENGTH",
};

enum_names ikev2_trans_attr_descs = {
	IKEv2_KEY_LENGTH + ISAKMP_ATTR_AF_TV,
	IKEv2_KEY_LENGTH + ISAKMP_ATTR_AF_TV,
	ARRAY_REF(ikev2_trans_attr_name),
	NULL
};

static ip_address ipv4_any, ipv6_any;
static ip_subnet ipv4_wildcard, ipv6_wildcard;
static ip_subnet ipv4_all, ipv6_all;

const struct af_info af_inet4_info = {
	AF_INET,
	"AF_INET",
	sizeof(struct in_addr),
	sizeof(struct sockaddr_in),
	32,
	ID_IPV4_ADDR, ID_IPV4_ADDR_SUBNET, ID_IPV4_ADDR_RANGE,
	&ipv4_any, &ipv4_wildcard, &ipv4_all,
};

const struct af_info af_inet6_info = {
	AF_INET6,
	"AF_INET6",
	sizeof(struct in6_addr),
	sizeof(struct sockaddr_in6),
	128,
	ID_IPV6_ADDR, ID_IPV6_ADDR_SUBNET, ID_IPV6_ADDR_RANGE,
	&ipv6_any, &ipv6_wildcard, &ipv6_all,
};

const struct af_info *aftoinfo(int af)
{
	switch (af) {
	case AF_INET:
		return &af_inet4_info;

	case AF_INET6:
		return &af_inet6_info;

	default:
		return NULL;
	}
}

bool subnetisnone(const ip_subnet *sn)
{
	ip_address base;

	networkof(sn, &base);
	return isanyaddr(&base) && subnetishost(sn);
}

/* BIND enumerated types */
#include <arpa/nameser.h>

static const char *const rr_type_name[] = {
	"T_A",		/* 1 host address */
	"T_NS",		/* 2 authoritative server */
	"T_MD",		/* 3 mail destination */
	"T_MF",		/* 4 mail forwarder */
	"T_CNAME",	/* 5 canonical name */
	"T_SOA",	/* 6 start of authority zone */
	"T_MB",		/* 7 mailbox domain name */
	"T_MG",		/* 8 mail group member */
	"T_MR",		/* 9 mail rename name */
	"T_NULL",	/* 10 null resource record */
	"T_WKS",	/* 11 well known service */
	"T_PTR",	/* 12 domain name pointer */
	"T_HINFO",	/* 13 host information */
	"T_MINFO",	/* 14 mailbox information */
	"T_MX",		/* 15 mail routing information */
	"T_TXT",	/* 16 text strings */
	"T_RP",		/* 17 responsible person */
	"T_AFSDB",	/* 18 AFS cell database */
	"T_X25",	/* 19 X_25 calling address */
	"T_ISDN",	/* 20 ISDN calling address */
	"T_RT",		/* 21 router */
	"T_NSAP",	/* 22 NSAP address */
	"T_NSAP_PTR",	/* 23 reverse NSAP lookup (deprecated) */
	"T_SIG",	/* 24 security signature */
	"T_KEY",	/* 25 security key */
	"T_PX",		/* 26 X.400 mail mapping */
	"T_GPOS",	/* 27 geographical position (withdrawn) */
	"T_AAAA",	/* 28 IP6 Address */
	"T_LOC",	/* 29 Location Information */
	"T_NXT",	/* 30 Next Valid Name in Zone */
	"T_EID",	/* 31 Endpoint identifier */
	"T_NIMLOC",	/* 32 Nimrod locator */
	"T_SRV",	/* 33 Server selection */
	"T_ATMA",	/* 34 ATM Address */
	"T_NAPTR",	/* 35 Naming Authority PoinTeR */
};

enum_names rr_type_names = {
	ns_t_a,
	ns_t_naptr,
	ARRAY_REF(rr_type_name),
	NULL
};

/* Query type values which do not appear in resource records */
static const char *const rr_qtype_name[] = {
	"T_TKEY",	/* 249 transaction key */
	"TSIG",		/* 250 transaction signature */
	"T_IXFR",	/* 251 incremental zone transfer */
	"T_AXFR",	/* 252 transfer zone of authority */
	"T_MAILB",	/* 253 transfer mailbox records */
	"T_MAILA",	/* 254 transfer mail agent records */
	"T_ANY",	/* 255 wildcard match */
};

enum_names rr_qtype_names = {
	ns_t_tkey,
	ns_t_any,
	ARRAY_REF(rr_qtype_name),
	&rr_type_names
};

static const char *const rr_class_name[] = {
	"C_IN",	/* 1 the arpa internet */
};

enum_names rr_class_names = {
	ns_c_in,
	ns_c_in,
	ARRAY_REF(rr_class_name),
	NULL
};

static const char *const ppk_name[] = {
	"PPK_PSK",
	"PPK_RSA",
	"PPK_XAUTH",
	"PPK_NULL",
};

enum_names ppk_names = {
	PPK_PSK,
	PPK_NULL,
	ARRAY_REF(ppk_name),
	NULL
};

/*
 * Values for right= and left=
 */
static struct keyword_enum_value kw_host_values[] = {
	{ "%defaultroute",  KH_DEFAULTROUTE },
	{ "%any",           KH_ANY },
	{ "%",              KH_IFACE },
	{ "%oppo",          KH_OPPO },
	{ "%opportunistic", KH_OPPO },
	{ "%opportunisticgroup", KH_OPPOGROUP },
	{ "%oppogroup",     KH_OPPOGROUP },
	{ "%group",         KH_GROUP },
	{ "%hostname",      KH_IPHOSTNAME }, /* makes no sense on input */
};

struct keyword_enum_values kw_host_list =
	{ kw_host_values, elemsof(kw_host_values) };

/* look up enum names in an enum_names */
const char *enum_name(enum_names *ed, unsigned long val)
{
	enum_names  *p;

	for (p = ed; p != NULL; p = p->en_next_range) {
		passert(p->en_last - p->en_first + 1 == p->en_checklen);
		if (p->en_first <= val && val <= p->en_last)
			return p->en_names[val - p->en_first];
	}

	return NULL;
}

/* find or construct a string to describe an enum value */
const char *enum_showb(enum_names *ed, unsigned long val, struct esb_buf *b)
{
	const char *p = enum_name(ed, val);

	if (p == NULL) {
		snprintf(b->buf, sizeof(b->buf), "%lu??", val);
		p = b->buf;
	}
	return p;
}

/*
 * find or construct a string to describe an enum value
 * Result may be in STATIC buffer -- NOT RE-ENTRANT!
 *
 * One consequence is that you cannot have two or more calls
 * as arguments in a single logging call.  Use enum_name instead.
 * (Of course that means that unnamed values will be shown
 * badly.)
 */
const char *enum_show(enum_names *ed, unsigned long val)
{
	static struct esb_buf buf;	/* only one! NON-RE-ENTRANT */

	return enum_showb(ed, val, &buf);
}

/* sometimes the prefix gets annoying */
const char *strip_prefix(const char *s, const char *prefix)
{
	size_t pl = strlen(prefix);

	return (s != NULL && strneq(s, prefix, pl)) ? s + pl : s;
}

/*
 * Find the value for a name in an enum_names table.  If not found, returns -1.
 *
 * Strings are compared without regard to case.
 *
 * ??? the table contains unsigned long values BUT the function returns an
 * int so there is some potential for overflow.
 */
int enum_search(enum_names *ed, const char *str)
{
	enum_names  *p;

	for (p = ed; p != NULL; p = p->en_next_range) {
		unsigned long en;

		passert(p->en_last - p->en_first + 1 == p->en_checklen);
		for (en = p->en_first; en <= p->en_last; en++) {
			const char *ptr = p->en_names[en - p->en_first];

			if (ptr != NULL && strcaseeq(ptr, str)) {
				passert(en <= INT_MAX);
				return en;
			}
		}
	}
	return -1;
}


/* choose table from struct enum_enum_names */
enum_names *enum_enum_table(enum_enum_names *een,
			    unsigned long table)
{
	passert(een->een_last - een->een_first + 1 == een->een_checklen);

	if (een->een_first <= table && table <= een->een_last) {
		return een->een_enum_name[table - een->een_first];
	} else {
		return NULL;
	}
}

const char *enum_enum_name(enum_enum_names *een, unsigned long table,
			   unsigned long val)
{
	if (een == NULL) {
		return NULL;
	}
	enum_names *en = enum_enum_table(een, table);
	if (en == NULL) {
		return NULL;
	}
	return enum_name(en, val);
}

const char *enum_enum_showb(enum_enum_names *een, unsigned long table,
			    unsigned long val, struct esb_buf *b)
{
	const char *name = enum_enum_name(een, table, val);
	if (name != NULL) {
		return name;
	}
	snprintf(b->buf, sizeof(b->buf), "%lu??", val);
	return b->buf;
}


/*
 * construct a string to name the bits on in a set
 *
 * Result of bitnamesof may be in STATIC buffer -- NOT RE-ENTRANT!
 * Note: prettypolicy depends on internal details of bitnamesofb.
 * binamesofb is re-entrant since the caller provides the buffer.
 */
const char *bitnamesofb(const char *const table[], lset_t val,
			char *b, size_t blen)
{
	char *const roof = b + blen;
	char *p = b;
	lset_t bit;
	const char *const *tp;

	passert(blen != 0); /* need room for NUL */

	/* if nothing gets filled in, default to "none" rather than "" */
	(void) jam_str(p, (size_t)(roof - p), "none");

	for (tp = table, bit = 01; val != 0; bit <<= 1) {
		if (val & bit) {
			const char *n = *tp;

			if (p != b)
				p = jam_str(p, (size_t)(roof - p), "+");

			if (n == NULL || *n == '\0') {
				/*
				 * No name for this bit, so use hex.
				 * if snprintf returns a different value from
				 * strlen, truncation happened
				 */
				(void)snprintf(p, (size_t)(roof - p),
					"0x%" PRIxLSET,
					bit);
				p += strlen(p);
			} else {
				p = jam_str(p, (size_t)(roof - p), n);
			}
			val -= bit;
		}
		/*
		 * Move on in the table, but not past end.
		 * This is a bit of a trick: while we are at stuck the end,
		 * the loop will print out the remaining bits in hex.
		 */
		if (*tp != NULL)
			tp++;
	}
	return b;
}

/*
 * NOT RE-ENTRANT!
 */
const char *bitnamesof(const char *const table[], lset_t val)
{
	static char bitnamesbuf[8192]; /* I hope that it is big enough! */

	return bitnamesofb(table, val, bitnamesbuf, sizeof(bitnamesbuf));
}

/* test a set by seeing if all bits have names */
bool testset(const char *const table[], lset_t val)
{
	lset_t bit;
	const char *const *tp;

	for (tp = table, bit = 01; val != 0; bit <<= 1, tp++) {
		const char *n = *tp;

		if (n == NULL || ((val & bit) && *n == '\0'))
			return FALSE;

		val &= ~bit;
	}
	return TRUE;
}

const char sparse_end[] = "end of sparse names";

/* look up enum names in a sparse_names */
const char *sparse_name(sparse_names sd, unsigned long val)
{
	const struct sparse_name *p;

	for (p = sd; p->name != sparse_end; p++)
		if (p->val == val)
			return p->name;

	return NULL;
}

/*
 * find or construct a string to describe an sparse value
 *
 * Result may be in STATIC buffer -- NOT RE-ENTRANT!
 */
const char *sparse_val_show(sparse_names sd, unsigned long val)
{
	const char *p = sparse_name(sd, val);

	if (p == NULL) {
		/* only one!  I hope that it is big enough */
		static char buf[12];

		snprintf(buf, sizeof(buf), "%lu??", val);
		p = buf;
	}
	return p;
}

/* registry of enum_names: allows consistency checking at startup */
static const enum_names *en_checklist[] = {
	&version_names,
	&doi_names,
	&connection_kind_names,
	&ikev1_payload_names,
	&ikev2_payload_names,
	&payload_names_ikev1orv2,
	&ikev2_last_proposal_desc,
	&ikev1_exchange_names,
	&exchange_names_ikev1orv2,
	&ikev1_protocol_names,
	&ikev2_protocol_names,
	&ikev2_del_protocol_names,
	&isakmp_transformid_names,
	&ah_transformid_names,
	&esp_transformid_names,
	&ipcomp_transformid_names,
	&ike_idtype_names,
	&ikev2_idtype_names,
	&ike_cert_type_names,
	&ikev2_cert_type_names,
	&certpolicy_type_names,
	&oakley_attr_names,
	&ipsec_attr_names,
	&sa_lifetime_names,
	&enc_mode_names,
	&auth_alg_names,
	&xauth_type_names,
	&modecfg_attr_names,
	&oakley_lifetime_names,
	&oakley_prf_names,
	&oakley_enc_names,
	&oakley_hash_names,
	&oakley_auth_names,
	&ikev2_cp_attribute_type_names,
	&ikev2_cp_type_names,
	&ikev2_auth_names,
	&oakley_group_names,
	&oakley_group_type_names,
	&ikev1_notify_names,
	&ikev2_notify_names,
	&ikev2_ts_type_names,
	&attr_msg_type_names,
	&ikev2_sec_proto_id_names,
	&ikev2_trans_type_encr_names,
	&ikev2_trans_type_prf_names,
	&ikev2_trans_type_integ_names,
	&ikev2_trans_type_esn_names,
	&ikev2_trans_type_names,
	&ikev2_trans_attr_descs,
	&rr_qtype_names,
	&rr_class_names,
	&ppk_names,
};

void check_enum_names(enum_names *checklist[], size_t tl)
{
	/* check that enum_names are well-formed */
	size_t i;

	for (i = 0; i != tl; i++) {
		/*
		 * enum_name will check all linked enum_names
		 * if given a value that isn't covered.
		 * -42 is probably not covered.
		 */
		(void) enum_name(checklist[i], -42UL);
	}
}

void init_constants(void)
{
	happy(anyaddr(AF_INET, &ipv4_any));
	happy(anyaddr(AF_INET6, &ipv6_any));

	happy(addrtosubnet(&ipv4_any, &ipv4_wildcard));
	happy(addrtosubnet(&ipv6_any, &ipv6_wildcard));

	happy(initsubnet(&ipv4_any, 0, '0', &ipv4_all));
	happy(initsubnet(&ipv6_any, 0, '0', &ipv6_all));

	check_enum_names(ARRAY_REF(en_checklist));

	/* check v2_transform_ID_enums, the only enum_enum_names */
	(void) enum_enum_table(&v2_transform_ID_enums, -42UL);
}
