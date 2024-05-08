/*
 * tables of names for values defined in constants.h
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

/*
 * Note that the array sizes are all specified; this is to enable range
 * checking by code that only includes constants.h.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <netinet/in.h>

#include <ietf_constants.h>
#include "passert.h"

#include "constants.h"
#include "enum_names.h"
#include "lswlog.h"
#include "ip_said.h"		/* for SPI_PASS et.al. */
#include "secrets.h"		/* for enum privae_key_kind */
#include "encap_mode.h"
#include "encap_proto.h"
#include "initiated_by.h"
#include "connection_owner.h"

const char *bool_str(bool b)
{
	return b ? "yes" : "no";
}

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

static const char *const perspective_name[] = {
	[NO_PERSPECTIVE] = "NO_PERSPECTIVE",
	[LOCAL_PERSPECTIVE] = "LOCAL_PERSPECTIVE",
	[REMOTE_PERSPECTIVE] = "REMOTE_PERSPECTIVE"
};

enum_names perspective_names = {
	NO_PERSPECTIVE, REMOTE_PERSPECTIVE,
	ARRAY_REF(perspective_name),
	NULL, /* prefix */
	NULL,
};

static const char *const shunt_policy_name[] = {
#define A(S) [S] = #S
	A(SHUNT_UNSET),
	A(SHUNT_IPSEC),
	A(SHUNT_HOLD),
	A(SHUNT_NONE),
	A(SHUNT_PASS),
	A(SHUNT_DROP),
	A(SHUNT_REJECT),
	A(SHUNT_TRAP),
#undef A
};

enum_names shunt_policy_names = {
	SHUNT_UNSET, SHUNT_POLICY_ROOF-1,
	ARRAY_REF(shunt_policy_name),
	"SHUNT_", /* prefix */
	NULL,
};

static const char *const shunt_kind_name[] = {
#define A(S) [S] = #S
	A(SHUNT_KIND_NONE),
	A(SHUNT_KIND_NEVER_NEGOTIATE),
	A(SHUNT_KIND_ONDEMAND),
	A(SHUNT_KIND_NEGOTIATION),
	A(SHUNT_KIND_IPSEC),
	A(SHUNT_KIND_FAILURE),
	A(SHUNT_KIND_BLOCK),
#undef A
};

enum_names shunt_kind_names = {
	0, SHUNT_KIND_ROOF-1,
	ARRAY_REF(shunt_kind_name),
	"SHUNT_KIND_", /*PREFIX*/
	NULL,
};

static const char *const shunt_policy_percent_name[] = {
	[SHUNT_UNSET] = "<shunt-unset>",
	[SHUNT_HOLD] = "%hold",
	[SHUNT_NONE] = "%none",
	[SHUNT_PASS] = "%pass",
	[SHUNT_DROP] = "%drop",
	[SHUNT_REJECT] = "%reject",
	[SHUNT_TRAP] = "%trap",
};

enum_names shunt_policy_percent_names = {
	SHUNT_UNSET, SHUNT_POLICY_ROOF-1,
	ARRAY_REF(shunt_policy_percent_name),
	"%"/*prefix*/,
	NULL,
};

/* NAT methods */
static const char *const natt_method_name[] = {
	"none",
	"draft-ietf-ipsec-nat-t-ike-02/03",
	"draft-ietf-ipsec-nat-t-ike-05",
	"RFC 3947 (NAT-Traversal)",

	"I am behind NAT",
	"peer behind NAT",
};

enum_names natt_method_names = {
	NAT_TRAVERSAL_METHOD_none, NATED_PEER,
	ARRAY_REF(natt_method_name),
	NULL, /* prefix */
	NULL
};

static const char *const allow_global_redirect_name[] = {
	"no",
	"yes",
	"auto",
};

enum_names allow_global_redirect_names = {
	GLOBAL_REDIRECT_NO,
	GLOBAL_REDIRECT_AUTO,
	ARRAY_REF(allow_global_redirect_name),
	NULL,
	NULL
};

static const char *const dns_auth_level_name[] = {
	"PUBKEY_LOCAL",
	"DNSSEC_INSECURE",
	"DNSSEC_SECURE",
};

enum_names dns_auth_level_names = {
	PUBKEY_LOCAL, DNSSEC_ROOF-1,
	ARRAY_REF(dns_auth_level_name),
	NULL, /* prefix */
	NULL
};

static const char *connection_event_kind_name[] = {
#define S(E) [E - 1] = #E
	S(CONNECTION_REVIVAL),
#undef S
};

const struct enum_names connection_event_kind_names = {
	1, CONNECTION_REVIVAL,
	ARRAY_REF(connection_event_kind_name),
	"CONNECTION_", NULL,
};

/*
 * Names for sa_policy_bits.
 */
static const char *const sa_policy_bit_name[] = {
#define P(N) [N##_IX] = #N
	P(POLICY_ENCRYPT),
	P(POLICY_AUTHENTICATE),
	P(POLICY_COMPRESS),
	P(POLICY_TUNNEL),
	P(POLICY_PFS),
#undef P
};

enum_names sa_policy_bit_names = {
	0, POLICY_IX_LAST,
	ARRAY_REF(sa_policy_bit_name),
	"POLICY_", /* prefix */
	NULL
};

/* systemd watchdog action names */
static const char *const sd_action_name[] = {
	"action: exit", /* daemon exiting */
	"action: start", /* daemon starting */
	"action: watchdog", /* the keepalive watchdog ping */
	"action: reloading", /* the keepalive watchdog ping */
	"action: ready", /* the keepalive watchdog ping */
	"action: stopping", /* the keepalive watchdog ping */
};
enum_names sd_action_names = {
	PLUTO_SD_EXIT, PLUTO_SD_STOPPING,
	ARRAY_REF(sd_action_name),
	NULL, /* prefix */
	NULL
};

static const char *const keyword_auth_name[] = {
	"unset",
	"never",
	"secret",
	"rsasig",
	"ecdsa",
	"null",
	"eaponly",
};

enum_names keyword_auth_names = {
	AUTH_UNSET, AUTH_EAPONLY,
	ARRAY_REF(keyword_auth_name),
	NULL, /* prefix */
	NULL
};

static const char *const stf_status_strings[] = {
#define A(S) [S] = #S
	A(STF_SKIP_COMPLETE_STATE_TRANSITION),
	A(STF_IGNORE),
	A(STF_SUSPEND),
	A(STF_OK),
	A(STF_INTERNAL_ERROR),
	A(STF_OK_INITIATOR_DELETE_IKE),
	A(STF_OK_RESPONDER_DELETE_IKE),
	A(STF_OK_INITIATOR_SEND_DELETE_IKE),
	A(STF_FATAL),
	A(STF_FAIL_v1N),
#undef A
};

enum_names stf_status_names = {
	0, elemsof(stf_status_strings)-1,
	ARRAY_REF(stf_status_strings),
	NULL, /* prefix */
	NULL
};

static const char *const keyword_host_name_ipaddr[] = {
	"KH_IPADDR",
};

static enum_names keyword_host_names_ipaddr = {
	KH_IPADDR, KH_IPADDR,
	ARRAY_REF(keyword_host_name_ipaddr),
	"KH_", /* prefix */
	NULL
};

static const char *const keyword_host_name[] = {
#define P(N) [N] = #N
	P(KH_NOTSET),
	P(KH_DEFAULTROUTE),
	P(KH_ANY),
	P(KH_IFACE),
	P(KH_OPPO),
	P(KH_OPPOGROUP),
	P(KH_GROUP),
	P(KH_IPHOSTNAME),
#undef P
};

enum_names keyword_host_names = {
	KH_NOTSET, KH_IPHOSTNAME,
	ARRAY_REF(keyword_host_name),
	"KH_", /* prefix */
	&keyword_host_names_ipaddr,
};

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
	NULL, /* prefix */
	NULL
};

enum_names version_names = {
	IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION,
	IKEv2_MAJOR_VERSION << ISA_MAJ_SHIFT | IKEv2_MINOR_VERSION,
	ARRAY_REF(version_name_2),
	NULL, /* prefix */
	&version_names_1
};

/*
 * IKEv1 vs IKEv2 language.
 */

static const char *const ike_version_name[] = {
	"<do-not-negotiate>",
	"IKEv1",
	"IKEv2",
};

enum_names ike_version_names = {
	0, IKEv2,
	ARRAY_REF(ike_version_name),
	"IKE", /* prefix */
	NULL,
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
	NULL, /* prefix */
	NULL
};

/* kind of struct connection */
static const char *const connection_kind_name[] = {
#define S(E) [E] = #E
	S(CK_INVALID),
	S(CK_GROUP),		/* policy group: instantiates to template */
	S(CK_TEMPLATE),		/* abstract connection, with wildcard */
	S(CK_PERMANENT),	/* normal connection */
	S(CK_INSTANCE),		/* instance of template */
	S(CK_LABELED_TEMPLATE),
	S(CK_LABELED_PARENT),
	S(CK_LABELED_CHILD),
#undef S
};

enum_names connection_kind_names = {
	CK_INVALID,
	CONNECTION_KIND_ROOF - 1,
	ARRAY_REF(connection_kind_name),
	"CK_", /* prefix */
	NULL
};

/* Payload types (RFC 2408 "ISAKMP" section 3.1) */
static const char *const payload_name_ikev1[] = {
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
	"ISAKMP_NEXT_", /* prefix */
	NULL
};

enum_names ikev1_payload_names = {
	ISAKMP_NEXT_NONE,
	ISAKMP_NEXT_GAP,
	ARRAY_REF(payload_name_ikev1),
	"ISAKMP_NEXT_", /* prefix */
	&payload_names_ikev1_private_use
};

static const char *const payload_name_ikev2[] = {
	"ISAKMP_NEXT_v2NONE", /* same for IKEv1 */
};

/* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-2 */
static const char *const payload_name_ikev2_main[] = {
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
	NULL, /* prefix */
	NULL
};

static enum_names payload_names_ikev2_main = {
	ISAKMP_NEXT_v2SA,
	ISAKMP_NEXT_v2SKF,
	ARRAY_REF(payload_name_ikev2_main),
	NULL, /* prefix */
	&payload_names_ikev2_private_use
};

enum_names ikev2_payload_names = {
	ISAKMP_NEXT_v2NONE,
	ISAKMP_NEXT_v2NONE,
	ARRAY_REF(payload_name_ikev2),
	"ISAKMP_NEXT_v2", /* prefix */
	&payload_names_ikev2_main
};

/* either V1 or V2 payload kind */
static enum_names payload_names_ikev2copy_main = {
	ISAKMP_NEXT_v2SA,
	ISAKMP_NEXT_v2SKF,
	ARRAY_REF(payload_name_ikev2_main),
	NULL, /* prefix */
	&payload_names_ikev1_private_use
};

enum_names payload_names_ikev1orv2 = {
	ISAKMP_NEXT_NONE,
	ISAKMP_NEXT_GAP,
	ARRAY_REF(payload_name_ikev1),
	NULL, /* prefix */
	&payload_names_ikev2copy_main
};

static enum_names *const payload_type_names_table[] = {
	[IKEv1 - IKEv1] = &ikev1_payload_names,
	[IKEv2 - IKEv1] = &ikev2_payload_names,
};

enum_enum_names payload_type_names = {
	IKEv1, IKEv2,
	ARRAY_REF(payload_type_names_table)
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
	NULL, /* prefix */
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
	NULL, /* prefix */
	NULL
};

/* Exchange types (note: two discontinuous ranges) */
static const char *const ikev1_exchange_name[] = {
	"ISAKMP_XCHG_NONE",
	"ISAKMP_XCHG_BASE",
	"ISAKMP_XCHG_IDPROT",
	"ISAKMP_XCHG_AO",
	"ISAKMP_XCHG_AGGR",
	"ISAKMP_XCHG_INFO",
	"ISAKMP_XCHG_MODE_CFG",	/* 6 - draft, not RFC */
};

static const char *const ikev1_exchange_doi_name[] = {
	"ISAKMP_XCHG_QUICK",	/* 32 */
	"ISAKMP_XCHG_NGRP",
};

static enum_names ikev1_exchange_doi_names = {
	ISAKMP_XCHG_QUICK,
	ISAKMP_XCHG_NGRP,
	ARRAY_REF(ikev1_exchange_doi_name),
	NULL, /* prefix */
	NULL,
};

enum_names ikev1_exchange_names = {
	ISAKMP_XCHG_NONE,
	ISAKMP_XCHG_MODE_CFG,
	ARRAY_REF(ikev1_exchange_name),
	"ISAKMP_XCHG_", /* prefix */
	&ikev1_exchange_doi_names
};

static enum_names isakmp_xchg_type_doi_and_v2_names = {
	ISAKMP_XCHG_QUICK,
	ISAKMP_XCHG_NGRP,
	ARRAY_REF(ikev1_exchange_doi_name),
	NULL, /* prefix */
	&ikev2_exchange_names,
};

enum_names isakmp_xchg_type_names = {
	ISAKMP_XCHG_NONE,
	ISAKMP_XCHG_MODE_CFG,
	ARRAY_REF(ikev1_exchange_name),
	NULL, /* prefix */
	&isakmp_xchg_type_doi_and_v2_names,
};

/* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-1 */
static const char *const ikev2_exchange_name[] = {
#define S(E) [E-IKEv2_EXCHANGE_FLOOR] = #E
	S(ISAKMP_v2_IKE_SA_INIT),
	S(ISAKMP_v2_IKE_AUTH),
	S(ISAKMP_v2_CREATE_CHILD_SA),
	S(ISAKMP_v2_INFORMATIONAL),
	S(ISAKMP_v2_IKE_SESSION_RESUME),
	S(ISAKMP_v2_GSA_AUTH),
	S(ISAKMP_v2_GSA_REGISTRATION),
	S(ISAKMP_v2_GSA_REKEY),
	S(ISAKMP_v2_IKE_INTERMEDIATE),
	S(ISAKMP_v2_IKE_FOLLOWUP_KE),
#undef S
};

const struct enum_names ikev2_exchange_names = {
	IKEv2_EXCHANGE_FLOOR,
	IKEv2_EXCHANGE_ROOF-1,
	ARRAY_REF(ikev2_exchange_name),
	"ISAKMP_v2_", /* prefix */
	NULL,
};

static enum_names *const exchange_type_names_table[] = {
	[IKEv1 - IKE_VERSION_FLOOR] = &ikev1_exchange_names,
	[IKEv2 - IKE_VERSION_FLOOR] = &ikev2_exchange_names,
};

enum_enum_names exchange_type_names = {
	IKE_VERSION_FLOOR, IKE_VERSION_ROOF-1,
	ARRAY_REF(exchange_type_names_table),
};

/* Flag BITS */
static const char *const isakmp_flag_name[] = {
	"ISAKMP_FLAG_v1_ENCRYPTION", /* IKEv1 only bit 0 */
	"ISAKMP_FLAG_v1_COMMIT", /* IKEv1 only bit 1 */
	"ISAKMP_FLAG_v1_AUTHONLY", /* IKEv1 only bit 2 */
	"ISAKMP_FLAG_v2_IKE_INIT", /* IKEv2 only bit 3 */
	"ISAKMP_FLAG_v2_VERSION", /* IKEv2 only bit 4 */
	"ISAKMP_FLAG_v2_MSG_RESPONSE", /* IKEv2 only bit 5 */
	"ISAKMP_FLAG_MSG_RESERVED_BIT6",
	"ISAKMP_FLAG_MSG_RESERVED_BIT7",
};

const struct enum_names isakmp_flag_names = {
	ISAKMP_FLAGS_v1_ENCRYPTION_IX,
	ISAKMP_FLAGS_RESERVED_BIT7_IX,
	ARRAY_REF(isakmp_flag_name),
	NULL, /* prefix */
	NULL, /* next */
};


/* Situation BITS definition for IPsec DOI */

static const char *const sit_bit_name[] = {
#define P(N) [N##_IX] = #N
	P(SIT_IDENTITY_ONLY),
	P(SIT_SECRECY),
	P(SIT_INTEGRITY),
#undef P
};

const struct enum_names sit_bit_names = {
	SIT_IDENTITY_ONLY_IX,
	SIT_INTEGRITY_IX,
	ARRAY_REF(sit_bit_name),
	NULL, /* prefix */
	NULL, /* next */
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
	NULL, /* prefix */
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
	NULL, /* prefix */
	NULL
};

/* IPsec AH transform values */

static const char *const ah_transform_name_private_use[] = {
	"AH_AES_CMAC_96",
	"AH_NULL",	/* verify with kame source? 251 */
	"AH_SHA2_256_TRUNC",	/* our own to signal bad truncation to kernel */
};

static enum_names ah_transformid_names_private_use = {
	AH_AES_CMAC_96,
	AH_SHA2_256_TRUNCBUG,
	ARRAY_REF(ah_transform_name_private_use),
	NULL, /* prefix */
	NULL
};

static const char *const ah_transform_name[] = {
	/* 0-1 RESERVED */
	"AH_MD5",
	"AH_SHA",
	"AH_DES(UNUSED)",
	"AH_SHA2_256",
	"AH_SHA2_384",
	"AH_SHA2_512",
	"AH_RIPEMD",
	"AH_AES_XCBC_MAC",
	"AH_RSA(UNUSED)",
	"AH_AES_128_GMAC",	/* RFC4543 Errata1821 */
	"AH_AES_192_GMAC",	/* RFC4543 Errata1821 */
	"AH_AES_256_GMAC",	/* RFC4543 Errata1821 */
	/* 14-248 Unassigned */
	/* 249-255 Reserved for private use */
};

enum_names ah_transformid_names = {
	AH_MD5, AH_AES_256_GMAC,
	ARRAY_REF(ah_transform_name),
	"AH_", /* prefix */
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
	"ESP_RC6(UNUSED)",
	"ESP_KAME_NULL",
	"ESP_SERPENT",
	"ESP_TWOFISH",
	"ESP_ID254(UNUSED)",
	"ESP_ID255(UNUSED)",
};

static enum_names esp_transformid_names_private_use = {
	ESP_MARS,
	ESP_ID255,
	ARRAY_REF(esp_transform_name_private_use),
	NULL, /* prefix */
	NULL
};

/* This tracks the IKEv2 registry now! see ietf_constants.h */
static const char *const esp_transform_name[] = {
	"ESP_DES_IV64(UNUSED)",	/* 1 - old DES */
	"ESP_DES(UNUSED)",	/* obsoleted */
	"ESP_3DES",
	"ESP_RC5(UNUSED)",
	"ESP_IDEA(UNUSED)",
	"ESP_CAST",
	"ESP_BLOWFISH(UNUSED)",	/* obsoleted */
	"ESP_3IDEA(UNUSED)",
	"ESP_DES_IV32(UNUSED)",
	"ESP_RC4(UNUSED)",
	"ESP_NULL",
	"ESP_AES",
	"ESP_AES_CTR",
	"ESP_AES_CCM_A",
	"ESP_AES_CCM_B",
	"ESP_AES_CCM_C",
	"ESP_UNUSED_ID17",
	"ESP_AES_GCM_A",
	"ESP_AES_GCM_B",
	"ESP_AES_GCM_C",
	"ESP_SEED_CBC", /* IKEv2 is NULL_AUTH_AES_GMAC */
	"ESP_CAMELLIA",
	"ESP_NULL_AUTH_AES_GMAC", /* IKEv2 is CAMELLIA_CBC */
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
	"ESP_", /* prefix */
	&esp_transformid_names_private_use
};

/* IPCOMP transform values */
static const char *const ipsec_ipcomp_algo_name[] = {
#define P(N) [N] = #N
	P(IPCOMP_NONE),
	P(IPCOMP_OUI),
	P(IPCOMP_DEFLATE),
	P(IPCOMP_LZS),
	P(IPCOMP_LZJH),
	/* 5-47 Reserved for approved algorithms */
	/* 48-63 Reserved for private use */
	/* 64-255 Unassigned */
#undef P
};

enum_names ipsec_ipcomp_algo_names = {
	IPCOMP_NONE,
	IPCOMP_LZJH,
	ARRAY_REF(ipsec_ipcomp_algo_name),
	"IPCOMP_", /* prefix */
	NULL
};

/*
 * IANA IKEv2 Hash Algorithms
 * https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#hash-algorithms
 */
static const char *const ikev2_hash_algorithm_name[] = {
	"IKEv2_HASH_ALGORITHM_RESERVED",
	"IKEv2_HASH_ALGORITHM_SHA1",
	"IKEv2_HASH_ALGORITHM_SHA2_256",
	"IKEv2_HASH_ALGORITHM_SHA2_384",
	"IKEv2_HASH_ALGORITHM_SHA2_512",
	"IKEv2_HASH_ALGORITHM_IDENTITY"
	/* 6-1023 Unassigned */
};

enum_names ikev2_hash_algorithm_names = {
	IKEv2_HASH_ALGORITHM_RESERVED,
	IKEv2_HASH_ALGORITHM_IDENTITY,
	ARRAY_REF(ikev2_hash_algorithm_name),
	"IKEv2_HASH_ALGORITHM_", /* prefix */
	NULL
};

/* Identification type values */

static const char *const ike_idtype_name[] = {
	/* private to Pluto */
	"%fromcert",	/* -1, ID_FROMCERT:taken from certificate */
	"%none",	/* 0, ID_NONE */

	/* standardized */
	"ID_IPV4_ADDR",	/* 1 */
	"ID_FQDN",
	"ID_USER_FQDN",
	"ID_IPV4_ADDR_SUBNET", /* v1 only */
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

/*
 * Local boilerplate macro for idtype name range initializer.
 * - macro is undef'ed very shortly
 * - not function-like since it expands to a struct initializer
 * - first entry in ike_idtype_name corresponds to ID_FROMCERT
 */
#define ID_NR(from,to,next) { \
		(from), (to), \
		&ike_idtype_name[(from)-ID_FROMCERT], (to)-(from) + 1, \
		NULL, /* prefix */ \
		next \
	}

/* IKEv1 */
enum_names ikev1_ike_id_type_names = ID_NR(ID_IPV4_ADDR, ID_NULL, NULL);

/*
 * all names, including private-to-pluto
 * Tricky: lower bound and uppers bound are treated as unsigned long
 * so we have to tack two ranges onto ike_idtype_names.
 *
 * XXX: why not treat them as longs?
 */
static enum_names ike_idtype_names_fromcert = ID_NR(ID_FROMCERT, ID_FROMCERT, NULL);
enum_names ike_id_type_names = ID_NR(ID_NONE, ID_NULL, &ike_idtype_names_fromcert);

/* IKEv2 names exclude ID_IPV4_ADDR_SUBNET, ID_IPV6_ADDR_SUBNET-ID_IPV6_ADDR_RANGE */

static enum_names ikev2_idtype_names_3 = ID_NR(ID_DER_ASN1_DN, ID_NULL,	NULL);
static enum_names ikev2_idtype_names_2 = ID_NR(ID_IPV6_ADDR, ID_IPV6_ADDR, &ikev2_idtype_names_3);
enum_names ikev2_ike_id_type_names = ID_NR(ID_IPV4_ADDR, ID_RFC822_ADDR, &ikev2_idtype_names_2);

#undef ID_NR

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
	"CERT_", /* prefix */
	NULL
};


static enum_names ikev2_cert_type_names_2 = {
	CERT_KERBEROS_TOKENS, CERT_RAW_PUBLIC_KEY,
	&ike_cert_type_name[CERT_KERBEROS_TOKENS-CERT_PKCS7_WRAPPED_X509],
	CERT_RAW_PUBLIC_KEY-CERT_KERBEROS_TOKENS+1,
	"CERT_", /* prefix */
	NULL
};

enum_names ikev2_cert_type_names = {
	CERT_PKCS7_WRAPPED_X509, CERT_X509_SIGNATURE,
	ike_cert_type_name,
	CERT_X509_SIGNATURE-CERT_PKCS7_WRAPPED_X509+1,
	"CERT_", /* prefix */
	&ikev2_cert_type_names_2
};

/*
 * certificate request payload policy
 */
static const char *const certpolicy_type_name[] = {
	"CERT_NEVERSEND",
	"CERT_SENDIFASKED",
	"CERT_ALWAYSSEND",
};

enum_names certpolicy_type_names = {
	CERT_NEVERSEND,
	CERT_ALWAYSSEND,
	ARRAY_REF(certpolicy_type_name),
	"CERT_", /* prefix */
	NULL
};

/*
 * Oakley transform attributes
 * oakley_attr_bit_names does double duty: it is used for enum names
 * and bit names.
 * https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-2
 */
static const char *const oakley_attr_bit_name[] = {
#define S(E) [E - OAKLEY_ENCRYPTION_ALGORITHM] = #E
	S(OAKLEY_ENCRYPTION_ALGORITHM),
	S(OAKLEY_HASH_ALGORITHM),
	S(OAKLEY_AUTHENTICATION_METHOD),
	S(OAKLEY_GROUP_DESCRIPTION),
	S(OAKLEY_GROUP_TYPE),
	S(OAKLEY_GROUP_PRIME),
	S(OAKLEY_GROUP_GENERATOR_ONE),
	S(OAKLEY_GROUP_GENERATOR_TWO),
	S(OAKLEY_GROUP_CURVE_A),
	S(OAKLEY_GROUP_CURVE_B),
	S(OAKLEY_LIFE_TYPE),
	S(OAKLEY_LIFE_DURATION),
	S(OAKLEY_PRF),
	S(OAKLEY_KEY_LENGTH),
	S(OAKLEY_FIELD_SIZE),
	S(OAKLEY_GROUP_ORDER),
#undef S
};

const struct enum_names oakley_attr_bit_names = {
	OAKLEY_ENCRYPTION_ALGORITHM,
	OAKLEY_GROUP_ORDER,
	ARRAY_REF(oakley_attr_bit_name),
	NULL, /*prefix*/
	NULL, /*next*/
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
	ARRAY_REF(oakley_attr_bit_name),
	NULL, /* prefix */
	NULL
};

enum_names oakley_attr_names = {
	OAKLEY_GROUP_PRIME,
	OAKLEY_GROUP_ORDER,
	ARRAY_REF(oakley_var_attr_name),
	NULL, /* prefix */
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
	"ECN_TUNNEL or old SECCTX",
	"ESN_64BIT_SEQNUM",
	"IKEv1_IPSEC_ATTR_UNSPEC_12", /* Maybe Tero knows why it was skipped? */
	"SIG_ENC_ALGO_VAL",
	"ADDRESS_PRESERVATION",
	"SA_DIRECTION",
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
	"NULL", /* ECN_TUNNEL_or_old_SECCTX */
	NULL, /* ESN_64BIT_SEQNUM */
	NULL, /* IKEv1_IPSEC_ATTR_UNSPEC_12 */
	NULL, /* SIG_ENC_ALGO_VAL */
	NULL, /* ADDRESS_PRESERVATION */
	NULL, /* SA_DIRECTION */
};

static const char *const ipsec_private_attr_name[] = {
	"SECCTX" /* 32001 */
};

static enum_names ipsec_private_attr_names_tv = {
	SECCTX + ISAKMP_ATTR_AF_TV,
	SECCTX + ISAKMP_ATTR_AF_TV,
	ARRAY_REF(ipsec_private_attr_name),
	NULL, /* prefix */
	NULL
};

static enum_names ipsec_private_attr_names = {
	SECCTX,
	SECCTX,
	ARRAY_REF(ipsec_private_attr_name),
	NULL, /* prefix */
	&ipsec_private_attr_names_tv
};

static enum_names ipsec_attr_desc_tv = {
	SA_LIFE_TYPE + ISAKMP_ATTR_AF_TV,
	SA_DIRECTION + ISAKMP_ATTR_AF_TV,
	ARRAY_REF(ipsec_attr_name),
	NULL, /* prefix */
	&ipsec_private_attr_names
};

enum_names ipsec_attr_names = {
	SA_LIFE_TYPE,
	SA_DIRECTION,
	ARRAY_REF(ipsec_var_attr_name),
	NULL, /* prefix */
	&ipsec_attr_desc_tv
};

/* for each IPsec attribute, which enum_names describes its values? */
enum_names *const ipsec_attr_val_descs[IPSEC_ATTR_VAL_DESCS_ROOF] = {
	NULL,	/* (none) */
	&sa_lifetime_names,	/* SA_LIFE_TYPE */
	NULL,	/* SA_LIFE_DURATION */
	&oakley_group_names,	/* GROUP_DESCRIPTION */
	&encapsulation_mode_names,
	&auth_alg_names,	/* AUTH_ALGORITHM */
	NULL,	/* KEY_LENGTH */
	NULL,	/* KEY_ROUNDS */
	NULL,	/* COMPRESS_DICT_SIZE */
	NULL,	/* COMPRESS_PRIVATE_ALG */
#ifdef HAVE_LABELED_IPSEC
	NULL,	/* ECN_TUNNEL_or_old_SECCTX */
#endif
	NULL, /* ESN_64BIT_SEQNUM */
	NULL, /* IKEv1_IPSEC_ATTR_UNSPEC_12 */
	NULL, /* SIG_ENC_ALGO_VAL */
	NULL, /* ADDRESS_PRESERVATION */
	NULL, /* SA_DIRECTION */
};

/* SA Lifetime Type attribute */
static const char *const sa_lifetime_name[] = {
	"SA_LIFE_TYPE_SECONDS",
	"SA_LIFE_TYPE_KBYTES",
};

enum_names sa_lifetime_names = {
	SA_LIFE_TYPE_SECONDS,
	SA_LIFE_TYPE_KBYTES,
	ARRAY_REF(sa_lifetime_name),
	NULL, /* prefix */
	NULL
};

/* Encapsulation Mode attribute */

static const char *const encapsulation_mode_draft_name[] = {
#define P(N) [N - ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS] = #N
	P(ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS),
	P(ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS),
#undef P
};

enum_names encapsulation_mode_draft_names = {
	ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS,
	ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS,
	ARRAY_REF(encapsulation_mode_draft_name),
	"ENCAPSULATION_MODE_", /* prefix */
	NULL,
};

static const char *const encapsulation_mode_rfc_name[] = {
#define P(N) [N - ENCAPSULATION_MODE_TUNNEL] = #N
	P(ENCAPSULATION_MODE_TUNNEL),
	P(ENCAPSULATION_MODE_TRANSPORT),
	P(ENCAPSULATION_MODE_UDP_TUNNEL_RFC),
	P(ENCAPSULATION_MODE_UDP_TRANSPORT_RFC),
#undef P
};

enum_names encapsulation_mode_names = {
	ENCAPSULATION_MODE_TUNNEL,
	ENCAPSULATION_MODE_UDP_TRANSPORT_RFC,
	ARRAY_REF(encapsulation_mode_rfc_name),
	"ENCAPSULATION_MODE_", /* prefix */
	&encapsulation_mode_draft_names,
};

/* Auth Algorithm attribute */

static const char *const auth_alg_name_stolen_use[] = {
	"AUTH_ALGORITHM_AES_CMAC_96",
	"AUTH_ALGORITHM_NULL_KAME",	/*
					 * according to our source code
					 * comments from jjo, needs
					 * verification
					 */
	"AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG",
};

static enum_names auth_alg_names_stolen_use = {
	AUTH_ALGORITHM_AES_CMAC_96,
	AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG,
	ARRAY_REF(auth_alg_name_stolen_use),
	NULL, /* prefix */
	NULL
};

/* these string names map via a lookup function to configuration strings */
static const char *const auth_alg_name[] = {
	"AUTH_ALGORITHM_NONE",	/* our own value, not standard */
	"AUTH_ALGORITHM_HMAC_MD5",
	"AUTH_ALGORITHM_HMAC_SHA1",
	"AUTH_ALGORITHM_DES_MAC(UNUSED)",
	"AUTH_ALGORITHM_KPDK(UNUSED)",
	"AUTH_ALGORITHM_HMAC_SHA2_256",
	"AUTH_ALGORITHM_HMAC_SHA2_384",
	"AUTH_ALGORITHM_HMAC_SHA2_512",
	"AUTH_ALGORITHM_HMAC_RIPEMD",
	"AUTH_ALGORITHM_AES_XCBC",
	"AUTH_ALGORITHM_SIG_RSA(UNUSED)",	/* RFC4359 */
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
	"AUTH_ALGORITHM_", /* prefix */
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
	NULL, /* prefix */
	NULL
};

/* IKEv1 XAUTH-STATUS attribute names */
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
	NULL, /* prefix */
	NULL
};

static const char *const modecfg_microsoft_attr_name[] = {
	"INTERNAL_IP4_SERVER",	/* 23456 */
	"INTERNAL_IP6_SERVER",
};
static enum_names modecfg_microsoft_attr_names = {
	IKEv1_INTERNAL_IP4_SERVER,
	IKEv1_INTERNAL_IP6_SERVER,
	ARRAY_REF(modecfg_microsoft_attr_name),
	NULL, /* prefix */
	&modecfg_cisco_attr_names
};

enum_names modecfg_attr_names = {
	IKEv1_INTERNAL_IP4_ADDRESS,
	IKEv1_HOME_AGENT_ADDRESS,
	ARRAY_REF(modecfg_attr_name_draft),
	NULL, /* prefix */
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
	NULL, /* prefix */
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
	NULL, /* prefix */
	NULL
};

/* Oakley PRF attribute (none defined) */
static enum_names oakley_prf_names = {
	1,
	0,
	NULL, 0,
	NULL, /* prefix */
	NULL
};

/*
 * IKEv1 Oakley Encryption Algorithm attribute
 * www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-4
 */

static const char *const oakley_enc_name[] = {
	"OAKLEY_DES_CBC(UNUSED)", /* obsoleted */
	"OAKLEY_IDEA_CBC(UNUSED)",
	"OAKLEY_BLOWFISH_CBC(UNUSED)", /* obsoleted */
	"OAKLEY_RC5_R16_B64_CBC(UNUSED)",
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
	NULL, /* prefix */
	NULL
};

static enum_names oakley_enc_names_private_use = {
	OAKLEY_MARS_CBC,
	OAKLEY_TWOFISH_CBC,
	ARRAY_REF(oakley_enc_name_private_use),
	NULL, /* prefix */
	&oakley_enc_names_private_use_ssh
};

enum_names oakley_enc_names = {
	OAKLEY_DES_CBC,
	OAKLEY_CAMELLIA_CCM_C,
	ARRAY_REF(oakley_enc_name),
	"OAKLEY_", /* prefix */
	&oakley_enc_names_private_use
};

/*
 * Oakley Hash Algorithm attribute
 * https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
 */

/* these string names map via a lookup function to configuration strings */
static const char *const oakley_hash_name[] = {
	/* 0 - RESERVED */
	"OAKLEY_MD5",
	"OAKLEY_SHA1",
	"OAKLEY_TIGER(UNUSED)",
	"OAKLEY_SHA2_256",	/* RFC 4878 */
	"OAKLEY_SHA2_384",	/* RFC 4878 */
	"OAKLEY_SHA2_512",	/* RFC 4878 */
	/* 7-65000 Unassigned */
	/* 65001-65535 Reserved for private use */
};

enum_names oakley_hash_names = {
	OAKLEY_MD5,
	OAKLEY_SHA2_512,
	ARRAY_REF(oakley_hash_name),
	"OAKLEY_", /* prefix */
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
	NULL, /* prefix */
	NULL
};

static enum_names oakley_auth_names_private_use = {
	XAUTHInitPreShared,
	XAUTHRespRSARevisedEncryption,
	ARRAY_REF(oakley_auth_name_private_use),
	NULL, /* prefix */
	&oakley_auth_names_private_use2
};

enum_names oakley_auth_names = {
	OAKLEY_PRESHARED_KEY,
	OAKLEY_ECDSA_P521,
	ARRAY_REF(oakley_auth_name),
	"OAKLEY_", /* prefix */
	&oakley_auth_names_private_use
};

/*
 * IKEv2 CP attribute name. Some of them are shared with XAUTH Attrib names.
 * https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-21
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
	"IKEv2_TIMEOUT_PERIOD_FOR_LIVENESS_CHECK", /* 3gpp */
	"IKEv2_INTERNAL_DNS_DOMAIN", /* draft-ietf-ipsecme-split-dns */
	"IKEv2_INTERNAL_DNSSEC_TA", /* draft-ietf-ipsecme-split-dns */
};

enum_names ikev2_cp_attribute_type_names = {
	IKEv2_CP_ATTR_RESERVED,
	IKEv2_INTERNAL_DNSSEC_TA,
	ARRAY_REF(ikev2_cp_attribute_type_name),
	NULL, /* prefix */
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
	NULL, /* prefix */
	NULL
};

/* ikev2 auth methods */
static const char *const ikev2_auth_method_name[] = {
#define E(S) [S] = #S
	E(IKEv2_AUTH_RESERVED),
	E(IKEv2_AUTH_RSA),
	[IKEv2_AUTH_PSK] = "IKEv2_AUTH_SHARED",
	E(IKEv2_AUTH_DSS_DIGITAL_SIGNATURE),
	/* 4 - 8 unassigned */
	E(IKEv2_AUTH_ECDSA_SHA2_256_P256),
	E(IKEv2_AUTH_ECDSA_SHA2_384_P384),
	E(IKEv2_AUTH_ECDSA_SHA2_512_P521),
	E(IKEv2_AUTH_GENERIC_SECURE_PASSWORD_AUTHENTICATION_METHOD), /* 12 - RFC 6467 */
	E(IKEv2_AUTH_NULL),
	E(IKEv2_AUTH_DIGSIG), /* 14 - RFC 7427 */
#undef E
};

enum_names ikev2_auth_method_names = {
	IKEv2_AUTH_RESERVED,
	IKEv2_AUTH_DIGSIG,
	ARRAY_REF(ikev2_auth_method_name),
	"IKEv2_AUTH_", /* prefix */
	NULL
};

/*
 * Oakley Group Description attribute
 * XXX: Shared for IKEv1 and IKEv2 (although technically there could
 * be differences we need to care about)
 */

/* these string names map via a lookup function to configuration strings */
static const char *const oakley_group_name[] = {
	"OAKLEY_GROUP_NONE", /* 0! RFC 7296 */
	"OAKLEY_GROUP_MODP768",
	"OAKLEY_GROUP_MODP1024",
	"OAKLEY_GROUP_GP155(UNUSED)",
	"OAKLEY_GROUP_GP185(UNUSED)",
	"OAKLEY_GROUP_MODP1536", /* RFC 3526 */
	"OAKLEY_GROUP_EC2N_2_1(UNUSED)", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_2(UNUSED)", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_3(UNUSED)", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_4(UNUSED)", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_5(UNUSED)", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_6(UNUSED)", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_7(UNUSED)", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_EC2N_2_8(UNUSED)", /* draft-ietf-ipsec-ike-ecc-groups */
	"OAKLEY_GROUP_MODP2048", /* RFC 3526 */
	"OAKLEY_GROUP_MODP3072", /* RFC 3526 */
	"OAKLEY_GROUP_MODP4096", /* RFC 3526 */
	"OAKLEY_GROUP_MODP6144", /* RFC 3526 */
	"OAKLEY_GROUP_MODP8192", /* RFC 3526 */
	"OAKLEY_GROUP_ECP_256", /* RFC 5903 */
	"OAKLEY_GROUP_ECP_384", /* RFC 5903 */
	"OAKLEY_GROUP_ECP_521", /* RFC 5903 */
	"OAKLEY_GROUP_DH22", /* RFC 5114 */
	"OAKLEY_GROUP_DH23", /* RFC 5114 */
	"OAKLEY_GROUP_DH24", /* RFC 5114 */
	"OAKLEY_GROUP_ECP_192", /* RFC 5114 */
	"OAKLEY_GROUP_ECP_224", /* RFC 5114 */
	"OAKLEY_GROUP_BRAINPOOL_P224R1", /* RFC 6932 */
	"OAKLEY_GROUP_BRAINPOOL_P256R1", /* RFC 6932 */
	"OAKLEY_GROUP_BRAINPOOL_P384R1", /* RFC 6932 */
	"OAKLEY_GROUP_BRAINPOOL_P512R1", /* RFC 6932 */
	"OAKLEY_GROUP_CURVE25519", /* RFC-ietf-ipsecme-safecurves-05 */
	"OAKLEY_GROUP_CURVE448", /* RFC-ietf-ipsecme-safecurves-05 */
	/* 33 - 32767 Unassigned */
	/* 32768 - 65535 Reserved for private use */
};

enum_names oakley_group_names = {
	OAKLEY_GROUP_NONE,
	OAKLEY_GROUP_CURVE448,
	ARRAY_REF(oakley_group_name),
	"OAKLEY_GROUP_", /* prefix */
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
	NULL, /* prefix */
	NULL
};

/* Notify message type -- RFC2408 3.14.1 */
static const char *const v1_notification_name[] = {
	"v1N_INVALID_PAYLOAD_TYPE", /* 1 */
	"v1N_DOI_NOT_SUPPORTED",
	"v1N_SITUATION_NOT_SUPPORTED",
	"v1N_INVALID_COOKIE",
	"v1N_INVALID_MAJOR_VERSION",
	"v1N_INVALID_MINOR_VERSION",
	"v1N_INVALID_EXCHANGE_TYPE",
	"v1N_INVALID_FLAGS",
	"v1N_INVALID_MESSAGE_ID",
	"v1N_INVALID_PROTOCOL_ID",
	"v1N_INVALID_SPI",
	"v1N_INVALID_TRANSFORM_ID",
	"v1N_ATTRIBUTES_NOT_SUPPORTED",
	"v1N_NO_PROPOSAL_CHOSEN",
	"v1N_BAD_PROPOSAL_SYNTAX",
	"v1N_PAYLOAD_MALFORMED",
	"v1N_INVALID_KEY_INFORMATION",
	"v1N_INVALID_ID_INFORMATION",
	"v1N_INVALID_CERT_ENCODING",
	"v1N_INVALID_CERTIFICATE",
	"v1N_CERT_TYPE_UNSUPPORTED",
	"v1N_INVALID_CERT_AUTHORITY",
	"v1N_INVALID_HASH_INFORMATION",
	"v1N_AUTHENTICATION_FAILED",
	"v1N_INVALID_SIGNATURE",
	"v1N_ADDRESS_NOTIFICATION",
	"v1N_NOTIFY_SA_LIFETIME",
	"v1N_CERTIFICATE_UNAVAILABLE",
	"v1N_UNSUPPORTED_EXCHANGE_TYPE",
	"v1N_UNEQUAL_PAYLOAD_LENGTHS",
};

static const char *const v1_notification_connected_name[] = {
	"v1N_CONNECTED", /* 16384 */
};

static const char *const v1_notification_ipsec_name[] = {
	"v1N_IPSEC_RESPONDER_LIFETIME", /* 24576 */
	"v1N_IPSEC_REPLAY_STATUS",
	"v1N_IPSEC_INITIAL_CONTACT",
};

static const char *const v1_notification_cisco_chatter_name[] = {
	"v1N_ISAKMP_N_CISCO_HELLO", /* 30000 */
	"v1N_ISAKMP_N_CISCO_WWTEBR",
	"v1N_ISAKMP_N_CISCO_SHUT_UP",
};

static const char *const v1_notification_ios_alives_name[] = {
	"v1N_ISAKMP_N_IOS_KEEP_ALIVE_REQ", /* 32768 */
	"v1N_ISAKMP_N_IOS_KEEP_ALIVE_ACK",
};

static const char *const v1_notification_dpd_name[] = {
	"v1N_R_U_THERE", /* 36136 */
	"v1N_R_U_THERE_ACK",
};

static const char *const v1_notification_juniper_name[] = {
	/* Next Hop Tunnel Binding */
	"v1N_NETSCREEN_NHTB_INFORM", /* 40001 */
};

static const char *const v1_notification_cisco_more_name[] = {
	"v1N_ISAKMP_N_CISCO_LOAD_BALANCE", /* 40501 */
	"v1N_ISAKMP_N_CISCO_UNKNOWN_40502",
	"v1N_ISAKMP_N_CISCO_PRESHARED_KEY_HASH",
};

static enum_names v1_notification_cisco_more_names = {
	v1N_ISAKMP_N_CISCO_LOAD_BALANCE,
	v1N_ISAKMP_N_CISCO_PRESHARED_KEY_HASH,
	ARRAY_REF(v1_notification_cisco_more_name),
	NULL, /* prefix */
	NULL, /* next */
};

static enum_names v1_notification_juniper_names = {
	v1N_NETSCREEN_NHTB_INFORM,
	v1N_NETSCREEN_NHTB_INFORM,
	ARRAY_REF(v1_notification_juniper_name),
	NULL, /* prefix */
	&v1_notification_cisco_more_names
};

static enum_names v1_notification_dpd_names = {
	v1N_R_U_THERE,
	v1N_R_U_THERE_ACK,
	ARRAY_REF(v1_notification_dpd_name),
	NULL, /* prefix */
	&v1_notification_juniper_names
};

static enum_names v1_notification_ios_alives_names = {
	v1N_ISAKMP_N_IOS_KEEP_ALIVE_REQ,
	v1N_ISAKMP_N_IOS_KEEP_ALIVE_ACK,
	ARRAY_REF(v1_notification_ios_alives_name),
	NULL, /* prefix */
	&v1_notification_dpd_names
};

static enum_names v1_notification_cisco_chatter_names = {
	v1N_ISAKMP_N_CISCO_HELLO,
	v1N_ISAKMP_N_CISCO_SHUT_UP,
	ARRAY_REF(v1_notification_cisco_chatter_name),
	NULL, /* prefix */
	&v1_notification_ios_alives_names
};

static enum_names v1_notification_ipsec_names = {
	v1N_IPSEC_RESPONDER_LIFETIME,
	v1N_IPSEC_INITIAL_CONTACT,
	ARRAY_REF(v1_notification_ipsec_name),
	NULL, /* prefix */
	&v1_notification_cisco_chatter_names
};

static enum_names v1_notification_connected_names = {
	v1N_CONNECTED,
	v1N_CONNECTED,
	ARRAY_REF(v1_notification_connected_name),
	NULL, /* prefix */
	&v1_notification_ipsec_names
};

enum_names v1_notification_names = {
	v1N_INVALID_PAYLOAD_TYPE,
	v1N_UNEQUAL_PAYLOAD_LENGTHS,
	ARRAY_REF(v1_notification_name),
	"v1N_", /* prefix */
	&v1_notification_connected_names
};

static const char *const v2_notification_error_name[] = {
#define S(E) [E] = #E
	S(v2N_UNSUPPORTED_CRITICAL_PAYLOAD),
	S(v2N_INVALID_IKE_SPI),
	S(v2N_INVALID_MAJOR_VERSION),
	S(v2N_INVALID_SYNTAX),
	S(v2N_INVALID_MESSAGE_ID),
	S(v2N_INVALID_SPI),
	S(v2N_NO_PROPOSAL_CHOSEN),
	S(v2N_INVALID_KE_PAYLOAD),
	S(v2N_AUTHENTICATION_FAILED),
	S(v2N_SINGLE_PAIR_REQUIRED),
	S(v2N_NO_ADDITIONAL_SAS),
	S(v2N_INTERNAL_ADDRESS_FAILURE),
	S(v2N_FAILED_CP_REQUIRED),
	S(v2N_TS_UNACCEPTABLE),
	S(v2N_INVALID_SELECTORS),
	S(v2N_UNACCEPTABLE_ADDRESSES),
	S(v2N_UNEXPECTED_NAT_DETECTED),
	S(v2N_USE_ASSIGNED_HoA),
	S(v2N_TEMPORARY_FAILURE),
	S(v2N_CHILD_SA_NOT_FOUND),
	S(v2N_INVALID_GROUP_ID),
	S(v2N_AUTHORIZATION_FAILED),
	S(v2N_STATE_NOT_FOUND),
#undef S
};

/* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xml#ikev2-parameters-13 */
static const char *const v2_notification_status_name[] = {
#define S(E) [E-v2N_STATUS_FLOOR] = #E
	S(v2N_INITIAL_CONTACT),    /* 16384 */
	S(v2N_SET_WINDOW_SIZE),
	S(v2N_ADDITIONAL_TS_POSSIBLE),
	S(v2N_IPCOMP_SUPPORTED),
	S(v2N_NAT_DETECTION_SOURCE_IP),
	S(v2N_NAT_DETECTION_DESTINATION_IP),
	S(v2N_COOKIE),
	S(v2N_USE_TRANSPORT_MODE),
	S(v2N_HTTP_CERT_LOOKUP_SUPPORTED),
	S(v2N_REKEY_SA),
	S(v2N_ESP_TFC_PADDING_NOT_SUPPORTED),
	S(v2N_NON_FIRST_FRAGMENTS_ALSO),
	S(v2N_MOBIKE_SUPPORTED),
	S(v2N_ADDITIONAL_IP4_ADDRESS),
	S(v2N_ADDITIONAL_IP6_ADDRESS),
	S(v2N_NO_ADDITIONAL_ADDRESSES),
	S(v2N_UPDATE_SA_ADDRESSES),
	S(v2N_COOKIE2),
	S(v2N_NO_NATS_ALLOWED),
	S(v2N_AUTH_LIFETIME),
	S(v2N_MULTIPLE_AUTH_SUPPORTED),
	S(v2N_ANOTHER_AUTH_FOLLOWS),
	S(v2N_REDIRECT_SUPPORTED),
	S(v2N_REDIRECT),
	S(v2N_REDIRECTED_FROM),
	S(v2N_TICKET_LT_OPAQUE),
	S(v2N_TICKET_REQUEST),
	S(v2N_TICKET_ACK),
	S(v2N_TICKET_NACK),
	S(v2N_TICKET_OPAQUE),
	S(v2N_LINK_ID),
	S(v2N_USE_WESP_MODE),
	S(v2N_ROHC_SUPPORTED),
	S(v2N_EAP_ONLY_AUTHENTICATION),
	S(v2N_CHILDLESS_IKEV2_SUPPORTED),
	S(v2N_QUICK_CRASH_DETECTION),
	S(v2N_IKEV2_MESSAGE_ID_SYNC_SUPPORTED),
	S(v2N_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED),
	S(v2N_IKEV2_MESSAGE_ID_SYNC),
	S(v2N_IPSEC_REPLAY_COUNTER_SYNC),
	S(v2N_SECURE_PASSWORD_METHODS),
	S(v2N_PSK_PERSIST),
	S(v2N_PSK_CONFIRM),
	S(v2N_ERX_SUPPORTED),
	S(v2N_IFOM_CAPABILITY),
	S(v2N_SENDER_REQUEST_ID),
	S(v2N_IKEV2_FRAGMENTATION_SUPPORTED),
	S(v2N_SIGNATURE_HASH_ALGORITHMS),
	S(v2N_CLONE_IKE_SA_SUPPORTED),
	S(v2N_CLONE_IKE_SA),
	S(v2N_PUZZLE),
	S(v2N_USE_PPK),
	S(v2N_PPK_IDENTITY),
	S(v2N_NO_PPK_AUTH),
	S(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED),
	S(v2N_IP4_ALLOWED),
	S(v2N_IP6_ALLOWED),
	S(v2N_ADDITIONAL_KEY_EXCHANGE),
	S(v2N_USE_AGGFRAG),
#undef S
};

static const char *const v2_notification_private_name[] = {
	"v2N_NULL_AUTH",	/* 40960, used for mixed OE */
};

static const struct enum_names v2_notification_private_names = {
	v2N_NULL_AUTH,
	v2N_NULL_AUTH,
	ARRAY_REF(v2_notification_private_name),
	"v2N_", /* prefix */
	NULL
};

static const struct enum_names v2_notification_status_names = {
	v2N_INITIAL_CONTACT,
	v2N_USE_AGGFRAG,
	ARRAY_REF(v2_notification_status_name),
	"v2N_", /* prefix */
	&v2_notification_private_names,
};

const struct enum_names v2_notification_names = {
	v2N_NOTHING_WRONG,
	v2N_STATE_NOT_FOUND,
	ARRAY_REF(v2_notification_error_name),
	"v2N_", /* prefix */
	&v2_notification_status_names
};

/* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xml#ikev2-parameters-19 */
static const char *const ikev2_ts_type_name[] = {
	"IKEv2_TS_IPV4_ADDR_RANGE",     /* 7 */
	"IKEv2_TS_IPV6_ADDR_RANGE",     /* 8 */
	"IKEv2_TS_FC_ADDR_RANGE",	/* 9; not implemented */
	"IKEv2_TS_SECLABEL", /* 10; Early Code Point */
};

enum_names ikev2_ts_type_names = {
	IKEv2_TS_IPV4_ADDR_RANGE,
	IKEv2_TS_SECLABEL,
	ARRAY_REF(ikev2_ts_type_name),
	NULL, /* prefix */
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
	NULL, /* prefix */
	NULL
};

/*
 * IKEv2 Critical bit and RESERVED (7) bits
 */
static const char *const payload_flag_name[] = {
	"RESERVED bit 0",	/* bit 0 */
	"RESERVED bit 1",	/* bit 1 */
	"RESERVED bit 2",	/* bit 2 */
	"RESERVED bit 3",	/* bit 3 */
	"RESERVED bit 4",	/* bit 4 */
	"RESERVED bit 5",	/* bit 5 */
	"RESERVED bit 6",	/* bit 6 */
	"PAYLOAD_CRITICAL",	/* bit 7 */
};

const enum_names payload_flag_names = {
	ISAKMP_PAYLOAD_FLAG_LIBRESWAN_BOGUS_IX,
	ISAKMP_PAYLOAD_FLAG_CRITICAL_IX,
	ARRAY_REF(payload_flag_name),
	NULL, /* prefix */
	NULL, /* next */
};

/*
 * IKEv2 Security Protocol Identifiers
 */

/* proposal payload allows IKE=1, AH=2, ESP=3 */

static const char *const ikev2_proposal_protocol_id_name[] = {
	"IKEv2_SEC_PROTO_IKE",
	"IKEv2_SEC_PROTO_AH",
	"IKEv2_SEC_PROTO_ESP",
	"IKEv2_SEC_FC_ESP_HEADER",		/* RFC 4595 */
	"IKEv2_SEC_FC_CT_AUTHENTICATION",	/* RFC 4595 */
	/* 6 - 200 Unassigned */
	/* 201 - 255 Private use */
};

enum_names ikev2_proposal_protocol_id_names = {
	IKEv2_SEC_PROTO_IKE,
	IKEv2_SEC_FC_CT_AUTHENTICATION,
	ARRAY_REF(ikev2_proposal_protocol_id_name),
	.en_prefix = "IKEv2_SEC_PROTO_", /* prefix */
};

/* delete payload allows IKE=1, AH=2, ESP=3 */

static const char *const ikev2_delete_protocol_id_name[] = {
	"IKEv2_SEC_PROTO_IKE",
	"IKEv2_SEC_PROTO_AH",
	"IKEv2_SEC_PROTO_ESP",
};

enum_names ikev2_delete_protocol_id_names = {
	IKEv2_SEC_PROTO_IKE,
	IKEv2_SEC_PROTO_ESP,
	ARRAY_REF(ikev2_delete_protocol_id_name),
	.en_prefix = "IKEv2_SEC_PROTO_", /* prefix */
};

/*
 * Notify payload allows NONE=0, [IKE=1,] AH=2, ESP=3
 * https://tools.ietf.org/html/rfc7296#section-3.10
 * Technically 1 is not valid but is sent by by Cisco,
 * and the RFC states we should accept and ignore it:
 * "If the SPI field is empty, this field MUST be
 *  sent as zero and MUST be ignored on receipt."
 */

static const char *const ikev2_protocol_id_notify_name[] = {
#define E(V) [V] = #V
	E(IKEv2_SEC_PROTO_NONE),
	E(IKEv2_SEC_PROTO_IKE),
	E(IKEv2_SEC_PROTO_AH),
	E(IKEv2_SEC_PROTO_ESP),
#undef E
};

enum_names ikev2_notify_protocol_id_names = {
	IKEv2_SEC_PROTO_NONE,
	IKEv2_SEC_PROTO_ESP,
	ARRAY_REF(ikev2_protocol_id_notify_name),
	.en_prefix = "IKEv2_SEC_PROTO_", /* prefix */
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
	"DES_IV64(UNUSED)",	/* 1 */
	"DES(UNUSED)",
	"3DES",
	"RC5(UNUSED)",
	"IDEA(UNUSED)",
	"CAST",
	"BLOWFISH(UNUSED)",
	"3IDEA(UNUSED)",
	"DES_IV32(UNUSED)",
	"RES10(UNUSED)",
	"NULL",
	"AES_CBC",
	"AES_CTR",
	"AES_CCM_A",	/* AES-CCM_8 RFC 4309 */
	"AES_CCM_B",	/* AES-CCM_12 */
	"AES_CCM_C",	/* AES-CCM_16 */
	"UNASSIGNED(UNUSED)",
	"AES_GCM_A",	/* AES-GCM_8 RFC 4106 */
	"AES_GCM_B",	/* AES-GCM_12 */
	"AES_GCM_C",	/* AES-GCM_16 */
	"NULL_AUTH_AES_GMAC",	/* RFC 4543 */
	"RESERVED_FOR_IEEE_P1619_XTS_AES(UNUSED)",
	"CAMELLIA_CBC",	/* RFC 5529 */
	"CAMELLIA_CTR",	/* RFC 5529 */
	"CAMELLIA_CCM_A",	/* CAMELLIA_CCM_8 RFC 5529 */
	"CAMELLIA_CCM_B",	/* CAMELLIA_CCM_12 RFC 5529 */
	"CAMELLIA_CCM_C",	/* CAMELLIA_CCM_16 RFC 5529 */
	"CHACHA20_POLY1305", /* RFC 7634 */
	/* 29 - 1023 Unassigned */
	/* 1024 - 65535 Private use */
};

static enum_names ikev2_trans_type_encr_names_private_use2 = {
	OAKLEY_TWOFISH_CBC_SSH,
	OAKLEY_TWOFISH_CBC_SSH,
	ARRAY_REF(ikev2_trans_type_encr_name_private_use2),
	NULL, /* prefix */
	NULL
};

static enum_names ikev2_trans_type_encr_names_private_use1 = {
	OAKLEY_SERPENT_CBC,
	OAKLEY_TWOFISH_CBC,
	ARRAY_REF(ikev2_trans_type_encr_name_private_use1),
	NULL, /* prefix */
	&ikev2_trans_type_encr_names_private_use2
};

enum_names ikev2_trans_type_encr_names = {
	IKEv2_ENCR_DES_IV64,
	IKEv2_ENCR_CHACHA20_POLY1305,
	ARRAY_REF(ikev2_trans_type_encr_name),
	NULL, /* prefix */
	&ikev2_trans_type_encr_names_private_use1
};

/* Transform-type PRF */
static const char *const ikev2_trans_type_prf_name[] = {
	"PRF_HMAC_MD5",
	"PRF_HMAC_SHA1",
	"PRF_HMAC_TIGER",
	"PRF_AES128_XCBC",
	/* RFC 4868 Section 4 */
	"PRF_HMAC_SHA2_256",
	"PRF_HMAC_SHA2_384",
	"PRF_HMAC_SHA2_512",
	"PRF_AES128_CMAC"
};
enum_names ikev2_trans_type_prf_names = {
	IKEv2_PRF_HMAC_MD5,
	IKEv2_PRF_AES128_CMAC,
	ARRAY_REF(ikev2_trans_type_prf_name),
	"PRF_", /* prefix */
	NULL
};

/* Transform-type Integrity */
static const char *const ikev2_trans_type_integ_name[] = {
	"AUTH_NONE",
	"AUTH_HMAC_MD5_96",
	"AUTH_HMAC_SHA1_96",
	"AUTH_DES_MAC(UNUSED)",
	"AUTH_KPDK_MD5(UNUSED)",
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
	IKEv2_INTEG_NONE,
	IKEv2_INTEG_HMAC_SHA2_512_256,
	ARRAY_REF(ikev2_trans_type_integ_name),
	"AUTH_", /* prefix */
	NULL
};

/* Transform-type Integrity */
static const char *const ikev2_trans_type_esn_name[] = {
#define S(E) [E-IKEv2_ESN_FLOOR] = #E
	S(IKEv2_ESN_YES),
	S(IKEv2_ESN_NO),
#undef S
};

enum_names ikev2_trans_type_esn_names = {
	IKEv2_ESN_FLOOR,
	IKEv2_ESN_ROOF-1,
	ARRAY_REF(ikev2_trans_type_esn_name),
	"IKEv2_ESN_", /* prefix */
	NULL
};

/* Transform Type */
static const char *const ikev2_trans_type_name[] = {
#define S(E) [E-IKEv2_TRANS_TYPE_FLOOR] = #E
	S(IKEv2_TRANS_TYPE_ENCR),
	S(IKEv2_TRANS_TYPE_PRF),
	S(IKEv2_TRANS_TYPE_INTEG),
	S(IKEv2_TRANS_TYPE_DH),
	S(IKEv2_TRANS_TYPE_ESN),
#undef S
};

enum_names ikev2_trans_type_names = {
	IKEv2_TRANS_TYPE_FLOOR,
	IKEv2_TRANS_TYPE_ROOF-1,
	ARRAY_REF(ikev2_trans_type_name),
	"IKEv2_TRANS_TYPE_", /* prefix */
	NULL
};

/* for each IKEv2 transform attribute, which enum_names describes its values? */
static enum_names *const ikev2_transid_val_descs[] = {
#define S(E,V) [E-IKEv2_TRANS_TYPE_FLOOR] = &V
	S(IKEv2_TRANS_TYPE_ENCR, ikev2_trans_type_encr_names),        /* 1 */
	S(IKEv2_TRANS_TYPE_PRF, ikev2_trans_type_prf_names),          /* 2 */
	S(IKEv2_TRANS_TYPE_INTEG, ikev2_trans_type_integ_names),      /* 3 */
	S(IKEv2_TRANS_TYPE_DH, oakley_group_names),                   /* 4 */
	S(IKEv2_TRANS_TYPE_ESN, ikev2_trans_type_esn_names),          /* 5 */
};

enum_enum_names v2_transform_ID_enums = {
	IKEv2_TRANS_TYPE_FLOOR,
	IKEv2_TRANS_TYPE_ROOF-1,
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
	NULL, /* prefix */
	NULL
};

static const char *const secret_kind_name[] = {
	"SECRET_PSK",
	"SECRET_RSA",
	"SECRET_XAUTH",
	"SECRET_PPK",
	"SECRET_ECDSA",
	"SECRET_NULL",
	"SECRET_INVALID",
};

enum_names secret_kind_names = {
	SECRET_PSK,
	SECRET_INVALID,
	ARRAY_REF(secret_kind_name),
	"SECRET_", /* prefix */
	NULL
};

/*
 * IKEv2 PPK ID types - RFC 8784
 */
static const char *const ikev2_ppk_id_type_name[] = {
	/* 0 - Reserved */
	"PPK_ID_OPAQUE",
	"PPK_ID_FIXED",
	/* 3 - 127 Unassigned */
	/* 128 - 255 Private Use */
};

enum_names ikev2_ppk_id_type_names = {
	PPK_ID_OPAQUE,
	PPK_ID_FIXED,
	ARRAY_REF(ikev2_ppk_id_type_name),
	"PPK_ID_", /* prefix */
	NULL
};

/* IKEv2 Redirect Mechanism - RFC 5685 */
static const char *const ikev2_redirect_gw_name[] = {
	/* 0 - Reserved */
	"GW_IPv4",
	"GW_IPv6",
	"GW_FQDN",
	/* 4 - 240	Unassigned */
	/* 241 - 255	Private Use */
};

enum_names ikev2_redirect_gw_names = {
	GW_IPV4,
	GW_FQDN,
	ARRAY_REF(ikev2_redirect_gw_name),
	"GW_",	/* prefix */
	NULL
};

/* EAP - RFC 3748 */
static const char *const eap_code_name[] = {
	"EAP_CODE_REQUEST",
	"EAP_CODE_RESPONSE",
	"EAP_CODE_SUCCESS",
	"EAP_CODE_FAILURE",
};

enum_names eap_code_names = {
	EAP_CODE_REQUEST,
	EAP_CODE_FAILURE,
	ARRAY_REF(eap_code_name),
	"EAP_CODE_",	/* prefix */
	NULL
};

static const char *const eap_type_name[] = {
	"EAP_TYPE_TLS",
};

enum_names eap_type_names = {
	EAP_TYPE_TLS,
	EAP_TYPE_TLS,
	ARRAY_REF(eap_type_name),
	"EAP_TYPE_",	/* prefix */
	NULL
};

/* EAP-TLS Flag BITS */
static const char *const eaptls_flag_name[] = {
	"EAPTLS_FLAG_START",
	"EAPTLS_FLAG_MORE",
	"EAPTLS_FLAG_LENGTH",
};

const struct enum_names eaptls_flag_names = {
	EAPTLS_FLAGS_START_IX,
	EAPTLS_FLAGS_LENGTH_IX,
	ARRAY_REF(eaptls_flag_name),
	"EAPTLS_FLAG_", /* prefix */
	NULL, /* next */
};

/*
 * enum global_timers
 */

static const char *global_timer_name[] = {
#define E(T) [T] = #T
	E(EVENT_REINIT_SECRET),
	E(EVENT_SHUNT_SCAN),
	E(EVENT_PENDING_DDNS),
	E(EVENT_SD_WATCHDOG),
	E(EVENT_CHECK_CRLS),
	E(EVENT_FREE_ROOT_CERTS),
	E(EVENT_RESET_LOG_LIMITER),
	E(EVENT_PROCESS_KERNEL_QUEUE),
	E(EVENT_NAT_T_KEEPALIVE),
#undef E
};
const struct enum_names global_timer_names = {
	0, elemsof(global_timer_name) - 1,
	ARRAY_REF(global_timer_name),
	"EVENT_",
	NULL,
};

/*
 * enum event_type
 */

static const char *const event_name[] = {
#define E(EVENT) [EVENT - EVENT_NULL] = #EVENT
	E(EVENT_NULL),
	E(EVENT_RETRANSMIT),
	E(EVENT_CRYPTO_TIMEOUT),
#undef E
};

static const enum_names event_names = {
	EVENT_NULL, EVENT_CRYPTO_TIMEOUT,
	ARRAY_REF(event_name),
	"EVENT_", /* prefix */
	NULL
};

static const char *const event_v1_name[] = {
#define E(EVENT) [EVENT - EVENT_v1_SEND_XAUTH] = #EVENT
	E(EVENT_v1_SEND_XAUTH),
	E(EVENT_v1_DPD),
	E(EVENT_v1_DPD_TIMEOUT),
	E(EVENT_v1_PAM_TIMEOUT),
	E(EVENT_v1_REPLACE),
	E(EVENT_v1_DISCARD),
	E(EVENT_v1_EXPIRE),
#undef E
};

static const enum_names event_v1_names = {
	EVENT_v1_SEND_XAUTH, EVENT_v1_REPLACE,
	ARRAY_REF(event_v1_name),
	"EVENT_v1_", /* prefix */
	&event_names
};

static const char *const event_v2_name[] = {
#define E(EVENT) [EVENT - EVENT_v2_REKEY] = #EVENT
	E(EVENT_v2_REKEY),
	E(EVENT_v2_REPLACE),
	E(EVENT_v2_DISCARD),
	E(EVENT_v2_LIVENESS),
	E(EVENT_v2_ADDR_CHANGE),
	E(EVENT_v2_EXPIRE),
#undef E
};

static const enum_names event_v2_names = {
	EVENT_v2_REKEY, EVENT_v2_ADDR_CHANGE,
	ARRAY_REF(event_v2_name),
	"EVENT_v2_", /* prefix */
	&event_v1_names,
};

static const char *const event_retain_name[] = {
#define E(EVENT) [EVENT - EVENT_RETAIN] = #EVENT
	E(EVENT_RETAIN),
#undef E
};

const enum_names event_type_names = {
	EVENT_RETAIN, EVENT_RETAIN,
	ARRAY_REF(event_retain_name),
	"EVENT_", /* prefix */
	&event_v2_names,
};

void init_constants(void)
{
	check_enum_names(enum_names_checklist);
	check_enum_enum_names(enum_enum_names_checklist);
}
