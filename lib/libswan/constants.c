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
#define S(E) [E - NO_PERSPECTIVE] = #E
	S(NO_PERSPECTIVE),
	S(LOCAL_PERSPECTIVE),
	S(REMOTE_PERSPECTIVE),
#undef S
};

enum_names perspective_names = {
	NO_PERSPECTIVE, REMOTE_PERSPECTIVE,
	ARRAY_REF(perspective_name),
	NULL, /* prefix */
	NULL,
};

static const char *const shunt_policy_name[] = {
#define S(E) [E - SHUNT_UNSET] = #E
	S(SHUNT_UNSET),
	S(SHUNT_IPSEC),
	S(SHUNT_HOLD),
	S(SHUNT_NONE),
	S(SHUNT_PASS),
	S(SHUNT_DROP),
	S(SHUNT_REJECT),
	S(SHUNT_TRAP),
#undef S
};

enum_names shunt_policy_names = {
	SHUNT_UNSET, SHUNT_POLICY_ROOF-1,
	ARRAY_REF(shunt_policy_name),
	"SHUNT_", /* prefix */
	NULL,
};

static const char *const shunt_kind_name[] = {
#define S(E) [E - SHUNT_KIND_NONE] = #E
	S(SHUNT_KIND_NONE),
	S(SHUNT_KIND_NEVER_NEGOTIATE),
	S(SHUNT_KIND_ONDEMAND),
	S(SHUNT_KIND_NEGOTIATION),
	S(SHUNT_KIND_IPSEC),
	S(SHUNT_KIND_FAILURE),
	S(SHUNT_KIND_BLOCK),
#undef S
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
	[NAT_TRAVERSAL_METHOD_none] = "none",
	[NAT_TRAVERSAL_METHOD_IETF_02_03] = "draft-ietf-ipsec-nat-t-ike-02/03",
	[NAT_TRAVERSAL_METHOD_IETF_05] = "draft-ietf-ipsec-nat-t-ike-05",
	[NAT_TRAVERSAL_METHOD_IETF_RFC] = "RFC 3947 (NAT-Traversal)",

	[NATED_HOST] = "I am behind NAT",
	[NATED_PEER] = "peer behind NAT",
};

enum_names natt_method_names = {
	NAT_TRAVERSAL_METHOD_none, NATED_PEER,
	ARRAY_REF(natt_method_name),
	NULL, /* prefix */
	NULL
};

static const char *const allow_global_redirect_name[] = {
#define R(E,S) [E - GLOBAL_REDIRECT_NO] = S
	R(GLOBAL_REDIRECT_NO, "no"),
	R(GLOBAL_REDIRECT_YES, "yes"),
	R(GLOBAL_REDIRECT_AUTO, "auto"),
#undef R
};

enum_names allow_global_redirect_names = {
	GLOBAL_REDIRECT_NO,
	GLOBAL_REDIRECT_AUTO,
	ARRAY_REF(allow_global_redirect_name),
	NULL,
	NULL
};

static const char *const dns_auth_level_name[] = {
#define S(E) [E - PUBKEY_LOCAL] = #E
	S(PUBKEY_LOCAL),
	S(DNSSEC_INSECURE),
	S(DNSSEC_SECURE),
#undef S
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
#define R(E,S) [E - PLUTO_SD_EXIT] = S
	R(PLUTO_SD_EXIT, "action: exit"), /* daemon exiting */
	R(PLUTO_SD_START, "action: start"), /* daemon starting */
	R(PLUTO_SD_WATCHDOG, "action: watchdog"), /* the keepalive watchdog ping */
	R(PLUTO_SD_RELOADING, "action: reloading"), /* the keepalive watchdog ping */
	R(PLUTO_SD_READY, "action: ready"), /* the keepalive watchdog ping */
	R(PLUTO_SD_STOPPING, "action: stopping"), /* the keepalive watchdog ping */
#undef R
};
enum_names sd_action_names = {
	PLUTO_SD_EXIT, PLUTO_SD_STOPPING,
	ARRAY_REF(sd_action_name),
	NULL, /* prefix */
	NULL
};

static const char *const keyword_auth_name[] = {
#define R(E,S) [E - AUTH_UNSET] = S
	R(AUTH_UNSET, "unset"),
	R(AUTH_NEVER, "never"),
	R(AUTH_PSK, "secret"),
	R(AUTH_RSASIG, "rsasig"),
	R(AUTH_ECDSA, "ecdsa"),
	R(AUTH_NULL, "null"),
	R(AUTH_EAPONLY, "eaponly"),
#undef R
};

enum_names keyword_auth_names = {
	AUTH_UNSET, AUTH_EAPONLY,
	ARRAY_REF(keyword_auth_name),
	NULL, /* prefix */
	NULL
};

static const char *const stf_status_strings[] = {
#define S(E) [E - STF_SKIP_COMPLETE_STATE_TRANSITION] = #E
	S(STF_SKIP_COMPLETE_STATE_TRANSITION),
	S(STF_IGNORE),
	S(STF_SUSPEND),
	S(STF_OK),
	S(STF_INTERNAL_ERROR),
	S(STF_OK_INITIATOR_DELETE_IKE),
	S(STF_OK_RESPONDER_DELETE_IKE),
	S(STF_OK_INITIATOR_SEND_DELETE_IKE),
	S(STF_FATAL),
	S(STF_FAIL_v1N),
#undef S
};

enum_names stf_status_names = {
	0, elemsof(stf_status_strings)-1,
	ARRAY_REF(stf_status_strings),
	NULL, /* prefix */
	NULL
};

static const char *const keyword_host_name_ipaddr[] = {
#define S(E) [E - KH_IPADDR] = #E
	S(KH_IPADDR),
#undef S
};

static enum_names keyword_host_names_ipaddr = {
	KH_IPADDR, KH_IPADDR,
	ARRAY_REF(keyword_host_name_ipaddr),
	"KH_", /* prefix */
	NULL
};

static const char *const keyword_host_name[] = {
#define S(E) [E - KH_NOTSET] = #E
	S(KH_NOTSET),
	S(KH_DEFAULTROUTE),
	S(KH_ANY),
	S(KH_IFACE),
	S(KH_OPPO),
	S(KH_OPPOGROUP),
	S(KH_GROUP),
	S(KH_IPHOSTNAME),
#undef S
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
#define S(E) [E - 0] = #E
	"<do-not-negotiate>",
	S(IKEv1),
	S(IKEv2),
#undef S
};

enum_names ike_version_names = {
	0, IKEv2,
	ARRAY_REF(ike_version_name),
	"IKE", /* prefix */
	NULL,
};

/* Domain of Interpretation */

static const char *const doi_name[] = {
#define S(E) [E - ISAKMP_DOI_ISAKMP] = #E
	S(ISAKMP_DOI_ISAKMP),
	S(ISAKMP_DOI_IPSEC),
#undef S
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
#define S(E) [E - CK_INVALID] = #E
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
#define S(E) [E - ISAKMP_NEXT_NONE] = #E
	S(ISAKMP_NEXT_NONE),
	S(ISAKMP_NEXT_SA),	/* 1 */
	S(ISAKMP_NEXT_P),
	S(ISAKMP_NEXT_T),
	S(ISAKMP_NEXT_KE),
	S(ISAKMP_NEXT_ID),	/* 5 */
	S(ISAKMP_NEXT_CERT),
	S(ISAKMP_NEXT_CR),
	S(ISAKMP_NEXT_HASH),
	S(ISAKMP_NEXT_SIG),
	S(ISAKMP_NEXT_NONCE),	/* 10 */
	S(ISAKMP_NEXT_N),
	S(ISAKMP_NEXT_D),
	S(ISAKMP_NEXT_VID),
	S(ISAKMP_NEXT_MODECFG),	/* 14 */
	S(ISAKMP_NEXT_SAK),	/* 15 was ISAKMP_NEXT_NATD_BADDRAFTS */
	S(ISAKMP_NEXT_TEK),
	S(ISAKMP_NEXT_KD),
	S(ISAKMP_NEXT_SEQ),
	S(ISAKMP_NEXT_POP),
	S(ISAKMP_NEXT_NATD_RFC),
	S(ISAKMP_NEXT_NATOA_RFC),
	S(ISAKMP_NEXT_GAP),
#undef S
};

static const char *const payload_name_ikev1_private_use[] = {
#define S(E) [E - ISAKMP_NEXT_NATD_DRAFTS] = #E
	S(ISAKMP_NEXT_NATD_DRAFTS),
	S(ISAKMP_NEXT_NATOA_DRAFTS),
	S(ISAKMP_NEXT_IKE_FRAGMENTATION),	/*
						 * proprietary Cisco/Microsoft
						 * IKE fragmented payload
						 */
#undef S
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
#define S(E) [E - ISAKMP_NEXT_v2NONE] = #E
	"ISAKMP_NEXT_v2NONE", /* same for IKEv1 */
#undef S
};

/* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-2 */
static const char *const payload_name_ikev2_main[] = {
#define S(E) [E - ISAKMP_NEXT_v2SA] = #E
	S(ISAKMP_NEXT_v2SA),	/* 33 */
	S(ISAKMP_NEXT_v2KE),
	S(ISAKMP_NEXT_v2IDi),
	S(ISAKMP_NEXT_v2IDr),
	S(ISAKMP_NEXT_v2CERT),
	S(ISAKMP_NEXT_v2CERTREQ),
	S(ISAKMP_NEXT_v2AUTH),
	S(ISAKMP_NEXT_v2Ni),
	S(ISAKMP_NEXT_v2N),
	S(ISAKMP_NEXT_v2D),
	S(ISAKMP_NEXT_v2V),
	S(ISAKMP_NEXT_v2TSi),
	S(ISAKMP_NEXT_v2TSr),
	S(ISAKMP_NEXT_v2SK),
	S(ISAKMP_NEXT_v2CP),
	S(ISAKMP_NEXT_v2EAP),
	S(ISAKMP_NEXT_v2GSPM), /* RFC 6467 */
	S(ISAKMP_NEXT_v2IDG), /* [draft-yeung-g-ikev2] */
	S(ISAKMP_NEXT_v2GSA), /* [draft-yeung-g-ikev2] */
	S(ISAKMP_NEXT_v2KD), /* [draft-yeung-g-ikev2] */
	S(ISAKMP_NEXT_v2SKF), /* RFC 7383 */
#undef S
};

/*
 * Old IKEv1 method applied to IKEv2, different from IKEv2's RFC7383
 * Can be removed
 */
static const char *const payload_name_ikev2_private_use[] = {
#define S(E) [E - ISAKMP_NEXT_v2IKE_FRAGMENTATION] = #E
	S(ISAKMP_NEXT_v2IKE_FRAGMENTATION),
#undef S
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
#define S(E) [E - v2_PROPOSAL_LAST] = #E
	S(v2_PROPOSAL_LAST),
	S(v2_PROPOSAL_NON_LAST),
#undef S
};

enum_names ikev2_last_proposal_desc = {
	v2_PROPOSAL_LAST,
	v2_PROPOSAL_NON_LAST,
	ARRAY_REF(ikev2_last_proposal_names),
	NULL, /* prefix */
	NULL
};

static const char *const ikev2_last_transform_names[] = {
#define S(E) [E - v2_TRANSFORM_LAST] = #E
	S(v2_TRANSFORM_LAST),
	S(v2_TRANSFORM_NON_LAST),
#undef S
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
#define S(E) [E - ISAKMP_XCHG_NONE] = #E
	S(ISAKMP_XCHG_NONE),
	S(ISAKMP_XCHG_BASE),
	S(ISAKMP_XCHG_IDPROT),
	S(ISAKMP_XCHG_AO),
	S(ISAKMP_XCHG_AGGR),
	S(ISAKMP_XCHG_INFO),
	S(ISAKMP_XCHG_MODE_CFG),	/* 6 - draft, not RFC */
#undef S
};

static const char *const ikev1_exchange_doi_name[] = {
#define S(E) [E - ISAKMP_XCHG_QUICK] = #E
	S(ISAKMP_XCHG_QUICK),	/* 32 */
	S(ISAKMP_XCHG_NGRP),
#undef S
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
#define S(E) [E - IKEv2_EXCHANGE_FLOOR] = #E
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
#define S(E) [E - ISAKMP_FLAG_v1_ENCRYPTION] = #E
#define R(E,S) [E - ISAKMP_FLAGS_v1_ENCRYPTION_IX] = #S
	R(ISAKMP_FLAGS_v1_ENCRYPTION_IX, ISAKMP_FLAG_v1_ENCRYPTION), /* IKEv1 only bit 0 */
	R(ISAKMP_FLAGS_v1_COMMIT_IX, ISAKMP_FLAG_v1_COMMIT), /* IKEv1 only bit 1 */
	R(ISAKMP_FLAGS_v1_AUTH_IX, ISAKMP_FLAG_v1_AUTHONLY), /* IKEv1 only bit 2 */
	R(ISAKMP_FLAGS_v2_IKE_I_IX, ISAKMP_FLAG_v2_IKE_INIT), /* IKEv2 only bit 3 */
	R(ISAKMP_FLAGS_v2_VER_IX, ISAKMP_FLAG_v2_VERSION), /* IKEv2 only bit 4 */
	R(ISAKMP_FLAGS_v2_MSG_R_IX, ISAKMP_FLAG_v2_MSG_RESPONSE), /* IKEv2 only bit 5 */
	R(ISAKMP_FLAGS_RESERVED_BIT6_IX, ISAKMP_FLAG_MSG_RESERVED_BIT6),
	R(ISAKMP_FLAGS_RESERVED_BIT7_IX, ISAKMP_FLAG_MSG_RESERVED_BIT7),
#undef R
#undef S
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
#define S(E) [E - PROTO_RESERVED] = #E
	S(PROTO_RESERVED),
	S(PROTO_ISAKMP),
	S(PROTO_IPSEC_AH),
	S(PROTO_IPSEC_ESP),
	S(PROTO_IPCOMP),
#undef S
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
#define S(E) [E - KEY_IKE] = #E
	S(KEY_IKE),
#undef S
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
#define S(E) [E - IKEv1_AH_AES_CMAC_96] = #E
	S(IKEv1_AH_AES_CMAC_96),
	S(IKEv1_AH_NULL),	/* verify with kame source? 251 */
	S(IKEv1_AH_SHA2_256_TRUNCBUG),	/* our own to signal bad truncation to kernel */
#undef S
};

static enum_names ah_transformid_names_private_use = {
	IKEv1_AH_AES_CMAC_96,
	IKEv1_AH_SHA2_256_TRUNCBUG,
	ARRAY_REF(ah_transform_name_private_use),
	"IKEv1_AH_", /* prefix */
	NULL
};

static const char *const ah_transform_name[] = {
	/* 0-1 RESERVED */
#define S(E) [E - IKEv1_AH_MD5] = #E
	S(IKEv1_AH_MD5),
	S(IKEv1_AH_SHA),
	S(IKEv1_AH_DES),
	S(IKEv1_AH_SHA2_256),
	S(IKEv1_AH_SHA2_384),
	S(IKEv1_AH_SHA2_512),
	S(IKEv1_AH_RIPEMD),
	S(IKEv1_AH_AES_XCBC_MAC),
	S(IKEv1_AH_RSA),
	S(IKEv1_AH_AES_128_GMAC),	/* RFC4543 Errata1821 */
	S(IKEv1_AH_AES_192_GMAC),	/* RFC4543 Errata1821 */
	S(IKEv1_AH_AES_256_GMAC),	/* RFC4543 Errata1821 */
#undef S
	/* 14-248 Unassigned */
	/* 249-255 Reserved for private use */
};

enum_names ah_transformid_names = {
	IKEv1_AH_MD5, IKEv1_AH_AES_256_GMAC,
	ARRAY_REF(ah_transform_name),
	"IKEv1_AH_", /* prefix */
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
#define S(E) [E - IKEv1_ESP_MARS] = #E
	S(IKEv1_ESP_MARS),
	S(IKEv1_ESP_RC6),
	S(IKEv1_ESP_KAME_NULL),
	S(IKEv1_ESP_SERPENT),
	S(IKEv1_ESP_TWOFISH),
#undef S
};

static enum_names esp_transformid_names_private_use = {
	IKEv1_ESP_MARS,
	IKEv1_ESP_TWOFISH,
	ARRAY_REF(esp_transform_name_private_use),
	"IKEv1_ESP_", /* prefix */
	NULL
};

/* This tracks the IKEv2 registry now! see ietf_constants.h */
static const char *const esp_transform_name[] = {
#define S(E) [E - IKEv1_ESP_DES_IV64] = #E
	S(IKEv1_ESP_DES_IV64),	/* 1 - old DES */
	S(IKEv1_ESP_DES),	/* obsoleted */
	S(IKEv1_ESP_3DES),
	S(IKEv1_ESP_RC5),
	S(IKEv1_ESP_IDEA),
	S(IKEv1_ESP_CAST),
	S(IKEv1_ESP_BLOWFISH),	/* obsoleted */
	S(IKEv1_ESP_3IDEA),
	S(IKEv1_ESP_DES_IV32),
	S(IKEv1_ESP_RC4),
	S(IKEv1_ESP_NULL),
	S(IKEv1_ESP_AES),
	S(IKEv1_ESP_AES_CTR),
	S(IKEv1_ESP_AES_CCM_8),
	S(IKEv1_ESP_AES_CCM_12),
	S(IKEv1_ESP_AES_CCM_16),
	S(IKEv1_ESP_AES_GCM_8),
	S(IKEv1_ESP_AES_GCM_12),
	S(IKEv1_ESP_AES_GCM_16),
	S(IKEv1_ESP_SEED_CBC), /* IKEv2 is NULL_AUTH_AES_GMAC */
	S(IKEv1_ESP_CAMELLIA),
	S(IKEv1_ESP_NULL_AUTH_AES_GMAC), /* IKEv2 is CAMELLIA_CBC */
	S(IKEv1_ESP_CAMELLIA_CTR), /* not assigned in/for IKEv1 */
	S(IKEv1_ESP_CAMELLIA_CCM_8), /* not assigned in/for IKEv1 */
	S(IKEv1_ESP_CAMELLIA_CCM_12), /* not assigned in/for IKEv1 */
	S(IKEv1_ESP_CAMELLIA_CCM_16), /* not assigned in/for IKEv1 */
#undef S
	/* IKEv1: 24-248 Unassigned */
	/* IKEv1: 249-255 reserved for private use */
	/* IKEv2: 28-1023 Unassigned */
	/* IKEv2: 1024-65535 reserved for private use */
};

enum_names esp_transformid_names = {
	IKEv1_ESP_DES_IV64,
	IKEv1_ESP_CAMELLIA_CCM_16,
	ARRAY_REF(esp_transform_name),
	"IKEv1_ESP_", /* prefix */
	&esp_transformid_names_private_use
};

/* IPCOMP transform values */
static const char *const ipsec_ipcomp_algo_name[] = {
#define S(E) [E - IPCOMP_NONE] = #E
	S(IPCOMP_NONE),
	S(IPCOMP_OUI),
	S(IPCOMP_DEFLATE),
	S(IPCOMP_LZS),
	S(IPCOMP_LZJH),
	/* 5-47 Reserved for approved algorithms */
	/* 48-63 Reserved for private use */
	/* 64-255 Unassigned */
#undef S
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
#define S(E) [E - IKEv2_HASH_ALGORITHM_RESERVED] = #E
	S(IKEv2_HASH_ALGORITHM_RESERVED),
	S(IKEv2_HASH_ALGORITHM_SHA1),
	S(IKEv2_HASH_ALGORITHM_SHA2_256),
	S(IKEv2_HASH_ALGORITHM_SHA2_384),
	S(IKEv2_HASH_ALGORITHM_SHA2_512),
	S(IKEv2_HASH_ALGORITHM_IDENTITY)
#undef S
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
	[0] = "%fromcert",	/* -1, ID_FROMCERT:taken from certificate */
	[1] = "%none",	/* 0, ID_NONE */

	/* standardized */
#define S(E) [E + 1] = #E
	S(ID_IPV4_ADDR),	/* 1 */
	S(ID_FQDN),
	S(ID_USER_FQDN),
	S(ID_IPV4_ADDR_SUBNET), /* v1 only */
	S(ID_IPV6_ADDR),
	S(ID_IPV6_ADDR_SUBNET),	/* v1 only */
	S(ID_IPV4_ADDR_RANGE),	/* v1 only */
	S(ID_IPV6_ADDR_RANGE),	/* v1 only */
	S(ID_DER_ASN1_DN),
	S(ID_DER_ASN1_GN),
	S(ID_KEY_ID),
	S(ID_FC_NAME), /* RFC 3554 */
	S(ID_NULL), /* draft-ietf-ipsecme-ikev2-null-auth */
#undef S
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
#define S(E) [E - CERT_PKCS7_WRAPPED_X509] = #E
	S(CERT_PKCS7_WRAPPED_X509),
	S(CERT_PGP),
	S(CERT_DNS_SIGNED_KEY),
	S(CERT_X509_SIGNATURE),
	S(CERT_X509_KEY_EXCHANGE),	/* v1 only */
	S(CERT_KERBEROS_TOKENS),
	S(CERT_CRL),
	S(CERT_ARL),
	S(CERT_SPKI),
	S(CERT_X509_ATTRIBUTE),

	/* IKEv2 only from here */
	S(CERT_RAW_RSA),
	S(CERT_X509_CERT_URL),
	S(CERT_X509_BUNDLE_URL),
	S(CERT_OCSP_CONTENT), /* 14 */
	S(CERT_RAW_PUBLIC_KEY),

	/* 16 - 200 Reserved */
	/* 201 - 255 Private use */
#undef S
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
#define S(E) [E - CERT_NEVERSEND] = #E
	S(CERT_NEVERSEND),
	S(CERT_SENDIFASKED),
	S(CERT_ALWAYSSEND),
#undef S
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
#define R(E,S) [E - OAKLEY_GROUP_PRIME] = #S
	R(OAKLEY_GROUP_PRIME, OAKLEY_GROUP_PRIME (variable length)),
	R(OAKLEY_GROUP_GENERATOR_ONE, OAKLEY_GROUP_GENERATOR_ONE (variable length)),
	R(OAKLEY_GROUP_GENERATOR_TWO, OAKLEY_GROUP_GENERATOR_TWO (variable length)),
	R(OAKLEY_GROUP_CURVE_A, OAKLEY_GROUP_CURVE_A (variable length)),
	R(OAKLEY_GROUP_CURVE_B, OAKLEY_GROUP_CURVE_B (variable length)),
	NULL,
	R(OAKLEY_LIFE_DURATION, OAKLEY_LIFE_DURATION (variable length)),
	NULL,
	NULL,
	NULL,
	R(OAKLEY_GROUP_ORDER, OAKLEY_GROUP_ORDER (variable length)),
#undef R
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

static const struct enum_names *const ikev1_oakley_attr_value_name[] = {
	[OAKLEY_ENCRYPTION_ALGORITHM] = &oakley_enc_names,
	[OAKLEY_HASH_ALGORITHM] = &oakley_hash_names,
	[OAKLEY_AUTHENTICATION_METHOD] = &oakley_auth_names,
	[OAKLEY_GROUP_DESCRIPTION] = &oakley_group_names,
	[OAKLEY_GROUP_TYPE] = &oakley_group_type_names,
	[OAKLEY_LIFE_TYPE] = &oakley_lifetime_names,
	[OAKLEY_PRF] = &oakley_prf_names,
};

const struct enum_enum_names ikev1_oakley_attr_value_names = {
	0, OAKLEY_PRF,
	ARRAY_REF(ikev1_oakley_attr_value_name),
};

/* IPsec DOI attributes (RFC 2407 "IPsec DOI" section 4.5) */
static const char *const ipsec_attr_name[] = {
#define S(E) [E - SA_LIFE_TYPE] = #E
#define R(E,S) [E - SA_LIFE_TYPE] = #S
	S(SA_LIFE_TYPE),
	S(SA_LIFE_DURATION),
	S(GROUP_DESCRIPTION),
	S(ENCAPSULATION_MODE),
	S(AUTH_ALGORITHM),
	S(KEY_LENGTH),
	S(KEY_ROUNDS),
	S(COMPRESS_DICT_SIZE),
	S(COMPRESS_PRIVATE_ALG),
	R(ECN_TUNNEL, ECN_TUNNEL or old SECCTX),
	S(ESN_64BIT_SEQNUM),
	S(IKEv1_IPSEC_ATTR_UNSPEC_12), /* Maybe Tero knows why it was skipped? */
	S(SIG_ENC_ALGO_VAL),
	S(ADDRESS_PRESERVATION),
	S(SA_DIRECTION),
#undef R
#undef S
};

/*
 * These are attributes with variable length values (TLV).
 * The ones we actually support have non-NULL entries.
 */
static const char *const ipsec_var_attr_name[] = {
#define R(E,S) [E - SA_LIFE_TYPE] = #S
	NULL,	/* SA_LIFE_TYPE */
	R(SA_LIFE_DURATION, SA_LIFE_DURATION (variable length)),
	NULL,	/* GROUP_DESCRIPTION */
	NULL,	/* ENCAPSULATION_MODE */
	NULL,	/* AUTH_ALGORITHM */
	NULL,	/* KEY_LENGTH */
	NULL,	/* KEY_ROUNDS */
	NULL,	/* COMPRESS_DICT_SIZE */
	R(COMPRESS_PRIVATE_ALG, COMPRESS_PRIVATE_ALG (variable length)),
	R(ECN_TUNNEL, NULL), /* ECN_TUNNEL_or_old_SECCTX; yes "NULL" */
	NULL, /* ESN_64BIT_SEQNUM */
	NULL, /* IKEv1_IPSEC_ATTR_UNSPEC_12 */
	NULL, /* SIG_ENC_ALGO_VAL */
	NULL, /* ADDRESS_PRESERVATION */
	NULL, /* SA_DIRECTION */
#undef R
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
static const struct enum_names *ikev1_ipsec_attr_value_name[] = {
	[SA_LIFE_TYPE] = &sa_lifetime_names,
	[GROUP_DESCRIPTION] = &oakley_group_names,
	[ENCAPSULATION_MODE] = &encapsulation_mode_names,
	[AUTH_ALGORITHM] = &auth_alg_names,
};

const struct enum_enum_names ikev1_ipsec_attr_value_names = {
	0, AUTH_ALGORITHM,
	ARRAY_REF(ikev1_ipsec_attr_value_name),
};

/* SA Lifetime Type attribute */
static const char *const sa_lifetime_name[] = {
#define S(E) [E - SA_LIFE_TYPE_SECONDS] = #E
	S(SA_LIFE_TYPE_SECONDS),
	S(SA_LIFE_TYPE_KBYTES),
#undef S
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
#define S(E) [E - ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS] = #E
	S(ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS),
	S(ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS),
#undef S
};

enum_names encapsulation_mode_draft_names = {
	ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS,
	ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS,
	ARRAY_REF(encapsulation_mode_draft_name),
	"ENCAPSULATION_MODE_", /* prefix */
	NULL,
};

static const char *const encapsulation_mode_rfc_name[] = {
#define S(E) [E - ENCAPSULATION_MODE_TUNNEL] = #E
	S(ENCAPSULATION_MODE_TUNNEL),
	S(ENCAPSULATION_MODE_TRANSPORT),
	S(ENCAPSULATION_MODE_UDP_TUNNEL_RFC),
	S(ENCAPSULATION_MODE_UDP_TRANSPORT_RFC),
#undef S
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
#define S(E) [E - AUTH_ALGORITHM_AES_CMAC_96] = #E
	S(AUTH_ALGORITHM_AES_CMAC_96),
	S(AUTH_ALGORITHM_NULL_KAME),	/*
					 * according to our source code
					 * comments from jjo, needs
					 * verification
					 */
	S(AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG),
#undef S
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
#define S(E) [E - AUTH_ALGORITHM_NONE] = #E
	S(AUTH_ALGORITHM_NONE),	/* our own value, not standard */
	S(AUTH_ALGORITHM_HMAC_MD5),
	S(AUTH_ALGORITHM_HMAC_SHA1),
	S(AUTH_ALGORITHM_DES_MAC),
	S(AUTH_ALGORITHM_KPDK),
	S(AUTH_ALGORITHM_HMAC_SHA2_256),
	S(AUTH_ALGORITHM_HMAC_SHA2_384),
	S(AUTH_ALGORITHM_HMAC_SHA2_512),
	S(AUTH_ALGORITHM_HMAC_RIPEMD),
	S(AUTH_ALGORITHM_AES_XCBC),
	S(AUTH_ALGORITHM_SIG_RSA),	/* RFC4359 */
	S(AUTH_ALGORITHM_AES_128_GMAC),	/* RFC4543 [Errata1821] */
	S(AUTH_ALGORITHM_AES_192_GMAC),	/* RFC4543 [Errata1821] */
	S(AUTH_ALGORITHM_AES_256_GMAC),	/* RFC4543 [Errata1821] */
	/* 14-61439 Unassigned */
	/* 61440-65535 Reserved for private use */
#undef S
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
#define R(E,S) [E - XAUTH_TYPE_GENERIC] = #S
	R(XAUTH_TYPE_GENERIC, Generic),
	R(XAUTH_TYPE_CHAP, RADIUS-CHAP),
	R(XAUTH_TYPE_OTP, OTP),
	R(XAUTH_TYPE_SKEY, S/KEY),
#undef R
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
#define R(E,S) [E - IKEv1_INTERNAL_IP4_ADDRESS] = #S
	R(IKEv1_INTERNAL_IP4_ADDRESS, INTERNAL_IP4_ADDRESS),	/* 1 */
	R(IKEv1_INTERNAL_IP4_NETMASK, INTERNAL_IP4_NETMASK),
	R(IKEv1_INTERNAL_IP4_DNS, INTERNAL_IP4_DNS),
	R(IKEv1_INTERNAL_IP4_NBNS, INTERNAL_IP4_NBNS),
	R(IKEv1_INTERNAL_ADDRESS_EXPIRY, INTERNAL_ADDRESS_EXPIRY),
	R(IKEv1_INTERNAL_IP4_DHCP, INTERNAL_IP4_DHCP),
	R(IKEv1_APPLICATION_VERSION, APPLICATION_VERSION),
	R(IKEv1_INTERNAL_IP6_ADDRESS, INTERNAL_IP6_ADDRESS),
	R(IKEv1_INTERNAL_IP6_NETMASK, INTERNAL_IP6_NETMASK),
	R(IKEv1_INTERNAL_IP6_DNS, INTERNAL_IP6_DNS),
	R(IKEv1_INTERNAL_IP6_NBNS, INTERNAL_IP6_NBNS),
	R(IKEv1_INTERNAL_IP6_DHCP, INTERNAL_IP6_DHCP),
	R(IKEv1_INTERNAL_IP4_SUBNET, INTERNAL_IP4_SUBNET),	/* 13 */
	R(IKEv1_SUPPORTED_ATTRIBUTES, SUPPORTED_ATTRIBUTES),
	R(IKEv1_INTERNAL_IP6_SUBNET, INTERNAL_IP6_SUBNET),
	R(IKEv1_MIP6_HOME_PREFIX, MIP6_HOME_PREFIX),
	R(IKEv1_INTERNAL_IP6_LINK, INTERNAL_IP6_LINK),
	R(IKEv1_INTERNAL_IP6_PREFIX, INTERNAL_IP6_PREFIX),
	R(IKEv1_HOME_AGENT_ADDRESS, HOME_AGENT_ADDRESS),	/* 19 */
#undef R
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
#define S(E) [E - MODECFG_BANNER] = #E
	S(MODECFG_BANNER),	/* 28672 */
	S(CISCO_SAVE_PW),
	S(MODECFG_DOMAIN),
	S(CISCO_SPLIT_DNS),
	S(CISCO_SPLIT_INC),
	S(CISCO_UDP_ENCAP_PORT),
	S(CISCO_SPLIT_EXCLUDE),
	S(CISCO_DO_PFS),
	S(CISCO_FW_TYPE),
	S(CISCO_BACKUP_SERVER),
	S(CISCO_DDNS_HOSTNAME),
	S(CISCO_UNKNOWN_SEEN_ON_IPHONE),	/* 28683 */
#undef S
};

static enum_names modecfg_cisco_attr_names = {
	MODECFG_BANNER,
	CISCO_UNKNOWN_SEEN_ON_IPHONE,
	ARRAY_REF(modecfg_cisco_attr_name),
	NULL, /* prefix */
	NULL
};

static const char *const modecfg_microsoft_attr_name[] = {
#define R(E,S) [E - IKEv1_INTERNAL_IP4_SERVER] = #S
	R(IKEv1_INTERNAL_IP4_SERVER, INTERNAL_IP4_SERVER),	/* 23456 */
	R(IKEv1_INTERNAL_IP6_SERVER, INTERNAL_IP6_SERVER),
#undef R
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
#define R(E,S) [E - XAUTH_TYPE] = #S
	R(XAUTH_TYPE, XAUTH-TYPE), /* 16520 */
	R(XAUTH_USER_NAME, XAUTH-USER-NAME),
	R(XAUTH_USER_PASSWORD, XAUTH-USER-PASSWORD),
	R(XAUTH_PASSCODE, XAUTH-PASSCODE),
	R(XAUTH_MESSAGE, XAUTH-MESSAGE),
	R(XAUTH_CHALLENGE, XAUTH-CHALLENGE),
	R(XAUTH_DOMAIN, XAUTH-DOMAIN),
	R(XAUTH_STATUS, XAUTH-STATUS),
	R(XAUTH_NEXT_PIN, XAUTH-NEXT-PIN),
	R(XAUTH_ANSWER, XAUTH-ANSWER), /* 16529 */
#undef R
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
#define S(E) [E - OAKLEY_LIFE_SECONDS] = #E
	S(OAKLEY_LIFE_SECONDS),
	S(OAKLEY_LIFE_KILOBYTES),
#undef S
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
#define S(E) [E - 0] = #E
#define R(E,S) [E - 0] = #S
	S(OAKLEY_DES_CBC), /* obsoleted */
	S(OAKLEY_IDEA_CBC),
	S(OAKLEY_BLOWFISH_CBC), /* obsoleted */
	S(OAKLEY_RC5_R16_B64_CBC),
	S(OAKLEY_3DES_CBC),
	S(OAKLEY_CAST_CBC),
	S(OAKLEY_AES_CBC),
	S(OAKLEY_CAMELLIA_CBC), /* 8 */
	S(OAKLEY_AES_CTR), /* stolen from IKEv2 */
	R(OAKLEY_AES_CCM_8, OAKLEY_AES_CCM_A),
	R(OAKLEY_AES_CCM_12, OAKLEY_AES_CCM_B),
	S(OAKLEY_AES_CCM_16),
	R(OAKLEY_AES_GCM_8, OAKLEY_AES_GCM_A),
	R(OAKLEY_AES_GCM_12, OAKLEY_AES_GCM_B),
	R(OAKLEY_AES_GCM_16, OAKLEY_AES_GCM_C),
	S(OAKLEY_CAMELLIA_CTR),
	S(OAKLEY_CAMELLIA_CCM_A),
	S(OAKLEY_CAMELLIA_CCM_B),
	S(OAKLEY_CAMELLIA_CCM_C),
	/* 9-65000 Unassigned */
	/* 65001-65535 Reserved for private use */
#undef R
#undef S
};

static const char *const oakley_enc_name_private_use[] = {
#define S(E) [E - OAKLEY_MARS_CBC] = #E
	S(OAKLEY_MARS_CBC),	/* 65001 */
	S(OAKLEY_RC6_CBC),	/* 65002 */
	S(OAKLEY_SERPENT_CBC),	/* 65004 */
	S(OAKLEY_TWOFISH_CBC),	/* 65005 */
#undef S
};

static const char *const oakley_enc_name_private_use_ssh[] = {
#define S(E) [E - OAKLEY_TWOFISH_CBC_SSH] = #E
	S(OAKLEY_TWOFISH_CBC_SSH),	/* 65289 */
#undef S
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
	0,
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
#define S(E) [E - OAKLEY_MD5] = #E
	/* 0 - RESERVED */
	S(OAKLEY_MD5),
	S(OAKLEY_SHA1),
	S(OAKLEY_TIGER),
	S(OAKLEY_SHA2_256),	/* RFC 4878 */
	S(OAKLEY_SHA2_384),	/* RFC 4878 */
	S(OAKLEY_SHA2_512),	/* RFC 4878 */
	/* 7-65000 Unassigned */
	/* 65001-65535 Reserved for private use */
#undef S
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
#define S(E) [E - OAKLEY_PRESHARED_KEY] = #E
	S(OAKLEY_PRESHARED_KEY),
	S(OAKLEY_DSS_SIG),
	S(OAKLEY_RSA_SIG),
	S(OAKLEY_RSA_ENC),
	S(OAKLEY_RSA_REVISED_MODE),
	S(OAKLEY_ECDSA_P256), /* RFC 4754 */
	S(OAKLEY_ECDSA_P384), /* RFC 4754 */
	S(OAKLEY_ECDSA_P521), /* RFC 4754 */
#undef S
};

static const char *const oakley_auth_name_private_use2[] = {
#define S(E) [E - HybridInitRSA] = #E
	S(HybridInitRSA), /* 64221 */
	S(HybridRespRSA),
	S(HybridInitDSS),
	S(HybridRespDSS),
#undef S
};

static const char *const oakley_auth_name_private_use[] = {
#define S(E) [E - XAUTHInitPreShared] = #E
	S(XAUTHInitPreShared), /* 65001 */
	S(XAUTHRespPreShared),
	S(XAUTHInitDSS),
	S(XAUTHRespDSS),
	S(XAUTHInitRSA),
	S(XAUTHRespRSA),
	S(XAUTHInitRSAEncryption),
	S(XAUTHRespRSAEncryption),
	S(XAUTHInitRSARevisedEncryption),
	S(XAUTHRespRSARevisedEncryption), /* 65010 */
#undef S
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
#define S(E) [E - IKEv2_CP_ATTR_RESERVED] = #E
#define R(E,S) [E - IKEv2_CP_ATTR_RESERVED] = #S
	S(IKEv2_CP_ATTR_RESERVED),
	S(IKEv2_INTERNAL_IP4_ADDRESS),	/* 1 */
	S(IKEv2_INTERNAL_IP4_NETMASK),
	S(IKEv2_INTERNAL_IP4_DNS),
	S(IKEv2_INTERNAL_IP4_NBNS),
	R(IKEv2_RESERVED_5, IKEv2_CP_ATTRIBUTE_RESERVED_5),
	S(IKEv2_INTERNAL_IP4_DHCP),
	S(IKEv2_APPLICATION_VERSION),
	S(IKEv2_INTERNAL_IP6_ADDRESS),
	R(IKEv2_RESERVED_9, IKEv2_CP_ATTRIBUTE_RESERVED_9),
	S(IKEv2_INTERNAL_IP6_DNS),
	R(IKEv2_RESERVED_11, IKEv2_CP_ATTRIBUTE_RESERVED_11),
	S(IKEv2_INTERNAL_IP6_DHCP),
	S(IKEv2_INTERNAL_IP4_SUBNET),	/* 13 */
	S(IKEv2_SUPPORTED_ATTRIBUTES),
	S(IKEv2_INTERNAL_IP6_SUBNET),
	S(IKEv2_MIP6_HOME_PREFIX),
	S(IKEv2_INTERNAL_IP6_LINK),
	S(IKEv2_INTERNAL_IP6_PREFIX),
	S(IKEv2_HOME_AGENT_ADDRESS),
	S(IKEv2_P_CSCF_IP4_ADDRESS), /* 20 */
	S(IKEv2_P_CSCF_IP6_ADDRESS),
	S(IKEv2_FTT_KAT),
	S(IKEv2_EXTERNAL_SOURCE_IP4_NAT_INFO), /* 3gpp */
	S(IKEv2_TIMEOUT_PERIOD_FOR_LIVENESS_CHECK), /* 3gpp */
	S(IKEv2_INTERNAL_DNS_DOMAIN), /* draft-ietf-ipsecme-split-dns */
	S(IKEv2_INTERNAL_DNSSEC_TA), /* draft-ietf-ipsecme-split-dns */
#undef R
#undef S
};

enum_names ikev2_cp_attribute_type_names = {
	IKEv2_CP_ATTR_RESERVED,
	IKEv2_INTERNAL_DNSSEC_TA,
	ARRAY_REF(ikev2_cp_attribute_type_name),
	NULL, /* prefix */
	NULL
};

static const char *const ikev2_cp_type_name[] = {
#define S(E) [E - IKEv2_CP_CFG_REQUEST] = #E
	S(IKEv2_CP_CFG_REQUEST), /* 1 */
	S(IKEv2_CP_CFG_REPLY),
	S(IKEv2_CP_CFG_SET),
	S(IKEv2_CP_CFG_ACK),
#undef S
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
#define S(E) [E - IKEv2_AUTH_RESERVED] = #E
#define R(E,S) [E - IKEv2_AUTH_RESERVED] = #S
	S(IKEv2_AUTH_RESERVED),
	S(IKEv2_AUTH_RSA),
	R(IKEv2_AUTH_PSK, IKEv2_AUTH_SHARED),
	S(IKEv2_AUTH_DSS_DIGITAL_SIGNATURE),
	/* 4 - 8 unassigned */
	S(IKEv2_AUTH_ECDSA_SHA2_256_P256),
	S(IKEv2_AUTH_ECDSA_SHA2_384_P384),
	S(IKEv2_AUTH_ECDSA_SHA2_512_P521),
	S(IKEv2_AUTH_GENERIC_SECURE_PASSWORD_AUTHENTICATION_METHOD), /* 12 - RFC 6467 */
	S(IKEv2_AUTH_NULL),
	S(IKEv2_AUTH_DIGSIG), /* 14 - RFC 7427 */
#undef R
#undef S
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
#define S(E) [E - OAKLEY_GROUP_NONE] = #E
	S(OAKLEY_GROUP_NONE), /* 0! RFC 7296 */
	S(OAKLEY_GROUP_MODP768),
	S(OAKLEY_GROUP_MODP1024),
	S(OAKLEY_GROUP_GP155),
	S(OAKLEY_GROUP_GP185),
	S(OAKLEY_GROUP_MODP1536), /* RFC 3526 */
	S(OAKLEY_GROUP_EC2N_2_1), /* draft-ietf-ipsec-ike-ecc-groups */
	S(OAKLEY_GROUP_EC2N_2_2), /* draft-ietf-ipsec-ike-ecc-groups */
	S(OAKLEY_GROUP_EC2N_2_3), /* draft-ietf-ipsec-ike-ecc-groups */
	S(OAKLEY_GROUP_EC2N_2_4), /* draft-ietf-ipsec-ike-ecc-groups */
	S(OAKLEY_GROUP_EC2N_2_5), /* draft-ietf-ipsec-ike-ecc-groups */
	S(OAKLEY_GROUP_EC2N_2_6), /* draft-ietf-ipsec-ike-ecc-groups */
	S(OAKLEY_GROUP_EC2N_2_7), /* draft-ietf-ipsec-ike-ecc-groups */
	S(OAKLEY_GROUP_EC2N_2_8), /* draft-ietf-ipsec-ike-ecc-groups */
	S(OAKLEY_GROUP_MODP2048), /* RFC 3526 */
	S(OAKLEY_GROUP_MODP3072), /* RFC 3526 */
	S(OAKLEY_GROUP_MODP4096), /* RFC 3526 */
	S(OAKLEY_GROUP_MODP6144), /* RFC 3526 */
	S(OAKLEY_GROUP_MODP8192), /* RFC 3526 */
	S(OAKLEY_GROUP_ECP_256), /* RFC 5903 */
	S(OAKLEY_GROUP_ECP_384), /* RFC 5903 */
	S(OAKLEY_GROUP_ECP_521), /* RFC 5903 */
	S(OAKLEY_GROUP_DH22), /* RFC 5114 */
	S(OAKLEY_GROUP_DH23), /* RFC 5114 */
	S(OAKLEY_GROUP_DH24), /* RFC 5114 */
	S(OAKLEY_GROUP_ECP_192), /* RFC 5114 */
	S(OAKLEY_GROUP_ECP_224), /* RFC 5114 */
	S(OAKLEY_GROUP_BRAINPOOL_P224R1), /* RFC 6932 */
	S(OAKLEY_GROUP_BRAINPOOL_P256R1), /* RFC 6932 */
	S(OAKLEY_GROUP_BRAINPOOL_P384R1), /* RFC 6932 */
	S(OAKLEY_GROUP_BRAINPOOL_P512R1), /* RFC 6932 */
	S(OAKLEY_GROUP_CURVE25519), /* RFC-ietf-ipsecme-safecurves-05 */
	S(OAKLEY_GROUP_CURVE448), /* RFC-ietf-ipsecme-safecurves-05 */
	/* 33 - 32767 Unassigned */
	/* 32768 - 65535 Reserved for private use */
#undef S
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
#define S(E) [E - OAKLEY_GROUP_TYPE_MODP] = #E
	S(OAKLEY_GROUP_TYPE_MODP),
	S(OAKLEY_GROUP_TYPE_ECP),
	S(OAKLEY_GROUP_TYPE_EC2N),
#undef S
};

static enum_names oakley_group_type_names = {
	OAKLEY_GROUP_TYPE_MODP,
	OAKLEY_GROUP_TYPE_EC2N,
	ARRAY_REF(oakley_group_type_name),
	"OAKLEY_GROUP_TYPE_", /* prefix */
	NULL
};

/* Notify message type -- RFC2408 3.14.1 */
static const char *const v1_notification_name[] = {
#define S(E) [E - v1N_INVALID_PAYLOAD_TYPE] = #E
	S(v1N_INVALID_PAYLOAD_TYPE), /* 1 */
	S(v1N_DOI_NOT_SUPPORTED),
	S(v1N_SITUATION_NOT_SUPPORTED),
	S(v1N_INVALID_COOKIE),
	S(v1N_INVALID_MAJOR_VERSION),
	S(v1N_INVALID_MINOR_VERSION),
	S(v1N_INVALID_EXCHANGE_TYPE),
	S(v1N_INVALID_FLAGS),
	S(v1N_INVALID_MESSAGE_ID),
	S(v1N_INVALID_PROTOCOL_ID),
	S(v1N_INVALID_SPI),
	S(v1N_INVALID_TRANSFORM_ID),
	S(v1N_ATTRIBUTES_NOT_SUPPORTED),
	S(v1N_NO_PROPOSAL_CHOSEN),
	S(v1N_BAD_PROPOSAL_SYNTAX),
	S(v1N_PAYLOAD_MALFORMED),
	S(v1N_INVALID_KEY_INFORMATION),
	S(v1N_INVALID_ID_INFORMATION),
	S(v1N_INVALID_CERT_ENCODING),
	S(v1N_INVALID_CERTIFICATE),
	S(v1N_CERT_TYPE_UNSUPPORTED),
	S(v1N_INVALID_CERT_AUTHORITY),
	S(v1N_INVALID_HASH_INFORMATION),
	S(v1N_AUTHENTICATION_FAILED),
	S(v1N_INVALID_SIGNATURE),
	S(v1N_ADDRESS_NOTIFICATION),
	S(v1N_NOTIFY_SA_LIFETIME),
	S(v1N_CERTIFICATE_UNAVAILABLE),
	S(v1N_UNSUPPORTED_EXCHANGE_TYPE),
	S(v1N_UNEQUAL_PAYLOAD_LENGTHS),
#undef S
};

static const char *const v1_notification_connected_name[] = {
#define S(E) [E - v1N_CONNECTED] = #E
	S(v1N_CONNECTED), /* 16384 */
#undef S
};

static const char *const v1_notification_ipsec_name[] = {
#define S(E) [E - v1N_IPSEC_RESPONDER_LIFETIME] = #E
	S(v1N_IPSEC_RESPONDER_LIFETIME), /* 24576 */
	S(v1N_IPSEC_REPLAY_STATUS),
	S(v1N_IPSEC_INITIAL_CONTACT),
#undef S
};

static const char *const v1_notification_cisco_chatter_name[] = {
#define S(E) [E - v1N_ISAKMP_N_CISCO_HELLO] = #E
	S(v1N_ISAKMP_N_CISCO_HELLO), /* 30000 */
	S(v1N_ISAKMP_N_CISCO_WWTEBR),
	S(v1N_ISAKMP_N_CISCO_SHUT_UP),
#undef S
};

static const char *const v1_notification_ios_alives_name[] = {
#define S(E) [E - v1N_ISAKMP_N_IOS_KEEP_ALIVE_REQ] = #E
	S(v1N_ISAKMP_N_IOS_KEEP_ALIVE_REQ), /* 32768 */
	S(v1N_ISAKMP_N_IOS_KEEP_ALIVE_ACK),
#undef S
};

static const char *const v1_notification_dpd_name[] = {
#define S(E) [E - v1N_R_U_THERE] = #E
	S(v1N_R_U_THERE), /* 36136 */
	S(v1N_R_U_THERE_ACK),
#undef S
};

static const char *const v1_notification_juniper_name[] = {
#define S(E) [E - v1N_NETSCREEN_NHTB_INFORM] = #E
	/* Next Hop Tunnel Binding */
	S(v1N_NETSCREEN_NHTB_INFORM), /* 40001 */
#undef S
};

static const char *const v1_notification_cisco_more_name[] = {
#define S(E) [E - v1N_ISAKMP_N_CISCO_LOAD_BALANCE] = #E
	S(v1N_ISAKMP_N_CISCO_LOAD_BALANCE), /* 40501 */
	S(v1N_ISAKMP_N_CISCO_UNKNOWN_40502),
	S(v1N_ISAKMP_N_CISCO_PRESHARED_KEY_HASH),
#undef S
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
#define S(E) [E - v2N_NOTHING_WRONG] = #E
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
#define S(E) [E - v2N_STATUS_FLOOR] = #E
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
#define S(E) [E - v2N_NULL_AUTH] = #E
	S(v2N_NULL_AUTH),	/* 40960, used for mixed OE */
#undef S
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
#define S(E) [E - IKEv2_TS_IPV4_ADDR_RANGE] = #E
	S(IKEv2_TS_IPV4_ADDR_RANGE),     /* 7 */
	S(IKEv2_TS_IPV6_ADDR_RANGE),     /* 8 */
	S(IKEv2_TS_FC_ADDR_RANGE),	/* 9; not implemented */
	S(IKEv2_TS_SECLABEL), /* 10; Early Code Point */
#undef S
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
#define S(E) [E - ISAKMP_CFG_REQUEST] = #E
	S(ISAKMP_CFG_REQUEST),	/* 1 */
	S(ISAKMP_CFG_REPLY),
	S(ISAKMP_CFG_SET),
	S(ISAKMP_CFG_ACK),
#undef S
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
#define S(E) [E - 0] = #E
#define R(E,S) [E - 0] = #S
	R(0, RESERVED bit 0),	/* bit 0 */
	R(1, RESERVED bit 1),	/* bit 1 */
	R(2, RESERVED bit 2),	/* bit 2 */
	R(3, RESERVED bit 3),	/* bit 3 */
	R(4, RESERVED bit 4),	/* bit 4 */
	R(5, RESERVED bit 5),	/* bit 5 */
	R(6, RESERVED bit 6),	/* bit 6 */
	R(7, PAYLOAD_CRITICAL),	/* bit 7 */
#undef R
#undef S
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
#define S(E) [E - IKEv2_SEC_PROTO_IKE] = #E
	S(IKEv2_SEC_PROTO_IKE),
	S(IKEv2_SEC_PROTO_AH),
	S(IKEv2_SEC_PROTO_ESP),
	S(IKEv2_SEC_FC_ESP_HEADER),		/* RFC 4595 */
	S(IKEv2_SEC_FC_CT_AUTHENTICATION),	/* RFC 4595 */
	/* 6 - 200 Unassigned */
	/* 201 - 255 Private use */
#undef S
};

enum_names ikev2_proposal_protocol_id_names = {
	IKEv2_SEC_PROTO_IKE,
	IKEv2_SEC_FC_CT_AUTHENTICATION,
	ARRAY_REF(ikev2_proposal_protocol_id_name),
	.en_prefix = "IKEv2_SEC_PROTO_", /* prefix */
};

/* delete payload allows IKE=1, AH=2, ESP=3 */

static const char *const ikev2_delete_protocol_id_name[] = {
#define S(E) [E - IKEv2_SEC_PROTO_IKE] = #E
	S(IKEv2_SEC_PROTO_IKE),
	S(IKEv2_SEC_PROTO_AH),
	S(IKEv2_SEC_PROTO_ESP),
#undef S
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
#define S(E) [E - IKEv2_SEC_PROTO_NONE] = #E
	S(IKEv2_SEC_PROTO_NONE),
	S(IKEv2_SEC_PROTO_IKE),
	S(IKEv2_SEC_PROTO_AH),
	S(IKEv2_SEC_PROTO_ESP),
#undef S
};

enum_names ikev2_notify_protocol_id_names = {
	IKEv2_SEC_PROTO_NONE,
	IKEv2_SEC_PROTO_ESP,
	ARRAY_REF(ikev2_protocol_id_notify_name),
	.en_prefix = "IKEv2_SEC_PROTO_", /* prefix */
};

/* Transform-type Encryption */
static const char *const ikev2_trans_type_encr_name_private_use2[] = {
#define S(E) [E - IKEv2_ENCR_TWOFISH_CBC_SSH] = #E
	S(IKEv2_ENCR_TWOFISH_CBC_SSH),	/* 65289 */
#undef S
};

static enum_names ikev2_trans_type_encr_names_private_use2 = {
	IKEv2_ENCR_TWOFISH_CBC_SSH,
	IKEv2_ENCR_TWOFISH_CBC_SSH,
	ARRAY_REF(ikev2_trans_type_encr_name_private_use2),
	NULL, /* prefix */
	NULL
};

static const char *const ikev2_trans_type_encr_name_private_use1[] = {
#define S(E) [E - IKEv2_ENCR_SERPENT_CBC] = #E
	S(IKEv2_ENCR_SERPENT_CBC),	/* 65004 */
	S(IKEv2_ENCR_TWOFISH_CBC),
#undef S
};

static enum_names ikev2_trans_type_encr_names_private_use1 = {
	IKEv2_ENCR_SERPENT_CBC,
	IKEv2_ENCR_TWOFISH_CBC,
	ARRAY_REF(ikev2_trans_type_encr_name_private_use1),
	NULL, /* prefix */
	&ikev2_trans_type_encr_names_private_use2
};

static const char *const ikev2_trans_type_encr_name[] = {
#define S(E) [E - IKEv2_ENCR_DES_IV64] = #E
#define R(E,S) [E - IKEv2_ENCR_DES_IV64] = S
	S(IKEv2_ENCR_DES_IV64),	/* 1 */
	S(IKEv2_ENCR_DES),
	S(IKEv2_ENCR_3DES),
	S(IKEv2_ENCR_RC5),
	S(IKEv2_ENCR_IDEA),
	S(IKEv2_ENCR_CAST),
	S(IKEv2_ENCR_BLOWFISH),
	S(IKEv2_ENCR_3IDEA),
	S(IKEv2_ENCR_DES_IV32),
	S(IKEv2_ENCR_RES10),
	S(IKEv2_ENCR_NULL),
	S(IKEv2_ENCR_AES_CBC),
	S(IKEv2_ENCR_AES_CTR),
	R(IKEv2_ENCR_AES_CCM_8, "AES_CCM_A"),	/* AES-CCM_8 RFC 4309 */
	R(IKEv2_ENCR_AES_CCM_12, "AES_CCM_B"),	/* AES-CCM_12 */
	R(IKEv2_ENCR_AES_CCM_16, "AES_CCM_C"),	/* AES-CCM_16 */
	R(IKEv2_UNUSED_17, "UNASSIGNED"),
	R(IKEv2_ENCR_AES_GCM_8, "AES_GCM_A"),	/* AES-GCM_8 RFC 4106 */
	R(IKEv2_ENCR_AES_GCM_12, "AES_GCM_B"),	/* AES-GCM_12 */
	R(IKEv2_ENCR_AES_GCM_16, "AES_GCM_C"),	/* AES-GCM_16 */
	S(IKEv2_ENCR_NULL_AUTH_AES_GMAC),	/* RFC 4543 */
	R(IKEv2_RESERVED_IEEE_P1619_XTS_AES, "RESERVED_FOR_IEEE_P1619_XTS_AES"),
	S(IKEv2_ENCR_CAMELLIA_CBC),		/* RFC 5529 */
	S(IKEv2_ENCR_CAMELLIA_CTR),		/* RFC 5529 */
	S(IKEv2_ENCR_CAMELLIA_CCM_A),		/* CAMELLIA_CCM_8 RFC 5529 */
	S(IKEv2_ENCR_CAMELLIA_CCM_B),		/* CAMELLIA_CCM_12 RFC 5529 */
	S(IKEv2_ENCR_CAMELLIA_CCM_C),		/* CAMELLIA_CCM_16 RFC 5529 */
	S(IKEv2_ENCR_CHACHA20_POLY1305), /* RFC 7634 */
	/* 29 - 1023 Unassigned */
	/* 1024 - 65535 Private use */
#undef R
#undef S
};

enum_names ikev2_trans_type_encr_names = {
	IKEv2_ENCR_DES_IV64,
	IKEv2_ENCR_CHACHA20_POLY1305,
	ARRAY_REF(ikev2_trans_type_encr_name),
	"IKEv2_ENCR_", /* prefix */
	&ikev2_trans_type_encr_names_private_use1
};

/* Transform-type PRF */
static const char *const ikev2_trans_type_prf_name[] = {
#define S(E) [E - IKEv2_PRF_HMAC_MD5] = #E
	S(IKEv2_PRF_HMAC_MD5),
	S(IKEv2_PRF_HMAC_SHA1),
	S(IKEv2_PRF_HMAC_TIGER),
	S(IKEv2_PRF_AES128_XCBC),
	/* RFC 4868 Section 4 */
	S(IKEv2_PRF_HMAC_SHA2_256),
	S(IKEv2_PRF_HMAC_SHA2_384),
	S(IKEv2_PRF_HMAC_SHA2_512),
	S(IKEv2_PRF_AES128_CMAC)
#undef S
};

enum_names ikev2_trans_type_prf_names = {
	IKEv2_PRF_HMAC_MD5,
	IKEv2_PRF_AES128_CMAC,
	ARRAY_REF(ikev2_trans_type_prf_name),
	"IKEv2_PRF_", /* prefix */
	NULL
};

/* Transform-type Integrity */

static const char *const ikev2_trans_type_integ_name[] = {
#define S(E) [E - IKEv2_INTEG_NONE] = #E
	S(IKEv2_INTEG_NONE),
	S(IKEv2_INTEG_HMAC_MD5_96),
	S(IKEv2_INTEG_HMAC_SHA1_96),
	S(IKEv2_INTEG_DES_MAC),
	S(IKEv2_INTEG_KPDK_MD5),
	S(IKEv2_INTEG_AES_XCBC_96),
	S(IKEv2_INTEG_HMAC_MD5_128),
	S(IKEv2_INTEG_HMAC_SHA1_160),
	S(IKEv2_INTEG_AES_CMAC_96),
	S(IKEv2_INTEG_AES_128_GMAC),
	S(IKEv2_INTEG_AES_192_GMAC),
	S(IKEv2_INTEG_AES_256_GMAC),
	S(IKEv2_INTEG_HMAC_SHA2_256_128),
	S(IKEv2_INTEG_HMAC_SHA2_384_192),
	S(IKEv2_INTEG_HMAC_SHA2_512_256),
#undef S
};

enum_names ikev2_trans_type_integ_names = {
	IKEv2_INTEG_NONE,
	IKEv2_INTEG_HMAC_SHA2_512_256,
	ARRAY_REF(ikev2_trans_type_integ_name),
	"IKEv2_INTEG_", /* prefix */
	NULL
};

/* Transform-type Integrity */
static const char *const ikev2_trans_type_esn_name[] = {
#define S(E) [E - IKEv2_ESN_FLOOR] = #E
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
#define S(E) [E - IKEv2_TRANS_TYPE_FLOOR] = #E
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
#define S(E,V) [E - IKEv2_TRANS_TYPE_FLOOR] = &V
	S(IKEv2_TRANS_TYPE_ENCR, ikev2_trans_type_encr_names),        /* 1 */
	S(IKEv2_TRANS_TYPE_PRF, ikev2_trans_type_prf_names),          /* 2 */
	S(IKEv2_TRANS_TYPE_INTEG, ikev2_trans_type_integ_names),      /* 3 */
	S(IKEv2_TRANS_TYPE_DH, oakley_group_names),                   /* 4 */
	S(IKEv2_TRANS_TYPE_ESN, ikev2_trans_type_esn_names),          /* 5 */
#undef S
};

enum_enum_names v2_transform_ID_enums = {
	IKEv2_TRANS_TYPE_FLOOR,
	IKEv2_TRANS_TYPE_ROOF-1,
	ARRAY_REF(ikev2_transid_val_descs)
};

/* Transform Attributes */
static const char *const ikev2_trans_attr_name[] = {
#define S(E) [E - IKEv2_KEY_LENGTH] = #E
	S(IKEv2_KEY_LENGTH),
#undef S
};

enum_names ikev2_trans_attr_descs = {
	IKEv2_KEY_LENGTH + ISAKMP_ATTR_AF_TV,
	IKEv2_KEY_LENGTH + ISAKMP_ATTR_AF_TV,
	ARRAY_REF(ikev2_trans_attr_name),
	NULL, /* prefix */
	NULL
};

static const char *const secret_kind_name[] = {
#define S(E) [E - SECRET_PSK] = #E
	S(SECRET_PSK),
	S(SECRET_RSA),
	S(SECRET_XAUTH),
	S(SECRET_PPK),
	S(SECRET_ECDSA),
	S(SECRET_NULL),
	S(SECRET_INVALID),
#undef S
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
#define S(E) [E - PPK_ID_OPAQUE] = #E
	S(PPK_ID_OPAQUE),
	S(PPK_ID_FIXED),
#undef S
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
#define S(E) [E - GW_IPV4] = #E
#define R(E,S) [E - GW_IPV4] = #S
	/* 0 - Reserved */
	R(GW_IPV4, GW_IPv4),
	R(GW_IPV6, GW_IPv6),
	S(GW_FQDN),
	/* 4 - 240	Unassigned */
	/* 241 - 255	Private Use */
#undef R
#undef S
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
#define S(E) [E - EAP_CODE_REQUEST] = #E
	S(EAP_CODE_REQUEST),
	S(EAP_CODE_RESPONSE),
	S(EAP_CODE_SUCCESS),
	S(EAP_CODE_FAILURE),
#undef S
};

enum_names eap_code_names = {
	EAP_CODE_REQUEST,
	EAP_CODE_FAILURE,
	ARRAY_REF(eap_code_name),
	"EAP_CODE_",	/* prefix */
	NULL
};

static const char *const eap_type_name[] = {
#define S(E) [E - EAP_TYPE_TLS] = #E
	S(EAP_TYPE_TLS),
#undef S
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
#define S(E) [E - EAPTLS_FLAGS_START_IX] = #E
#define R(E,S) [E - EAPTLS_FLAGS_START_IX] = #S
	R(EAPTLS_FLAGS_START_IX, EAPTLS_FLAG_START),
	R(EAPTLS_FLAGS_MORE_IX, EAPTLS_FLAG_MORE),
	R(EAPTLS_FLAGS_LENGTH_IX, EAPTLS_FLAG_LENGTH),
#undef R
#undef S
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
#define S(E) [E - EVENT_REINIT_SECRET] = #E
	S(EVENT_REINIT_SECRET),
	S(EVENT_SHUNT_SCAN),
	S(EVENT_PENDING_DDNS),
	S(EVENT_SD_WATCHDOG),
	S(EVENT_CHECK_CRLS),
	S(EVENT_FREE_ROOT_CERTS),
	S(EVENT_RESET_LOG_LIMITER),
	S(EVENT_PROCESS_KERNEL_QUEUE),
	S(EVENT_NAT_T_KEEPALIVE),
#undef S
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
#define S(E) [E - EVENT_NULL] = #E
	S(EVENT_NULL),
	S(EVENT_RETRANSMIT),
	S(EVENT_CRYPTO_TIMEOUT),
#undef S
};

static const enum_names event_names = {
	EVENT_NULL, EVENT_CRYPTO_TIMEOUT,
	ARRAY_REF(event_name),
	"EVENT_", /* prefix */
	NULL
};

static const char *const event_v1_name[] = {
#define S(E) [E - EVENT_v1_SEND_XAUTH] = #E
	S(EVENT_v1_SEND_XAUTH),
	S(EVENT_v1_DPD),
	S(EVENT_v1_DPD_TIMEOUT),
	S(EVENT_v1_PAM_TIMEOUT),
	S(EVENT_v1_REPLACE),
	S(EVENT_v1_DISCARD),
	S(EVENT_v1_EXPIRE),
#undef S
};

static const enum_names event_v1_names = {
	EVENT_v1_SEND_XAUTH, EVENT_v1_REPLACE,
	ARRAY_REF(event_v1_name),
	"EVENT_v1_", /* prefix */
	&event_names
};

static const char *const event_v2_name[] = {
#define S(E) [E - EVENT_v2_REKEY] = #E
	S(EVENT_v2_REKEY),
	S(EVENT_v2_REPLACE),
	S(EVENT_v2_DISCARD),
	S(EVENT_v2_LIVENESS),
	S(EVENT_v2_ADDR_CHANGE),
	S(EVENT_v2_EXPIRE),
#undef S
};

static const enum_names event_v2_names = {
	EVENT_v2_REKEY, EVENT_v2_ADDR_CHANGE,
	ARRAY_REF(event_v2_name),
	"EVENT_v2_", /* prefix */
	&event_v1_names,
};

static const char *const event_retain_name[] = {
#define S(E) [E - EVENT_RETAIN] = #E
	S(EVENT_RETAIN),
#undef S
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
