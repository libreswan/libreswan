/* tables of names for values defined in constants.h
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

/*
 * Note that the array sizes are all specified; this is to enable range
 * checking by code that only includes constants.h.
 */

#include "passert.h"

#include "jambuf.h"
#include "constants.h"
#include "enum_names.h"
#include "defs.h"
#include "kernel.h"

/*
 * To obsolete or convert to runtime options:
 * IPSEC_CONNECTION_LIMIT
 * NOTYET
 * NOT_YET
 * PFKEY
 * PLUTO_GROUP_CTL
 * SOFTREMOTE_CLIENT_WORKAROUND
 * USE_3DES USE_AES USE_MD5 USE_SHA1 USE_SHA2
 */

/* DPD actions */
static const char *const dpd_action_name[] = {
	"action:unset",
	"action:clear",
	"action:hold",
	"action:restart",
};

enum_names dpd_action_names = {
	DPD_ACTION_UNSET, DPD_ACTION_RESTART,
	ARRAY_REF(dpd_action_name),
	"action:", /* prefix */
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

static const char *const stf_status_strings[] = {
#define A(S) [S] = #S
	A(STF_SKIP_COMPLETE_STATE_TRANSITION),
	A(STF_IGNORE),
	A(STF_SUSPEND),
	A(STF_OK),
	A(STF_INTERNAL_ERROR),
	A(STF_V2_RESPONDER_DELETE_IKE_FAMILY),
	A(STF_V2_INITIATOR_DELETE_IKE_FAMILY),
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
	P(POLICY_DECAP_DSCP),
	P(POLICY_NOPMTUDISC),
	P(POLICY_MSDH_DOWNGRADE),
	P(POLICY_ALLOW_NO_SAN),
	P(POLICY_DNS_MATCH_ID),
	P(POLICY_SHA2_TRUNCBUG),
	P(POLICY_DONT_REKEY),
	P(POLICY_REAUTH),
	P(POLICY_OPPORTUNISTIC),
	P(POLICY_GROUPINSTANCE),
	P(POLICY_ROUTE),
	P(POLICY_UP),
	P(POLICY_XAUTH),
	P(POLICY_MODECFG_PULL),
	P(POLICY_AGGRESSIVE),
	P(POLICY_OVERLAPIP),
	P(POLICY_IKEV2_ALLOW_NARROWING),
	P(POLICY_IKEV2_PAM_AUTHORIZE),
	P(POLICY_SEND_REDIRECT_ALWAYS),
	P(POLICY_SEND_REDIRECT_NEVER),
	P(POLICY_ACCEPT_REDIRECT_YES),
	P(POLICY_IKE_FRAG_ALLOW),
	P(POLICY_IKE_FRAG_FORCE),
	P(POLICY_NO_IKEPAD),
	P(POLICY_MOBIKE),
	P(POLICY_PPK_ALLOW),
	P(POLICY_PPK_INSIST),
	P(POLICY_ESN_NO),
	P(POLICY_ESN_YES),
	P(POLICY_INTERMEDIATE),
	P(POLICY_IGNORE_PEER_DNS),
#undef P
};

enum_names sa_policy_bit_names = {
	0, POLICY_IX_LAST,
	ARRAY_REF(sa_policy_bit_name),
	"POLICY_", /* prefix */
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

/* enum kernel_policy_op_names */

static const char *kernel_policy_op_name[] = {
#define S(E) [E] = #E
	S(KERNEL_POLICY_OP_ADD),
	S(KERNEL_POLICY_OP_DELETE),
	S(KERNEL_POLICY_OP_REPLACE),
#undef S
};

enum_names kernel_policy_op_names = {
	0, elemsof(kernel_policy_op_name)-1,
	ARRAY_REF(kernel_policy_op_name),
	.en_prefix = "KERNEL_POLICY_OP_",
};

/* enum direction_names */

static const char *direction_name[] = {
#define S(E) [E-DIRECTION_INBOUND] = #E
	S(DIRECTION_OUTBOUND),
	S(DIRECTION_INBOUND),
#undef S
};

enum_names direction_names = {
	DIRECTION_INBOUND,
	DIRECTION_OUTBOUND,
	ARRAY_REF(direction_name),
	.en_prefix = "DIRECTION_",
};

/* enum encap_mode_names */

static const char *encap_mode_name[] = {
#define S(E) [E-ENCAP_MODE_TRANSPORT] = #E
	S(ENCAP_MODE_TRANSPORT),
	S(ENCAP_MODE_TUNNEL),
#undef S
};

enum_names encap_mode_names = {
	ENCAP_MODE_TRANSPORT,
	ENCAP_MODE_TUNNEL,
	ARRAY_REF(encap_mode_name),
	.en_prefix = "ENCAP_MODE_",
};

/* */

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
	A(SHUNT_KIND_IPSEC),
	A(SHUNT_KIND_NEGOTIATION),
	A(SHUNT_KIND_FAILURE),
	A(SHUNT_KIND_BLOCK),
	A(SHUNT_KIND_PROSPECTIVE),
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

/* print a policy: like bitnamesof, but it also does the non-bitfields.
 * Suppress the shunt and fail fields if 0.
 */

size_t jam_policy(struct jambuf *buf, lset_t policy)
{
	size_t s = 0;

	if (policy != LEMPTY) {
		s += jam_lset_short(buf, &sa_policy_bit_names, "+", policy);
	}
	return s;
}

const char *str_policy(lset_t policy, policy_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_policy(&buf, policy);
	return dst->buf;
}

static const enum_names *pluto_enum_names_checklist[] = {
	&dpd_action_names,
	&sd_action_names,
	&natt_method_names,
	&routing_story,
	&stf_status_names,
	&perspective_names,
	&sa_policy_bit_names,
	&kernel_policy_op_names,
	&direction_names,
	&encap_mode_names,
	&shunt_kind_names,
	&shunt_policy_names,
	&keyword_auth_names,
	&keyword_host_names,
};

void init_pluto_constants(void) {
	check_enum_names(ARRAY_REF(pluto_enum_names_checklist));
}
