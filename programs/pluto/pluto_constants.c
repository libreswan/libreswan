/* tables of names for values defined in constants.h
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#ifdef NETKEY_SUPPORT
#include "linux/xfrm.h" /* local (if configured) or system copy */
#endif
#include <libreswan.h>
#include <libreswan/passert.h>

#include "constants.h"
#include "enum_names.h"

/*
 * To obsolete or convert to runtime options:
 * ALLOW_MICROSOFT_BAD_PROPOSAL
 * EMIT_ISAKMP_SPI
 * IPSEC_CONNECTION_LIMIT
 * NET_21
 * NO_EXTRA_IKE
 * NOTYET
 * NOT_YET
 * PFKEY
 * PLUTO_SENDS_VENDORID
 * PLUTO_GROUP_CTL
 * SINGLE_CONF_DIR
 * SOFTREMOTE_CLIENT_WORKAROUND
 * TEST_INDECENT_PROPOSAL
 * USE_3DES USE_AES USE_MD5 USE_SERPENT USE_SHA1 USE_SHA2 USE_TWOFISH
 * USE_KEYRR
 */

static const char *const kern_interface_name[] = {
	"no-kernel", /* run without stack */
	"klips",
	"netkey",
	"win2k",
	"mastklips",
	"bsdkame"
};
enum_names kern_interface_names = {
	NO_KERNEL, USE_BSDKAME,
	ARRAY_REF(kern_interface_name),
	NULL, /* prefix */
	NULL
};

/* DPD actions */
static const char *const dpd_action_name[] = {
	"action:disabled",
	"action:clear",
	"action:hold",
	"action:restart",
};

enum_names dpd_action_names = {
	DPD_ACTION_DISABLED, DPD_ACTION_RESTART,
	ARRAY_REF(dpd_action_name),
	NULL, /* prefix */
	NULL
};

#ifdef NETKEY_SUPPORT
/* netkey SA direction names */
static const char *const netkey_sa_dir_name[] = {
	"XFRM_IN",
	"XFRM_OUT",
	"XFRM_FWD",
};

enum_names netkey_sa_dir_names = {
	XFRM_POLICY_IN, XFRM_POLICY_FWD,
	ARRAY_REF(netkey_sa_dir_name),
	NULL, /* prefix */
	NULL
};
#endif

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

/* Timer events */
static const char *const timer_event_name[] = {
	"EVENT_NULL",

	"EVENT_REINIT_SECRET",
	"EVENT_SHUNT_SCAN",
	"EVENT_PENDING_DDNS",
	"EVENT_SD_WATCHDOG",
	"EVENT_PENDING_PHASE2",
	"EVENT_CHECK_CRLS",

	"EVENT_SO_DISCARD",
	"EVENT_v1_RETRANSMIT",
	"EVENT_v1_SEND_XAUTH",
	"EVENT_SA_REPLACE",
	"EVENT_SA_REPLACE_IF_USED",
	"EVENT_v2_SA_REPLACE_IF_USED_IKE",
	"EVENT_v2_SA_REPLACE_IF_USED",
	"EVENT_SA_EXPIRE",
	"EVENT_NAT_T_KEEPALIVE",
	"EVENT_DPD",
	"EVENT_DPD_TIMEOUT",
	"EVENT_CRYPTO_TIMEOUT",
	"EVENT_PAM_TIMEOUT",

	"EVENT_v2_RETRANSMIT",
	"EVENT_v2_RESPONDER_TIMEOUT",
	"EVENT_v2_LIVENESS",
	"EVENT_v2_RELEASE_WHACK",
	"EVENT_v2_INITIATE_CHILD",
	"EVENT_v2_SEND_NEXT_IKE",
	"EVENT_v2_ADDR_CHANGE",
	"EVENT_RETAIN",
};

enum_names timer_event_names = {
	EVENT_NULL, EVENT_RETAIN,
	ARRAY_REF(timer_event_name),
	NULL, /* prefix */
	NULL
};

/* State of exchanges */
#define S(STATE) [STATE] = #STATE
static const char *const state_name[] = {
	S(STATE_UNDEFINED),
	S(STATE_UNUSED_1),
	S(STATE_UNUSED_2),
	S(STATE_MAIN_R0),
	S(STATE_MAIN_I1),
	S(STATE_MAIN_R1),
	S(STATE_MAIN_I2),
	S(STATE_MAIN_R2),
	S(STATE_MAIN_I3),
	S(STATE_MAIN_R3),
	S(STATE_MAIN_I4),

	S(STATE_AGGR_R0),
	S(STATE_AGGR_I1),
	S(STATE_AGGR_R1),
	S(STATE_AGGR_I2),
	S(STATE_AGGR_R2),

	S(STATE_QUICK_R0),
	S(STATE_QUICK_I1),
	S(STATE_QUICK_R1),
	S(STATE_QUICK_I2),
	S(STATE_QUICK_R2),

	S(STATE_INFO),
	S(STATE_INFO_PROTECTED),

	S(STATE_XAUTH_R0),
	S(STATE_XAUTH_R1),
	S(STATE_MODE_CFG_R0),
	S(STATE_MODE_CFG_R1),
	S(STATE_MODE_CFG_R2),

	S(STATE_MODE_CFG_I1),

	S(STATE_XAUTH_I0),
	S(STATE_XAUTH_I1),

	S(STATE_IKEv1_ROOF),

	/* v2 */
	S(STATE_IKEv2_BASE),
	S(STATE_PARENT_I0),
	S(STATE_PARENT_I1),
	S(STATE_PARENT_I2),
	S(STATE_PARENT_I3),
	S(STATE_PARENT_R0),
	S(STATE_PARENT_R1),
	S(STATE_PARENT_R2),
	S(STATE_V2_CREATE_I0),
	S(STATE_V2_CREATE_I),
	S(STATE_V2_REKEY_IKE_I0),
	S(STATE_V2_REKEY_IKE_I),
	S(STATE_V2_REKEY_CHILD_I0),
	S(STATE_V2_REKEY_CHILD_I),
	S(STATE_V2_CREATE_R),
	S(STATE_V2_REKEY_IKE_R),
	S(STATE_V2_REKEY_CHILD_R),
	S(STATE_V2_IPSEC_I),
	S(STATE_V2_IPSEC_R),
	S(STATE_IKESA_DEL),
	S(STATE_CHILDSA_DEL),

	S(STATE_IKEv2_ROOF),
};
#undef S

enum_names state_names = {
	STATE_UNDEFINED, STATE_IKEv2_ROOF,
	ARRAY_REF(state_name),
	"STATE_", /* prefix */
	NULL
};

/* story for state */

static const char *const state_story[] = {
	[STATE_UNDEFINED] = "not defined and probably dead (internal)",
	[STATE_UNUSED_1] = "STATE_UNUSED_1",
	[STATE_UNUSED_2] = "STATE_UNUSED_2",
	[STATE_MAIN_R0] = "expecting MI1",
	[STATE_MAIN_I1] = "sent MI1, expecting MR1",
	[STATE_MAIN_R1] = "sent MR1, expecting MI2",
	[STATE_MAIN_I2] = "sent MI2, expecting MR2",
	[STATE_MAIN_R2] = "sent MR2, expecting MI3",
	[STATE_MAIN_I3] = "sent MI3, expecting MR3",
	[STATE_MAIN_R3] = "sent MR3, ISAKMP SA established",
	[STATE_MAIN_I4] = "ISAKMP SA established",

	[STATE_AGGR_R0] = "expecting AI1",
	[STATE_AGGR_I1] = "sent AI1, expecting AR1",
	[STATE_AGGR_R1] = "sent AR1, expecting AI2",
	[STATE_AGGR_I2] = "sent AI2, ISAKMP SA established",
	[STATE_AGGR_R2] = "ISAKMP SA established",

	[STATE_QUICK_R0] = "expecting QI1",
	[STATE_QUICK_I1] = "sent QI1, expecting QR1",
	[STATE_QUICK_R1] = "sent QR1, inbound IPsec SA installed, expecting QI2",
	[STATE_QUICK_I2] = "sent QI2, IPsec SA established",
	[STATE_QUICK_R2] = "IPsec SA established",

	[STATE_INFO] = "got Informational Message in clear",
	[STATE_INFO_PROTECTED] = "got encrypted Informational Message",

	[STATE_XAUTH_R0] = "XAUTH responder - optional CFG exchange",
	[STATE_XAUTH_R1] = "XAUTH status sent, expecting Ack",
	[STATE_MODE_CFG_R0] = "ModeCfg Reply sent",
	[STATE_MODE_CFG_R1] = "ModeCfg Set sent, expecting Ack",
	[STATE_MODE_CFG_R2] = "ModeCfg R2",

	[STATE_MODE_CFG_I1] = "ModeCfg inititator - awaiting CFG_reply",

	[STATE_XAUTH_I0] = "XAUTH client - possibly awaiting CFG_request",
	[STATE_XAUTH_I1] = "XAUTH client - possibly awaiting CFG_set",

	[STATE_IKEv1_ROOF] = "invalid state - IKE roof",
	[STATE_IKEv2_FLOOR] = "invalid state - IKEv2 base",

	[STATE_PARENT_I0] = "waiting for KE to finish",
	[STATE_PARENT_I1] = "sent v2I1, expected v2R1",
	[STATE_PARENT_I2] = "sent v2I2, expected v2R2",
	[STATE_PARENT_I3] = "PARENT SA established",
	[STATE_PARENT_R0] = "processing SA_INIT request",
	[STATE_PARENT_R1] = "received v2I1, sent v2R1",
	[STATE_PARENT_R2] = "received v2I2, PARENT SA established",
	[STATE_V2_CREATE_I0] = "STATE_V2_CREATE_I0",
	[STATE_V2_CREATE_I] = "sent IPsec Child req wait response",
	[STATE_V2_REKEY_IKE_I0] = "STATE_V2_REKEY_IKE_I0",
	[STATE_V2_REKEY_IKE_I] = "STATE_V2_REKEY_IKE_I",
	[STATE_V2_REKEY_CHILD_I0] = "STATE_V2_REKEY_CHILD_I0",
	[STATE_V2_REKEY_CHILD_I] = "STATE_V2_REKEY_CHILD_I",
	[STATE_V2_CREATE_R] = "STATE_V2_CREATE_R",
	[STATE_V2_REKEY_IKE_R] = "STATE_V2_REKEY_IKE_R",
	[STATE_V2_REKEY_CHILD_R] = "STATE_V2_REKEY_CHILD_R",
	[STATE_V2_IPSEC_I] = "IPsec SA established",
	[STATE_V2_IPSEC_R] = "IPsec SA established",

	/* ??? better story needed for these */
	[STATE_IKESA_DEL] = "STATE_IKESA_DEL",
	[STATE_CHILDSA_DEL] = "STATE_CHILDSA_DEL",

	[STATE_IKEv2_ROOF] = "invalid state - IKEv2 roof",
};

enum_names state_stories = {
	STATE_UNDEFINED, STATE_IKEv2_ROOF,
	ARRAY_REF(state_story),
	NULL, /* prefix */
	NULL
};

/*
 * natt_bit_names is dual purpose:
 * - for bitnamesof(natt_bit_names, lset_t of enum natt_method)
 * - for enum_name(&natt_method_names, enum natt_method)
 */
const char *const natt_bit_names[] = {
	"none",
	"draft-ietf-ipsec-nat-t-ike-02/03",
	"draft-ietf-ipsec-nat-t-ike-05",
	"RFC 3947 (NAT-Traversal)",

	"I am behind NAT",
	"peer behind NAT",
	NULL	/* end for bitnamesof() */
};

enum_names natt_method_names = {
	NAT_TRAVERSAL_METHOD_none, NATED_PEER,
	ARRAY_REF(natt_bit_names)-1,
	NULL, /* prefix */
	NULL
};

/* routing status names */
static const char *const routing_story_strings[] = {
	"unrouted",             /* RT_UNROUTED: unrouted */
	"unrouted HOLD",        /* RT_UNROUTED_HOLD: unrouted, but HOLD shunt installed */
	"eroute eclipsed",      /* RT_ROUTED_ECLIPSED: RT_ROUTED_PROSPECTIVE except bare HOLD or instance has eroute */
	"prospective erouted",  /* RT_ROUTED_PROSPECTIVE: routed, and prospective shunt installed */
	"erouted HOLD",         /* RT_ROUTED_HOLD: routed, and HOLD shunt installed */
	"fail erouted",         /* RT_ROUTED_FAILURE: routed, and failure-context shunt eroute installed */
	"erouted",              /* RT_ROUTED_TUNNEL: routed, and erouted to an IPSEC SA group */
	"keyed, unrouted",      /* RT_UNROUTED_KEYED: was routed+keyed, but it got turned into an outer policy */
};

enum_names routing_story = {
	RT_UNROUTED, RT_UNROUTED_KEYED,
	ARRAY_REF(routing_story_strings),
	NULL, /* prefix */
	NULL };

static const char *const stf_status_strings[] = {
	"STF_IGNORE",
	"STF_SUSPEND",
	"STF_OK",
	"STF_INTERNAL_ERROR",
	"STF_FATAL",
	"STF_DROP",
	"STF_FAIL"
};

enum_names stf_status_names = {
	STF_IGNORE, STF_FAIL,
	ARRAY_REF(stf_status_strings),
	NULL, /* prefix */
	NULL
};

/* Names for sa_policy_bits.
 * Note: we drop the POLICY_ prefix so that logs are more concise.
 */
const char *const sa_policy_bit_names[] = {
	"PSK",
	"RSASIG",
	"ECDSA",
	"AUTH_NEVER",
	"AUTHNULL",
	"ENCRYPT",
	"AUTHENTICATE",
	"COMPRESS",
	"TUNNEL",
	"PFS",
	"DISABLEARRIVALCHECK",
	"DECAP_DSCP",
	"NOPMTUDISC",
	"MSDH_DOWNGRADE",
	"DNS_MATCH_ID",
	"SHA2_TRUNCBUG",
	"SHUNT0",
	"SHUNT1",
	"FAIL0",
	"FAIL1",
	"NEGO_PASS",
	"DONT_REKEY",
	"REAUTH",
	"OPPORTUNISTIC",
	"GROUP",
	"GROUTED",
	"GROUPINSTANCE",
	"UP",
	"XAUTH",
	"MODECFG_PULL",
	"AGGRESSIVE",
	"OVERLAPIP",
	"IKEV1_ALLOW",
	"IKEV2_ALLOW",
	"IKEV2_PROPOSE",
	"IKEV2_ALLOW_NARROWING",
	"IKEV2_PAM_AUTHORIZE",
	"SAREF_TRACK",
	"SAREF_TRACK_CONNTRACK",
	"IKE_FRAG_ALLOW",
	"IKE_FRAG_FORCE",
	"NO_IKEPAD",
	"MOBIKE",
	"PPK_ALLOW",
	"PPK_INSIST",
	"ESN_NO",
	"ESN_YES",
	NULL	/* end for bitnamesof() */
};

static const char *const ikev2_asym_auth_names[] = {
	"unset",
	"never",
	"secret",
	"rsasig",
	"ecdsa",
	"null",
};

enum_names ikev2_asym_auth_name = {
	AUTH_UNSET, AUTH_NULL,
	ARRAY_REF(ikev2_asym_auth_names),
	NULL, /* prefix */
	NULL
};

static const char *const policy_shunt_names[4] = {
	"TRAP",
	"PASS",
	"DROP",
	"REJECT",
};

static const char *const policy_fail_names[4] = {
	"NONE",
	"PASS",
	"DROP",
	"REJECT",
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

/* print a policy: like bitnamesof, but it also does the non-bitfields.
 * Suppress the shunt and fail fields if 0.
 */
const char *prettypolicy(lset_t policy)
{
	char pbitnamesbuf[200];
	const char *bn = bitnamesofb(sa_policy_bit_names,
				     policy &
				     ~(POLICY_SHUNT_MASK | POLICY_FAIL_MASK),
				     pbitnamesbuf, sizeof(pbitnamesbuf));
	static char buf[512]; /* NOT RE-ENTRANT!  I hope that it is big enough! */
	lset_t shunt = (policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT;
	lset_t fail = (policy & POLICY_FAIL_MASK) >> POLICY_FAIL_SHIFT;

	if (bn != pbitnamesbuf)
		pbitnamesbuf[0] = '\0';
	snprintf(buf, sizeof(buf), "%s%s%s%s%s",
		 pbitnamesbuf,
		 shunt == POLICY_SHUNT_TRAP >> POLICY_SHUNT_SHIFT ?  "" : "+",
		 shunt ==  POLICY_SHUNT_TRAP >> POLICY_SHUNT_SHIFT ? "" : policy_shunt_names[shunt],
		 fail == POLICY_FAIL_NONE >> POLICY_FAIL_SHIFT ? "" : "+failure",
		 fail == POLICY_FAIL_NONE >> POLICY_FAIL_SHIFT ? "" : policy_fail_names[fail]);
	return buf;
}

static const enum_names *pluto_enum_names_checklist[] = {
	&kern_interface_names,
	&dpd_action_names,
	&sd_action_names,
	&timer_event_names,
	&state_names,
	&state_stories,
	&natt_method_names,
	&routing_story,
	&stf_status_names,
#ifdef NETKEY_SUPPORT
	&netkey_sa_dir_names,
#endif
};

void init_pluto_constants(void) {
	check_enum_names(ARRAY_REF(pluto_enum_names_checklist));
}
