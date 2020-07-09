/* tables of names for values defined in constants.h
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
#ifdef XFRM_SUPPORT
#include "linux/xfrm.h" /* local (if configured) or system copy */
#endif
#include "passert.h"

#include "constants.h"
#include "enum_names.h"
#include "defs.h"

/*
 * To obsolete or convert to runtime options:
 * ALLOW_MICROSOFT_BAD_PROPOSAL
 * IPSEC_CONNECTION_LIMIT
 * NOTYET
 * NOT_YET
 * PFKEY
 * PLUTO_GROUP_CTL
 * SOFTREMOTE_CLIENT_WORKAROUND
 * USE_3DES USE_AES USE_MD5 USE_SHA1 USE_SHA2
 */

static const char *const kern_interface_name[] = {
	[USE_XFRM] = "netkey",
	[USE_BSDKAME] = "bsdkame",
};

enum_names kern_interface_names = {
	USE_XFRM, USE_BSDKAME,
	ARRAY_REF(kern_interface_name),
	"USE_", /* prefix */
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

#ifdef XFRM_SUPPORT
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
#define E(EVENT) [EVENT] = #EVENT

	E(EVENT_NULL),

	E(EVENT_SO_DISCARD),
	E(EVENT_RETRANSMIT),

	E(EVENT_SA_REKEY),
	E(EVENT_SA_REPLACE),
	E(EVENT_SA_EXPIRE),

	E(EVENT_v1_SEND_XAUTH),
	E(EVENT_v1_SA_REPLACE_IF_USED),
	E(EVENT_DPD),
	E(EVENT_DPD_TIMEOUT),
	E(EVENT_CRYPTO_TIMEOUT),
	E(EVENT_PAM_TIMEOUT),

	E(EVENT_v2_LIVENESS),
	E(EVENT_v2_RELEASE_WHACK),
	E(EVENT_v2_INITIATE_CHILD),
	E(EVENT_v2_ADDR_CHANGE),
	E(EVENT_v2_REDIRECT),
	E(EVENT_RETAIN),

#undef E
};

enum_names timer_event_names = {
	EVENT_NULL, EVENT_RETAIN,
	ARRAY_REF(timer_event_name),
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
#define A(S) [S] = #S
	A(STF_SKIP_COMPLETE_STATE_TRANSITION),
	A(STF_IGNORE),
	A(STF_SUSPEND),
	A(STF_OK),
	A(STF_INTERNAL_ERROR),
	A(STF_V2_DELETE_EXCHANGE_INITIATOR_IKE_SA),
	A(STF_FATAL),
	A(STF_FAIL),
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
	"DECAP_DSCP",
	"NOPMTUDISC",
	"MSDH_DOWNGRADE",
	"ALLOW_NO_SAN",
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
	"IKEV2_ALLOW_NARROWING",
	"IKEV2_PAM_AUTHORIZE",
	"SEND_REDIRECT_ALWAYS",
	"SEND_REDIRECT_NEVER",
	"ACCEPT_REDIRECT_YES",
	"IKE_FRAG_ALLOW",
	"IKE_FRAG_FORCE",
	"NO_IKEPAD",
	"MOBIKE",
	"PPK_ALLOW",
	"PPK_INSIST",
	"ESN_NO",
	"ESN_YES",
	"RSASIG_v1_5",
	NULL	/* end for bitnamesof() */
};

/*
 * Names for RFC 7427 IKEv2 AUTH signature hash algo sighash_policy_bits
 */
const char *const sighash_policy_bit_names[] = {
	"SHA2_256",
	"SHA2_384",
	"SHA2_512",
	NULL	/* end for bitnamesof() */
};

static const char *const keyword_authby_name[] = {
	"unset",
	"never",
	"secret",
	"rsasig",
	"ecdsa",
	"null",
};

enum_names keyword_authby_names = {
	AUTHBY_UNSET, AUTHBY_NULL,
	ARRAY_REF(keyword_authby_name),
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

/*
 * enum sa_type
 */

static const char *const v1_sa_type_name[] = {
	[IKE_SA] = "ISAKMP SA",
	[IPSEC_SA] = "IPsec SA"
};

enum_names v1_sa_type_names = {
	SA_TYPE_FLOOR, SA_TYPE_ROOF-1,
	ARRAY_REF(v1_sa_type_name),
	NULL, /* prefix */
	NULL,
};

static const char *const v2_sa_type_name[] = {
	[IKE_SA] = "IKE SA",
	[IPSEC_SA] = "CHILD SA"
};

enum_names v2_sa_type_names = {
	SA_TYPE_FLOOR, SA_TYPE_ROOF-1,
	ARRAY_REF(v2_sa_type_name),
	NULL, /* prefix */
	NULL,
};

static enum_names *sa_type_name[] = {
	[IKEv1 - IKEv1] = &v1_sa_type_names,
	[IKEv2 - IKEv1] = &v2_sa_type_names,
};

enum_enum_names sa_type_names = {
	IKEv1, IKEv2,
	ARRAY_REF(sa_type_name),
};

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
	&natt_method_names,
	&routing_story,
	&stf_status_names,
#ifdef XFRM_SUPPORT
	&netkey_sa_dir_names,
#endif
	&v1_sa_type_names,
	&v2_sa_type_names,
	&perspective_names,
};

void init_pluto_constants(void) {
	check_enum_names(ARRAY_REF(pluto_enum_names_checklist));
}
