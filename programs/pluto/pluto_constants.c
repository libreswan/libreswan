/* tables of names for values defined in constants.h
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>
#include <libreswan/passert.h>

#include "constants.h"
#include "enum_names.h"

/* 
 * To obsolete or convert to runtime options:
 * ALG_PATCH
 * ALLOW_MICROSOFT_BAD_PROPOSAL
 * DMALLOC
 * EMIT_ISAKMP_SPI
 * HAVE_STATSD
 * I_DONT_CARE_OF_SSH_SENTINEL
 * IPSEC_CONNECTION_LIMIT
 * NET_21
 * NO_EXTRA_IKE
 * NOTYET
 * NOT_YET
 * OLD_RESOLVER
 * PFKEY
 * PLUTO_SENDS_VENDORID
 * PLUTO_GROUP_CTL
 * SINGLE_CONF_DIR
 * SOFTREMOTE_CLIENT_WORKAROUND
 * SUPPORT_ESP_NULL
 * TEST_INDECENT_PROPOSAL 
 * USE_3DES USE_AES USE_MD5 USE_SERPENT USE_SHA1 USE_SHA2 USE_TWOFISH
 * USE_KEYRR
 * VIRTUAL_IP
 */

static const char *const kern_interface_name[] = {
	"none",
	"auto-pick",
	"klips",
	"netkey",
	"win2k",
	"mastklips",
	"bsdkame"
};
enum_names kern_interface_names =
{ NO_KERNEL, USE_BSDKAME, kern_interface_name, NULL };

/* DPD actions */
static const char *const dpd_action_name[] = {
	"action:clear",
	"action:hold",
	"action:restart",
};

enum_names dpd_action_names =
{ EVENT_NULL, DPD_ACTION_RESTART, dpd_action_name, NULL };

/* Timer events */
static const char *const timer_event_name[] = {
	"EVENT_NULL",
	"EVENT_REINIT_SECRET",
	"EVENT_SHUNT_SCAN",
	"EVENT_SO_DISCARD",
	"EVENT_RETRANSMIT",
	"EVENT_SA_REPLACE",
	"EVENT_SA_REPLACE_IF_USED",
	"EVENT_SA_EXPIRE",
	"EVENT_NAT_T_KEEPALIVE",
	"EVENT_DPD",
	"EVENT_DPD_TIMEOUT",
	"EVENT_LOG_DAILY",
	"EVENT_CRYPTO_FAILED",
	"EVENT_PENDING_PHASE2",
	"EVENT_v2_RETRANSMIT",
	"EVENT_PENDING_DDNS"
};

enum_names timer_event_names =
{ EVENT_NULL, EVENT_PENDING_DDNS, timer_event_name, NULL };

/* State of exchanges */
static const char *const state_name[] = {
	"STATE_MAIN_R0",
	"STATE_MAIN_I1",
	"STATE_MAIN_R1",
	"STATE_MAIN_I2",
	"STATE_MAIN_R2",
	"STATE_MAIN_I3",
	"STATE_MAIN_R3",
	"STATE_MAIN_I4",

	"STATE_AGGR_R0",
	"STATE_AGGR_I1",
	"STATE_AGGR_R1",
	"STATE_AGGR_I2",
	"STATE_AGGR_R2",

	"STATE_QUICK_R0",
	"STATE_QUICK_I1",
	"STATE_QUICK_R1",
	"STATE_QUICK_I2",
	"STATE_QUICK_R2",

	"STATE_INFO",
	"STATE_INFO_PROTECTED",

	"STATE_XAUTH_R0",
	"STATE_XAUTH_R1",
	"STATE_MODE_CFG_R0",
	"STATE_MODE_CFG_R1",
	"STATE_MODE_CFG_R2",

	"STATE_MODE_CFG_I1",

	"STATE_XAUTH_I0",
	"STATE_XAUTH_I1",

	"STATE_IKE_ROOF",

	/* v2 */
	"STATE_IKEv2_START",
	"STATE_PARENT_I1",
	"STATE_PARENT_I2",
	"STATE_PARENT_I3",
	"STATE_PARENT_R1",
	"STATE_PARENT_R2",
	"STATE_IKEv2_ROOF"

};

enum_names state_names =
{ STATE_MAIN_R0, STATE_IKEv2_ROOF - 1, state_name, NULL };

/* story for state */

const char *const state_story[] = {
	"expecting MI1",                                        /* STATE_MAIN_R0 */
	"sent MI1, expecting MR1",                              /* STATE_MAIN_I1 */
	"sent MR1, expecting MI2",                              /* STATE_MAIN_R1 */
	"sent MI2, expecting MR2",                              /* STATE_MAIN_I2 */
	"sent MR2, expecting MI3",                              /* STATE_MAIN_R2 */
	"sent MI3, expecting MR3",                              /* STATE_MAIN_I3 */
	"sent MR3, ISAKMP SA established",                      /* STATE_MAIN_R3 */
	"ISAKMP SA established",                                /* STATE_MAIN_I4 */

	"expecting AI1",                                        /* STATE_AGGR_R0 */
	"sent AI1, expecting AR1",                              /* STATE_AGGR_I1 */
	"sent AR1, expecting AI2",                              /* STATE_AGGR_R1 */
	"sent AI2, ISAKMP SA established",                      /* STATE_AGGR_I2 */
	"ISAKMP SA established",                                /* STATE_AGGR_R2 */

	"expecting QI1",                                        /* STATE_QUICK_R0 */
	"sent QI1, expecting QR1",                              /* STATE_QUICK_I1 */
	"sent QR1, inbound IPsec SA installed, expecting QI2",  /* STATE_QUICK_R1 */
	"sent QI2, IPsec SA established",                       /* STATE_QUICK_I2 */
	"IPsec SA established",                                 /* STATE_QUICK_R2 */

	"got Informational Message in clear",                   /* STATE_INFO */
	"got encrypted Informational Message",                  /* STATE_INFO_PROTECTED */

	"XAUTH responder - optional CFG exchange",              /* STATE_XAUTH_R0 */
	"XAUTH status sent, expecting Ack",                     /* STATE_XAUTH_R1 */
	"ModeCfg Reply sent",                           /* STATE_MODE_CFG_R0 */
	"ModeCfg Set sent, expecting Ack",              /* STATE_MODE_CFG_R1 */
	"ModeCfg R2",                                   /* STATE_MODE_CFG_R2 */

	"ModeCfg inititator - awaiting CFG_reply",      /* STATE_MODE_CFG_I1 */

	"XAUTH client - awaiting CFG_request",          /* MODE_XAUTH_I0 */
	"XAUTH client - awaiting CFG_set",              /* MODE_XAUTH_I1 */
	"invalid state - IKE roof",
	"invalid state - IKEv2 base",
	"sent v2I1, expected v2R1",             /* STATE_PARENT_I1 */
	"sent v2I2, expected v2R2",
	"PARENT SA established",
	"received v2I1, sent v2R1",
	"received v2I2, PARENT SA established",
	"invalid state - IKEv2 roof"
};

enum_names state_stories =
{ STATE_MAIN_R0, STATE_IKEv2_ROOF - 1, state_story, NULL };

static const char *const natt_method_result_name[] = {
	"NAT behind me",        /* 30 */
	"NAT behind peer"       /* 31 */
};
enum_names natt_method_result_names =
{ NAT_TRAVERSAL_NAT_BHND_ME, NAT_TRAVERSAL_NAT_BHND_PEER,
  natt_method_result_name, NULL };

static const char *const natt_method_name[] = {
	"draft-ietf-ipsec-nat-t-ike-00/01", /* 1 */
	"draft-ietf-ipsec-nat-t-ike-02/03",
	"draft-ietf-ipsec-nat-t-ike-05",
	"RFC 3947 (NAT-Traversal)" /* 4*/
};
enum_names natt_method_names =
{ NAT_TRAVERSAL_METHOD_IETF_00_01, NAT_TRAVERSAL_METHOD_IETF_RFC,
  natt_method_name, &natt_method_result_names };

/* pluto crypto operations */
static const char *const pluto_cryptoop_strings[] = {
	"build_kenonce",        /* calculate g^i and nonce */
	"rsa_sign",             /* do rsa signature operation */
	"rsa_check",            /* do rsa signature check */
	"x509cert_fetch",       /* X.509 fetch operation */
	"x509crl_fetch",        /* X.509 crl fetch operation */
	"build_nonce",          /* just fetch a new nonce */
	"compute dh+iv",        /* perform (g^x)(g^y) and calculate skeyids */
	"compute dh(p2)",       /* perform (g^x)(g^y) */
	"compute dh(v2)",       /* IKEv2 IKE_SA calculation */
};

enum_names pluto_cryptoop_names =
{ pcr_build_kenonce, pcr_compute_dh_v2, pluto_cryptoop_strings, NULL };

/* pluto crypto importance */
static const char *const pluto_cryptoimportance_strings[] = {
	"import:not set",
	"import:respond to stranger",
	"import:respond to friend",
	"import:ongoing calculation",
	"import:local rekey",
	"import:admin initiate"
};

enum_names pluto_cryptoimportance_names =
{ pcim_notset_crypto, pcim_demand_crypto,
  pluto_cryptoimportance_strings, NULL };

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

enum_names routing_story =
{ RT_UNROUTED, RT_ROUTED_TUNNEL, routing_story_strings, NULL };

static const char *const stfstatus_names[] = {
	"STF_IGNORE",
	"STF_INLINE",
	"STF_SUSPEND",
	"STF_OK",
	"STF_INTERNAL_ERROR",
	"STF_TOOMUCHCRYPTO",
	"STF_FATAL",
	"STF_STOLEN",
	"STF_FAIL"
};
enum_names stfstatus_name =
{ STF_IGNORE, STF_FAIL, stfstatus_names, NULL };

/* Goal BITs for establishing an SA
 * Note: we drop the POLICY_ prefix so that logs are more concise.
 */

const char *const sa_policy_bit_names[] = {
	"PSK",
	"RSASIG",
	"ENCRYPT",
	"AUTHENTICATE",
	"COMPRESS",
	"TUNNEL",
	"PFS",
	"DISABLEARRIVALCHECK",
	"SHUNT0",
	"SHUNT1",
	"FAILSHUNT0",
	"FAILSHUNT1",
	"DONTREKEY",
	"OPPORTUNISTIC",
	"GROUP",
	"GROUTED",
	"UP",
	"XAUTH",
	"MODECFGPULL",
	"AGGRESSIVE",
	"PERHOST",
	"SUBHOST",
	"PERPROTO",
	"OVERLAPIP",
	"!IKEv1",
	"IKEv2ALLOW",
	"IKEv2Init",
	"IKEv2ALLOW_NARROWING",
	"SAREFTRACK",
	"SAREFCONNTRACK",
	"IKE_FRAG",
	"IKE_FRAG_FORCE",
	"NO_IKEPAD",
	NULL
};

const char *const policy_shunt_names[4] = {
	"TRAP",
	"PASS",
	"DROP",
	"REJECT",
};

const char *const policy_fail_names[4] = {
	"NONE",
	"PASS",
	"DROP",
	"REJECT",
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
	static char buf[200]; /* NOT RE-ENTRANT!  I hope that it is big enough! */
	lset_t shunt = (policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT;
	lset_t fail = (policy & POLICY_FAIL_MASK) >> POLICY_FAIL_SHIFT;

	if (bn != pbitnamesbuf)
		pbitnamesbuf[0] = '\0';
	snprintf(buf, sizeof(buf), "%s%s%s%s%s%s",
		 pbitnamesbuf,
		 shunt != 0 ? "+" : "",
		 shunt != 0 ? policy_shunt_names[shunt] : "",
		 fail != 0 ? "+failure" : "", fail !=
		 0 ? policy_fail_names[fail] : "",
		 NEVER_NEGOTIATE(policy) ? "+NEVER_NEGOTIATE" : "");
	return buf;
}
