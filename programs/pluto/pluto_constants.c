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
 * RCSID $Id: pluto_constants.c,v 1.15.2.3 2005/08/19 17:58:09 ken Exp $
 */

/*
 * Note that the array sizes are all specified; this is to enable range
 * checking by code that only includes constants.h.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include <openswan/passert.h>

#include "constants.h"
#include "enum_names.h"

/* string naming compile-time options that have interop implications */
const char compile_time_interop_options[] = ""
	" " X509_VERSION
#ifdef LDAP_VER
#if LDAP_VER == 2
	" LDAP_V2"
#else
	" LDAP_V3"
#endif
#endif
#ifdef SMARTCARD
	" SMARTCARD"
#endif
#ifdef PLUTO_SENDS_VENDORID
	" PLUTO_SENDS_VENDORID"
#endif
#ifdef USE_KEYRR
	" PLUTO_USES_KEYRR"
#endif
    ;

static const char *const kern_interface_name[] = {
  "none",
  "auto-pick",
  "klips",
  "netkey"
};
enum_names kern_interface_names = 
  { NO_KERNEL, USE_NETKEY, kern_interface_name, NULL };

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
	"EVENT_PENDING_PHASE2"
    };

enum_names timer_event_names =
    { EVENT_NULL, EVENT_PENDING_PHASE2, timer_event_name, NULL };

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

	"STATE_IKE_ROOF"  
    };

enum_names state_names =
    { STATE_MAIN_R0, STATE_IKE_ROOF-1, state_name, NULL };

/* story for state */

const char *const state_story[] = {
	"expecting MI1",	/* STATE_MAIN_R0 */
	"sent MI1, expecting MR1",	/* STATE_MAIN_I1 */
	"sent MR1, expecting MI2",	/* STATE_MAIN_R1 */
	"sent MI2, expecting MR2",	/* STATE_MAIN_I2 */
	"sent MR2, expecting MI3",	/* STATE_MAIN_R2 */
	"sent MI3, expecting MR3",	/* STATE_MAIN_I3 */
	"sent MR3, ISAKMP SA established",	/* STATE_MAIN_R3 */
	"ISAKMP SA established",	/* STATE_MAIN_I4 */

	"expecting AI1",			/* STATE_AGGR_R0 */
	"sent AI1, expecting AR1",		/* STATE_AGGR_I1 */
	"sent AR1, expecting AI2",		/* STATE_AGGR_R1 */
	"sent AI2, ISAKMP SA established",	/* STATE_AGGR_I2 */
	"ISAKMP SA established",		/* STATE_AGGR_R2 */

	"expecting QI1",	/* STATE_QUICK_R0 */
	"sent QI1, expecting QR1",	/* STATE_QUICK_I1 */
	"sent QR1, inbound IPsec SA installed, expecting QI2",	/* STATE_QUICK_R1 */
	"sent QI2, IPsec SA established",	/* STATE_QUICK_I2 */
	"IPsec SA established",	/* STATE_QUICK_R2 */

	"got Informational Message in clear",	/* STATE_INFO */
	"got encrypted Informational Message",	/* STATE_INFO_PROTECTED */


	"XAUTH server - CFG_request sent, expecting CFG_reply",
	"XAUTH status send, expecting Ack",
	"ModeCfg Reply sent",			/* STATE_MODE_CFG_R0 */
	"ModeCfg Set sent, expecting Ack",	/* STATE_MODE_CFG_R1 */
	"ModeCfg R2",				/* STATE_MODE_CFG_R2 */

	"ModeCfg inititator - awaiting CFG_reply", /* STATE_MODE_CFG_I1 */

	"XAUTH client - awaiting CFG_request",  /* MODE_XAUTH_I0 */
	"XAUTH client - awaiting CFG_set",      /* MODE_XAUTH_I1 */
	"invalid state - IKE roof"
    };

enum_names state_stories =
    { STATE_MAIN_R0, STATE_IKE_ROOF-1, state_story, NULL };

/* pluto crypto operations */
static const char *const pluto_cryptoop_strings[] = {
  "build_kenonce",	/* calculate g^i and nonce */
  "rsa_sign",	        /* do rsa signature operation */
  "rsa_check",	        /* do rsa signature check */
  "x509cert_fetch",     /* X.509 fetch operation */
  "x509crl_fetch",      /* X.509 crl fetch operation */
  "build_nonce",        /* just fetch a new nonce */
  "compute dh+iv",      /* perform (g^x)(g^y) and calculate skeyids */
  "compute dh(p2)",     /* perform (g^x)(g^y) */
};

enum_names pluto_cryptoop_names =
    { pcr_build_kenonce, pcr_build_nonce, pluto_cryptoop_strings, NULL};


/* pluto crypto importance */
static const char *const pluto_cryptoimportance_strings[] = {
  "stranger asked for crypto",	
  "a known node asked for crypto",
  "an ongoing calculation needs crypto",
  "a local process initiated crypto",
  "a local administrator initiated crypto"
};

enum_names pluto_cryptoimportance_names =
    { pcim_stranger_crypto, pcim_demand_crypto
      , pluto_cryptoimportance_strings, NULL};


/* routing status names */

static const char *const routing_story_strings[] = {
    "unrouted",	/* RT_UNROUTED: unrouted */
    "unrouted HOLD",	/* RT_UNROUTED_HOLD: unrouted, but HOLD shunt installed */
    "eroute eclipsed",	/* RT_ROUTED_ECLIPSED: RT_ROUTED_PROSPECTIVE except bare HOLD or instance has eroute */
    "prospective erouted",	/* RT_ROUTED_PROSPECTIVE: routed, and prospective shunt installed */
    "erouted HOLD",	/* RT_ROUTED_HOLD: routed, and HOLD shunt installed */
    "fail erouted",	/* RT_ROUTED_FAILURE: routed, and failure-context shunt eroute installed */
    "erouted",	/* RT_ROUTED_TUNNEL: routed, and erouted to an IPSEC SA group */
    "keyed, unrouted",  /* RT_UNROUTED_KEYED: was routed+keyed, but it got turned into an outer policy */
    };

enum_names routing_story =
    { RT_UNROUTED, RT_ROUTED_TUNNEL, routing_story_strings, NULL};

static const char *const stfstatus_names[] = {
	"STF_IGNORE",
	"STF_INLINE",
	"STF_SUSPEND",
	"STF_OK",
	"STF_INTERNAL_ERROR",
	"STF_FAIL",
	"STF_FATAL"
};
enum_names stfstatus_name =
  {STF_IGNORE, STF_FATAL, stfstatus_names, NULL};

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
	"dummy1(XAUTH)",
	"MODECFGPULL",
	"AGGRESSIVE",
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

static char pbitnamesbuf[200];   /* only one!  I hope that it is big enough! */

/* print a policy: like bitnamesof, but it also does the non-bitfields.
 * Suppress the shunt and fail fields if 0.
 */
const char *
prettypolicy(lset_t policy)
{
    const char *bn = bitnamesofb(sa_policy_bit_names
				 , policy & ~(POLICY_SHUNT_MASK | POLICY_FAIL_MASK)
				 , pbitnamesbuf, sizeof(pbitnamesbuf));
    size_t len;
    lset_t shunt = (policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT;
    lset_t fail = (policy & POLICY_FAIL_MASK) >> POLICY_FAIL_SHIFT;

    if (bn != pbitnamesbuf)
	pbitnamesbuf[0] = '\0';
    len = strlen(pbitnamesbuf);
    if (shunt != 0)
    {
	snprintf(pbitnamesbuf + len, sizeof(pbitnamesbuf) - len, "+%s"
	    , policy_shunt_names[shunt]);
	len += strlen(pbitnamesbuf + len);
    }
    if (fail != 0)
    {
	snprintf(pbitnamesbuf + len, sizeof(pbitnamesbuf) - len, "+failure%s"
	    , policy_fail_names[fail]);
	len += strlen(pbitnamesbuf + len);
    }
    if (NEVER_NEGOTIATE(policy))
    {
	snprintf(pbitnamesbuf + len, sizeof(pbitnamesbuf) - len, "+NEVER_NEGOTIATE");
	len += strlen(pbitnamesbuf + len);
    }
    return pbitnamesbuf;
}

