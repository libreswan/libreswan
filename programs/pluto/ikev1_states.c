/* IKEv2 state machine, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Hiren Joshi <joshihirenn@gmail.com>
 * Copyright (C) 2009 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2019-2019 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"
#include "state.h"
#include "ikev1_states.h"

#define S(KIND, STORY, CAT) \
	struct finite_state state_v1_##KIND = {				\
		.kind = STATE_##KIND,					\
		.name = "STATE_"#KIND,					\
		/* Not using #KIND + 6 because of clang's -Wstring-plus-int */ \
		.short_name = #KIND,					\
		.story = STORY,						\
		.category = CAT,					\
		.ike_version = IKEv1,					\
	}

/*
 * Count I1 as half-open too because with ondemand, a
 * plaintext packet (that is spoofed) will trigger an outgoing
 * ISAKMP (IKE) SA.
 */

S(AGGR_R0, "expecting Aggressive Mode request", CAT_HALF_OPEN_IKE_SA);
S(AGGR_I1, "sent Aggressive Mode request", CAT_HALF_OPEN_IKE_SA);
S(MAIN_R0, "expecting Main Mode request", CAT_HALF_OPEN_IKE_SA);
S(MAIN_I1, "sent Main Mode request", CAT_HALF_OPEN_IKE_SA);

/*
 * All IKEv1 MAIN modes except the first (half-open) and last
 * ones are not authenticated.
 *
 * These exchanges don't have any userfriendly name, like we used
 * elsewhere (request, response, confirmation)
 */

S(MAIN_R1, "sent Main Mode R1", CAT_OPEN_IKE_SA);
S(MAIN_R2, "sent Main Mode R2", CAT_OPEN_IKE_SA);
S(MAIN_I2, "sent Main Mode I2", CAT_OPEN_IKE_SA);
S(MAIN_I3, "sent Main Mode I3", CAT_OPEN_IKE_SA);
S(AGGR_R1, "sent Aggressive Mode response, expecting confirmation", CAT_OPEN_IKE_SA);

/*
 * IKEv1 established states.
 *
 * XAUTH, seems to a second level of authentication performed
 * after the connection is established and authenticated.
 */

S(MAIN_I4, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA);
S(MAIN_R3, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA);
S(AGGR_I2, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA);
S(AGGR_R2, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA);
S(XAUTH_I0, "XAUTH client - possibly awaiting CFG_request", CAT_ESTABLISHED_IKE_SA);
S(XAUTH_I1, "XAUTH client - possibly awaiting CFG_set", CAT_ESTABLISHED_IKE_SA);
S(XAUTH_R0, "XAUTH responder - optional CFG exchange", CAT_ESTABLISHED_IKE_SA);
S(XAUTH_R1, "XAUTH status sent, expecting Ack", CAT_ESTABLISHED_IKE_SA);

/*
 * IKEv1: QUICK is for child connections children.
 *        Initiator                        Responder
 *       -----------                      -----------
 *        HDR*, HASH(1), SA, Ni
 *          [, KE ] [, IDci, IDcr ] -->
 *                                  <--    HDR*, HASH(2), SA, Nr
 *                                               [, KE ] [, IDci, IDcr ]
 *        HDR*, HASH(3)             -->
 */

/* this is not established yet */
S(QUICK_I1, "sent Quick Mode request", CAT_ESTABLISHED_CHILD_SA);
S(QUICK_I2, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA);
/* shouldn't we cat_ignore this? */
S(QUICK_R0, "expecting Quick Mode request", CAT_ESTABLISHED_CHILD_SA);
S(QUICK_R1, "sent Quick Mode reply, inbound IPsec SA installed, expecting confirmation", CAT_ESTABLISHED_CHILD_SA);
S(QUICK_R2, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA);

/*
 * IKEv1: Post established negotiation.
 */

S(MODE_CFG_I1, "sent ModeCfg request", CAT_ESTABLISHED_IKE_SA);
S(MODE_CFG_R1, "sent ModeCfg reply, expecting Ack", CAT_ESTABLISHED_IKE_SA);
S(MODE_CFG_R2, "received ModeCfg Ack", CAT_ESTABLISHED_IKE_SA);

S(INFO, "received unencrypted Informational Exchange message", CAT_INFORMATIONAL);
S(INFO_PROTECTED, "received encrypted Informational Exchange message", CAT_INFORMATIONAL);
S(MODE_CFG_R0, "received ModeCfg request, reply sent", CAT_INFORMATIONAL);

#undef S

struct finite_state *v1_states[] = {
#define S(KIND) [STATE_##KIND - STATE_IKEv1_FLOOR] = &state_v1_##KIND
	S(AGGR_R0),
	S(AGGR_I1),
	S(MAIN_R0),
	S(MAIN_I1),
	S(MAIN_R1),
	S(MAIN_R2),
	S(MAIN_I2),
	S(MAIN_I3),
	S(AGGR_R1),
	S(MAIN_I4),
	S(MAIN_R3),
	S(AGGR_I2),
	S(AGGR_R2),
	S(XAUTH_I0),
	S(XAUTH_I1),
	S(XAUTH_R0),
	S(XAUTH_R1),
	S(QUICK_I1),
	S(QUICK_I2),
	S(QUICK_R0),
	S(QUICK_R1),
	S(QUICK_R2),
	S(MODE_CFG_I1),
	S(MODE_CFG_R1),
	S(MODE_CFG_R2),
	S(INFO),
	S(INFO_PROTECTED),
	S(MODE_CFG_R0),
#undef S
};
