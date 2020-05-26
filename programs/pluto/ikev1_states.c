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

struct finite_state v1_states[] = {

#define S(KIND, STORY, CAT) [KIND - STATE_IKEv1_FLOOR] = {	\
		.kind = KIND,					\
		.name = #KIND,					\
		.short_name = #KIND + 6/*STATE_*/,		\
		.story = STORY,					\
		.category = CAT,				\
	}

	/*
	 * Count I1 as half-open too because with ondemand, a
	 * plaintext packet (that is spoofed) will trigger an outgoing
	 * IKE SA.
	 */

	S(STATE_AGGR_R0, "expecting AI1", CAT_HALF_OPEN_IKE_SA),
	S(STATE_AGGR_I1, "sent AI1, expecting AR1", CAT_HALF_OPEN_IKE_SA),
	S(STATE_MAIN_R0, "expecting MI1", CAT_HALF_OPEN_IKE_SA),
	S(STATE_MAIN_I1, "sent MI1, expecting MR1", CAT_HALF_OPEN_IKE_SA),

	/*
	 * All IKEv1 MAIN modes except the first (half-open) and last
	 * ones are not authenticated.
	 */

	S(STATE_MAIN_R1, "sent MR1, expecting MI2", CAT_OPEN_IKE_SA),
	S(STATE_MAIN_R2, "sent MR2, expecting MI3", CAT_OPEN_IKE_SA),
	S(STATE_MAIN_I2, "sent MI2, expecting MR2", CAT_OPEN_IKE_SA),
	S(STATE_MAIN_I3, "sent MI3, expecting MR3", CAT_OPEN_IKE_SA),
	S(STATE_AGGR_R1, "sent AR1, expecting AI2", CAT_OPEN_IKE_SA),

	/*
	 * IKEv1 established states.
	 *
	 * XAUTH, seems to a second level of authentication performed
	 * after the connection is established and authenticated.
	 */

	S(STATE_MAIN_I4, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA),
	S(STATE_MAIN_R3, "sent MR3, ISAKMP SA established", CAT_ESTABLISHED_IKE_SA),
	S(STATE_AGGR_I2, "sent AI2, ISAKMP SA established", CAT_ESTABLISHED_IKE_SA),
	S(STATE_AGGR_R2, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA),
	S(STATE_XAUTH_I0, "XAUTH client - possibly awaiting CFG_request", CAT_ESTABLISHED_IKE_SA),
	S(STATE_XAUTH_I1, "XAUTH client - possibly awaiting CFG_set", CAT_ESTABLISHED_IKE_SA),
	S(STATE_XAUTH_R0, "XAUTH responder - optional CFG exchange", CAT_ESTABLISHED_IKE_SA),
	S(STATE_XAUTH_R1, "XAUTH status sent, expecting Ack", CAT_ESTABLISHED_IKE_SA),

	/*
	 * IKEv1: QUICK is for child connections children.  Probably
	 * won't occur as a parent?
	 */

	/* this is not established yet? */
	S(STATE_QUICK_I1, "sent QI1, expecting QR1", CAT_ESTABLISHED_CHILD_SA),
	S(STATE_QUICK_I2, "sent QI2, IPsec SA established", CAT_ESTABLISHED_CHILD_SA),
	/* shouldn't we cat_ignore this? */
	S(STATE_QUICK_R0, "expecting QI1", CAT_ESTABLISHED_CHILD_SA),
	S(STATE_QUICK_R1, "sent QR1, inbound IPsec SA installed, expecting QI2", CAT_ESTABLISHED_CHILD_SA),
	S(STATE_QUICK_R2, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA),

	/*
	 * IKEv1: Post established negotiation.
	 */

	S(STATE_MODE_CFG_I1, "ModeCfg initiator - awaiting CFG_reply", CAT_ESTABLISHED_IKE_SA),
	S(STATE_MODE_CFG_R1, "ModeCfg Set sent, expecting Ack", CAT_ESTABLISHED_IKE_SA),
	S(STATE_MODE_CFG_R2, "ModeCfg R2", CAT_ESTABLISHED_IKE_SA),

	S(STATE_INFO, "got Informational Message in clear", CAT_INFORMATIONAL),
	S(STATE_INFO_PROTECTED, "got encrypted Informational Message", CAT_INFORMATIONAL),
	S(STATE_MODE_CFG_R0, "ModeCfg Reply sent", CAT_INFORMATIONAL),

#undef S
};
