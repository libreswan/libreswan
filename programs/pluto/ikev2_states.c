/* IKEv2 state machine, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney
 * Copyright (C) 2016-2018 Antony Antony <appu@phenome.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
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
#include "ikev2_states.h"

struct finite_state v2_states[] = {

#define S(KIND, STORY, CAT) [KIND - STATE_IKEv2_FLOOR] = {	\
		.kind = KIND,					\
		.name = #KIND,					\
		.short_name = #KIND + 6/*STATE_*/,		\
		.story = STORY,					\
		.category = CAT,				\
	}

	/*
	 * IKEv2 IKE SA initiator, while the the SA_INIT packet is
	 * being constructed, are in state.  Only once the packet has
	 * been sent out does it transition to STATE_PARENT_I1 and
	 * start being counted as half-open.
	 */

	S(STATE_PARENT_I0, "waiting for KE to finish", CAT_IGNORE),

	/*
	 * Count I1 as half-open too because with ondemand, a
	 * plaintext packet (that is spoofed) will trigger an outgoing
	 * IKE SA.
	 */

	S(STATE_PARENT_I1, "sent v2I1, expected v2R1", CAT_HALF_OPEN_IKE_SA),
	S(STATE_PARENT_R0, "processing SA_INIT request", CAT_HALF_OPEN_IKE_SA),
	S(STATE_PARENT_R1, "received v2I1, sent v2R1", CAT_HALF_OPEN_IKE_SA),

	/*
	 * All IKEv1 MAIN modes except the first (half-open) and last
	 * ones are not authenticated.
	 */

	S(STATE_PARENT_I2, "sent v2I2, expected v2R2", CAT_OPEN_IKE_SA),

	/*
	 * IKEv1 established states.
	 *
	 * XAUTH, seems to a second level of authentication performed
	 * after the connection is established and authenticated.
	 */

	/* isn't this an ipsec state */
	S(STATE_V2_CREATE_I0, "STATE_V2_CREATE_I0", CAT_ESTABLISHED_IKE_SA),
	 /* isn't this an ipsec state */
	S(STATE_V2_CREATE_I, "sent IPsec Child req wait response", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_IKE_I0, "STATE_V2_REKEY_IKE_I0", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_IKE_I, "STATE_V2_REKEY_IKE_I", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_CHILD_I0, "STATE_V2_REKEY_CHILD_I0", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_CHILD_I, "STATE_V2_REKEY_CHILD_I", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_CREATE_R, "STATE_V2_CREATE_R", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_IKE_R, "STATE_V2_REKEY_IKE_R", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_CHILD_R, "STATE_V2_REKEY_CHILD_R", CAT_ESTABLISHED_IKE_SA),

	/*
	 * IKEv2 established states.
	 */

	S(STATE_PARENT_I3, "PARENT SA established", CAT_ESTABLISHED_IKE_SA),
	S(STATE_PARENT_R2, "received v2I2, PARENT SA established", CAT_ESTABLISHED_IKE_SA),

	S(STATE_V2_IPSEC_I, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA),
	S(STATE_V2_IPSEC_R, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA),

	/* ??? better story needed for these */
	S(STATE_IKESA_DEL, "STATE_IKESA_DEL", CAT_ESTABLISHED_IKE_SA),
	S(STATE_CHILDSA_DEL, "STATE_CHILDSA_DEL", CAT_INFORMATIONAL),
#undef S
};
