/* IKEv2 state machine, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#ifndef IKEV1_STATE_H
#define IKEV1_STATE_H

#include "ikev1.h"		/* for ikev1_state_transition_fn; */
#include "ikev1_hash.h"		/* for v1_hash_type; */

/* State Microcode Flags, in several groups */

/* Oakley Auth values: to which auth values does this entry apply?
 * Most entries will use SMF_ALL_AUTH because they apply to all.
 * Note: SMF_ALL_AUTH matches 0 for those circumstances when no auth
 * has been set.
 *
 * The IKEv1 state machine then uses the auth type (SMF_*_AUTH flags)
 * to select the exact state transition.  For states where auth
 * (SMF_*_AUTH flags) don't apply (.e.g, child states)
 * flags|=SMF_ALL_AUTH so the first transition always matches.
 *
 * Once a transition is selected, the containing payloads are checked
 * against what is allowed.  For instance, in STATE_MAIN_R2 ->
 * STATE_MAIN_R3 with SMF_DS_AUTH requires P(SIG).
 *
 * In IKEv2, it is the message header and payload types that select
 * the state.  As for how the IKEv1 'from state' is selected, look for
 * a big nasty magic switch.
 *
 * XXX: the state transition table is littered with STATE_UNDEFINED /
 * SMF_ALL_AUTH / unexpected() entries.  These are to catch things
 * like unimplemented auth cases, and unexpected packets.  For the
 * latter, they seem to be place holders so that the table contains at
 * least one entry for the state.
 *
 * XXX: Some of the SMF flags specify attributes of the current state
 * (e.g., SMF_RETRANSMIT_ON_DUPLICATE), some apply to the state
 * transition (e.g., SMF_REPLY), and some can be interpreted as either
 * (.e.g., SMF_INPUT_ENCRYPTED).
 */
#define SMF_ALL_AUTH    LRANGE(0, OAKLEY_AUTH_ROOF - 1)
#define SMF_PSK_AUTH    LELEM(OAKLEY_PRESHARED_KEY)
#define SMF_DS_AUTH     (LELEM(OAKLEY_DSS_SIG) | LELEM(OAKLEY_RSA_SIG))
#define SMF_PKE_AUTH    LELEM(OAKLEY_RSA_ENC)
#define SMF_RPKE_AUTH   LELEM(OAKLEY_RSA_REVISED_MODE)

/* misc flags */
#define SMF_INITIATOR   LELEM(OAKLEY_AUTH_ROOF + 0)
#define SMF_FIRST_ENCRYPTED_INPUT       LELEM(OAKLEY_AUTH_ROOF + 1)
#define SMF_INPUT_ENCRYPTED     LELEM(OAKLEY_AUTH_ROOF + 2)
#define SMF_OUTPUT_ENCRYPTED    LELEM(OAKLEY_AUTH_ROOF + 3)
#define SMF_RETRANSMIT_ON_DUPLICATE     LELEM(OAKLEY_AUTH_ROOF + 4)

#define SMF_ENCRYPTED (SMF_INPUT_ENCRYPTED | SMF_OUTPUT_ENCRYPTED)

/* this state generates a reply message */
#define SMF_REPLY   LELEM(OAKLEY_AUTH_ROOF + 5)

/* this state completes P1, so any pending P2 negotiations should start */
#define SMF_RELEASE_PENDING_P2  LELEM(OAKLEY_AUTH_ROOF + 6)

/* if we have canonicalized the authentication from XAUTH mode */
#define SMF_XAUTH_AUTH  LELEM(OAKLEY_AUTH_ROOF + 7)

/* end of flags */

/*
 * state_v1_microcode is a tuple of information parameterizing certain
 * centralized processing of a packet.  For example, it roughly
 * specifies what payloads are expected in this message.  The
 * microcode is selected primarily based on the state.  In Phase 1,
 * the payload structure often depends on the authentication
 * technique, so that too plays a part in selecting the
 * state_v1_microcode to use.
 */

#define v1P(N) LELEM(ISAKMP_NEXT_##N)

struct state_v1_microcode {
	enum state_kind state, next_state;
	lset_t flags;
	lset_t req_payloads;    /* required payloads (allows just one) */
	lset_t opt_payloads;    /* optional payloads (any number) */
	enum event_type timeout_event;
	ikev1_state_transition_fn *processor;
	const char *message;
	enum v1_hash_type hash_type;
};

extern struct finite_state *v1_states[STATE_IKEv1_ROOF - STATE_IKEv1_FLOOR];

void init_ikev1_states(struct logger *logger);

#endif
