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

#ifndef IKEV2_STATE_H
#define IKEV2_STATE_H

struct v2_transition;
struct v2_transitions;
struct msg_digest;
struct logger;

#define S(KIND, ...) extern const struct finite_state state_v2_##KIND
S(UNSECURED_R);
/* includes larval states */
S(IKE_SA_INIT_I0);
S(IKE_SA_INIT_I);
S(IKE_SA_INIT_R);
S(IKE_SA_INIT_IR);
/* includes larval states */
S(IKE_SESSION_RESUME_I0);
S(IKE_SESSION_RESUME_I);
S(IKE_SESSION_RESUME_R0);
S(IKE_SESSION_RESUME_R);
S(IKE_SESSION_RESUME_IR);
/* come after above */
S(IKE_INTERMEDIATE_I);
S(IKE_INTERMEDIATE_R);
S(IKE_INTERMEDIATE_IR);
S(IKE_AUTH_EAP_R);
S(IKE_AUTH_I);
S(NEW_CHILD_I0);
S(NEW_CHILD_R0);
S(NEW_CHILD_I1);
S(REKEY_CHILD_I0);
S(REKEY_CHILD_I1);
S(REKEY_CHILD_R0);
S(REKEY_IKE_I0);
S(REKEY_IKE_I1);
S(REKEY_IKE_R0);
S(ESTABLISHED_IKE_SA);
S(ESTABLISHED_CHILD_SA);
S(ZOMBIE);
#undef S

bool is_plausible_secured_v2_exchange(struct ike_sa *ike, struct msg_digest *md);

/*
 * Used by the unsecured IKE_SA_INIT code to find initial transition.
 *
 * The request lookup happens before the IKE SA has been created, so
 * that a failure avoids that work.  Hence the lack of an IKE
 * parameter.
 */

diag_t find_v2_unsecured_request_transition(struct logger *logger,
					    const struct finite_state *state,
					    const struct msg_digest *md,
					    const struct v2_transition **transition);

diag_t find_v2_unsecured_response_transition(struct ike_sa *ike,
					     const struct msg_digest *md,
					     const struct v2_transition **transition);

/*
 * Used to process secured exchanges.
 */

const struct v2_transition *find_v2_secured_transition(struct ike_sa *ike,
						       const struct msg_digest *md,
						       bool *secured_payload_failed);

void init_ikev2_states(struct logger *logger);

#endif
