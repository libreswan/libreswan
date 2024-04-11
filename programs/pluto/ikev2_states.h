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

#define S(KIND, ...) extern const struct finite_state state_v2_##KIND
S(IKE_SA_INIT_I0);
S(IKE_SA_INIT_I);
S(IKE_SA_INIT_R0);
S(IKE_SA_INIT_R);
S(IKE_SA_INIT_IR);
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
S(IKE_SA_DELETE);
S(CHILD_SA_DELETE);
#undef S

bool is_plausible_secured_v2_exchange(struct ike_sa *ike, struct msg_digest *md);

/* used by the IKE_SA_INIT code to find initial transitions only */
const struct v2_transition *find_v2_unsecured_transition(struct logger *logger,
							 const struct v2_transitions *transitions,
							 struct msg_digest *md);

const struct v2_transition *find_v2_secured_transition(struct ike_sa *ike,
						       struct msg_digest *md,
						       bool *secured_payload_failed);

extern const struct v2_exchange v2_IKE_AUTH_exchange;

extern const struct v2_exchange v2_INFORMATIONAL_liveness_exchange;
extern const struct v2_exchange v2_INFORMATIONAL_redirect_ike_exchange;
extern const struct v2_exchange v2_INFORMATIONAL_delete_ike_exchange;
extern const struct v2_exchange v2_INFORMATIONAL_delete_child_exchange;
extern const struct v2_exchange v2_INFORMATIONAL_mobike_exchange;

void init_ikev2_states(struct logger *logger);

#endif
