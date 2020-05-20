/* IKEv2 REKEY Exchange
 *
 * Copyright (C) 2020 Andrew Cagney
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
 */

#include "defs.h"
#include "state.h"
#include "ikev2.h"
#include "ikev2_rekey.h"
#include "ikev2_message.h"
#include "ikev2_send.h"
#include "log.h"

static stf_status send_v2_rekey_ike_request(struct ike_sa *ike,
					     struct child_sa *unused_child UNUSED,
					     struct msg_digest *md)
{
	pexpect(md == NULL);
	log_state(RC_LOG, &ike->sa, "%s not implemented", __func__);
	return STF_INTERNAL_ERROR;
}

static stf_status send_v2_rekey_child_request(struct ike_sa *ike,
					       struct child_sa *child,
					       struct msg_digest *md)
{
	pexpect(md == NULL);
	log_state(RC_LOG, &ike->sa, "%s not implemented", __func__);
	log_state(RC_LOG, &child->sa, "%s not implemented", __func__);
	return STF_INTERNAL_ERROR;
}

/*
 * XXX: where to put this?
 */

static const struct state_v2_microcode v2_rekey_ike = {
	.story = "rekey IKE SA",
	.state = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_V2_ESTABLISHED_IKE_SA,
	.send = MESSAGE_REQUEST,
	.processor = send_v2_rekey_ike_request,
	.timeout_event =  EVENT_RETAIN,
};

static const struct state_v2_microcode v2_rekey_child = {
	.story = "rekey CHILD SA",
	.state = STATE_V2_ESTABLISHED_CHILD_SA,
	.next_state = STATE_V2_ESTABLISHED_CHILD_SA,
	.send = MESSAGE_REQUEST,
	.processor = send_v2_rekey_child_request,
	.timeout_event =  EVENT_RETAIN,
};

static const struct state_v2_microcode *transitions[SA_TYPE_ROOF] = {
	[IKE_SA] = &v2_rekey_ike,
	[IPSEC_SA] = &v2_rekey_child,
};

void initiate_v2_rekey(struct ike_sa *ike, struct state *st)
{
	const struct state_v2_microcode *transition = transitions[st->st_establishing_sa];
	if (st->st_state->kind != transition->state) {
		log_state(RC_LOG, st, "in state %s but need state %s to initiate rekey",
			  st->st_state->short_name,
			  finite_states[transition->state]->short_name);
		return;
	}
	v2_msgid_queue_initiator(ike, st, ISAKMP_v2_INFORMATIONAL,
				 transition, NULL);
}
