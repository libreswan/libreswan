/* IKEv2 DELETE Exchange
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
#include "ikev2_delete.h"
#include "ikev2_message.h"
#include "ikev2_send.h"
#include "log.h"

/*
 * Send an Informational Exchange announcing a deletion.
 *
 * CURRENTLY SUPPRESSED:
 * If we fail to send the deletion, we just go ahead with deleting the state.
 * The code in delete_state would break if we actually did this.
 *
 * Deleting an IKE SA is a bigger deal than deleting an IPsec SA.
 */

bool record_v2_delete(struct ike_sa *ike, struct state *st)
{
	/* make sure HDR is at start of a clean buffer */
	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	struct pbs_out packet = open_pbs_out("informational exchange delete request",
					     buf, sizeof(buf), st->st_logger);
	struct pbs_out rbody = open_v2_message(&packet, ike,
					       NULL /* request */,
					       ISAKMP_v2_INFORMATIONAL);
	if (!pbs_ok(&packet)) {
		return false;
	}

	v2SK_payload_t sk = open_v2SK_payload(st->st_logger, &rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return false;
	}

	{
		pb_stream del_pbs;
		struct ikev2_delete v2del_tmp;
		if (IS_CHILD_SA(st)) {
			v2del_tmp = (struct ikev2_delete) {
				.isad_protoid = PROTO_IPSEC_ESP,
				.isad_spisize = sizeof(ipsec_spi_t),
				.isad_nrspi = 1,
			};
		} else {
			v2del_tmp = (struct ikev2_delete) {
				.isad_protoid = PROTO_ISAKMP,
				.isad_spisize = 0,
				.isad_nrspi = 0,
			};
		}

		/* Emit delete payload header out */
		if (!out_struct(&v2del_tmp, &ikev2_delete_desc,
				&sk.pbs, &del_pbs))
			return false;

		/* Emit values of spi to be sent to the peer */
		if (IS_CHILD_SA(st)) {
			if (!out_raw((u_char *)&st->st_esp.our_spi,
				     sizeof(ipsec_spi_t), &del_pbs,
				     "local spis"))
				return false;
		}

		close_output_pbs(&del_pbs);
	}

	if (!close_v2SK_payload(&sk)) {
		return false;;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&packet);

	stf_status ret = encrypt_v2SK_payload(&sk);
	if (ret != STF_OK) {
		log_state(RC_LOG, st,"error encrypting notify message");
		return false;
	}

	record_v2_message(ike, &packet, "packet for ikev2 delete informational",
			  MESSAGE_REQUEST);
	return true;
}

static stf_status send_v2_delete_ike_request(struct ike_sa *ike,
					     struct child_sa *unused_child UNUSED,
					     struct msg_digest *md)
{
	pexpect(md == NULL);
	if (!record_v2_delete(ike, &ike->sa)) {
		return STF_INTERNAL_ERROR;
	}
	return STF_OK;
}

static stf_status send_v2_delete_child_request(struct ike_sa *ike,
					       struct child_sa *child,
					       struct msg_digest *md)
{
	pexpect(md == NULL);
	if (!record_v2_delete(ike, &child->sa)) {
		return STF_INTERNAL_ERROR;
	}
	return STF_OK;
}

/*
 * XXX: where to put this?
 */

static const struct state_v2_microcode v2_delete_ike = {
	.story = "delete IKE SA",
	.state = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_IKESA_DEL,
	.send = MESSAGE_REQUEST,
	.processor = send_v2_delete_ike_request,
	.timeout_event =  EVENT_RETAIN,
};

static const struct state_v2_microcode v2_delete_child = {
	.story = "delete CHILD SA",
	.state = STATE_V2_ESTABLISHED_CHILD_SA,
	.next_state = STATE_CHILDSA_DEL,
	.send = MESSAGE_REQUEST,
	.processor = send_v2_delete_child_request,
	.timeout_event =  EVENT_RETAIN,
};

static const struct state_v2_microcode *transitions[SA_TYPE_ROOF] = {
	[IKE_SA] = &v2_delete_ike,
	[IPSEC_SA] = &v2_delete_child,
};

void initiate_v2_delete(struct ike_sa *ike, struct state *st)
{
	const struct state_v2_microcode *transition = transitions[st->st_establishing_sa];
	if (st->st_state->kind != transition->state) {
		log_state(RC_LOG, st, "in state %s but need state %s to initiate delete",
			  st->st_state->short_name,
			  finite_states[transition->state]->short_name);
		return;
	}
	v2_msgid_queue_initiator(ike, st, ISAKMP_v2_INFORMATIONAL,
				 transition, NULL);
}
