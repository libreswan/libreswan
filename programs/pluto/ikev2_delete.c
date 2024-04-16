/* IKEv2 DELETE Exchange, for Libreswan
 *
 * Copyright (C) 2020-2024 Andrew Cagney
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
#include "ikev2_states.h"
#include "log.h"
#include "demux.h"
#include "connections.h"
#include "ikev2_informational.h"

static bool process_v2DELETE_requests(bool *del_ike, struct ike_sa *ike,
				      struct msg_digest *md, struct pbs_out *pbs);
static emit_v2_INFORMATIONAL_request_payload_fn emit_v2DELETE;
static ikev2_state_transition_fn initiate_v2_INFORMATIONAL_v2DELETE_request;
static ikev2_state_transition_fn process_v2_INFORMATIONAL_v2DELETE_request;
static ikev2_state_transition_fn process_v2_INFORMATIONAL_v2DELETE_response;

bool emit_v2DELETE(struct ike_sa *ike, struct child_sa *child, struct pbs_out *pbs)
{
	enum ikev2_sec_proto_id protoid =
		(child == NULL ? IKEv2_SEC_PROTO_IKE :
		 child->sa.st_esp.protocol == &ip_protocol_esp ? IKEv2_SEC_PROTO_ESP :
		 child->sa.st_ah.protocol == &ip_protocol_ah ? IKEv2_SEC_PROTO_AH :
		 IKEv2_SEC_PROTO_NONE);
	if (PBAD(ike->sa.logger, protoid == IKEv2_SEC_PROTO_NONE)) {
		return false;
	}

	if (impair.v2_delete_protoid.enabled) {
		enum_buf ebo, ebn;
		enum ikev2_sec_proto_id new_protoid = impair.v2_delete_protoid.value;
		llog(RC_LOG, ike->sa.logger,
		     "IMPAIR: changing Delete payload Protocol ID from %s to %s (%u)",
		     str_enum_short(&ikev2_delete_protocol_id_names, protoid, &ebo),
		     str_enum_short(&ikev2_delete_protocol_id_names, new_protoid, &ebn),
		     protoid);
		protoid = new_protoid;
	}

	struct ikev2_delete v2del = {
		.isad_protoid = protoid,
		.isad_spisize = (child != NULL ? sizeof(ipsec_spi_t) : 0),
		.isad_nrspi = (child != NULL ? 1 : 0),
	};

	/* Emit delete payload header out */
	struct pbs_out spi_pbs;
	if (!pbs_out_struct(pbs, &ikev2_delete_desc,
			    &v2del, sizeof(v2del), &spi_pbs)) {
		return false;
	}

	if (child != NULL) {
		/* Emit values of spi to be sent to the peer */
		if (!pbs_out_thing(&spi_pbs, child->sa.st_esp.inbound.spi, "local spis")) {
			/* already logged */
			return false;
		}
	}

	close_output_pbs(&spi_pbs);

	return true;
}

stf_status initiate_v2_INFORMATIONAL_v2DELETE_request(struct ike_sa *ike,
						      struct child_sa *child,
						      struct msg_digest *null_md)
{
	PEXPECT(ike->sa.logger, null_md == NULL);

	if (!record_v2_INFORMATIONAL_request("delete IKE SA",
					     ike->sa.logger, ike, child/*possibly-null*/,
					     emit_v2DELETE)) {
		/* already logged */
		return STF_INTERNAL_ERROR;
	}

	if (child == NULL) {
		/*
		 * Record the IKE's SO so that the response code knows
		 * to expect an empty delete.
		 */
		ike->sa.st_v2_msgid_windows.initiator.dead_sa = ike->sa.st_serialno;
		return STF_OK;
	}

	/*
	 * XXX: just assume an SA that isn't established is
	 * larval.
	 *
	 * Would be nice to have something indicating larval,
	 * established, zombie.
	 *
	 * Should use .llog_success, but that code doesn't
	 * know which Child SA the exchange was for.  Hence,
	 * pretend that it was sent when it hasn't (but will
	 * real soon, promise!)
	 */
	ike->sa.st_v2_msgid_windows.initiator.dead_sa = child->sa.st_serialno;
	bool established = IS_CHILD_SA_ESTABLISHED(&child->sa);
	if (!established) {
		/*
		 * Normally the responder would include it's
		 * outgoing SA's SPI, and this end would use
		 * that to find / delete the child.  Here,
		 * however, the SA isn't established so we've
		 * no clue as to what the responder will send
		 * back.  If anything.
		 *
		 * Hence signal the Child SA that it should
		 * delete itself.
		 */
		event_force(EVENT_v2_DISCARD, &child->sa);
	}

	return STF_OK;
}

static stf_status process_v2_INFORMATIONAL_v2DELETE_request(struct ike_sa *ike,
							    struct child_sa *null_child,
							    struct msg_digest *md)
{
	dbg("an informational request needing a response");
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	pexpect(null_child == NULL);

	/*
	 * Response packet preparation: DELETE
	 *
	 * There can be at most one Delete Payload for an IKE SA.  It
	 * means that this very SA is to be deleted.
	 *
	 * For each non-IKE Delete Payload we receive, we respond with
	 * a corresponding Delete Payload.  Note that that means we
	 * will have an empty response if no Delete Payloads came in
	 * or if the only Delete Payload is for an IKE SA.
	 */

	struct v2_message response;
	if (!open_v2_message("information exchange reply packet",
			     ike, ike->sa.logger,
			     md/*response*/, ISAKMP_v2_INFORMATIONAL,
			     reply_buffer, sizeof(reply_buffer), &response,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/* HDR out */

	bool del_ike = false;
	if (!process_v2DELETE_requests(&del_ike, ike, md, response.pbs)) {
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_INVALID_SYNTAX, NULL, ENCRYPTED_PAYLOAD);
		/*
		 * STF_FATAL will send the recorded message
		 * and then kill the IKE SA.  Should it
		 * instead zombify the IKE SA so that
		 * retransmits get a response?
		 */
		return STF_FATAL;
	}

	/*
	 * We've now build up the content (if any) of the Response:
	 *
	 * - if an ISAKMP SA is mentioned in input message, we are
	 *   sending an empty Response, as per standard.
	 *
	 * - for IPsec SA mentioned, we are sending its mate.
	 *
	 * Close up the packet and send it.
	 */

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * ... now we can delete the IKE SA if we want to.  The
	 * response is hopefully empty.
	 */
	if (del_ike) {
		/*
		 * Complete the transition; but then wipe us out.
		 */
		return STF_OK_RESPONDER_DELETE_IKE;
	}

	return STF_OK;
}

static void llog_v2_success_v2_INFORMATIONAL_v2DELETE_request(struct ike_sa *ike)
{
	/*
	 * XXX: should this, when there are children, also mention
	 * that they are being deleted?
	 */
	so_serial_t dead_sa = ike->sa.st_v2_msgid_windows.initiator.dead_sa;
	if (dead_sa == ike->sa.st_serialno) {
		llog(RC_LOG, ike->sa.logger, "sent INFORMATIONAL request to delete IKE SA");
		return;
	}

	struct child_sa *child = child_sa_by_serialno(dead_sa);
	if (PBAD(ike->sa.logger, child == NULL)) {
		return;
	}
	llog(RC_LOG, child->sa.logger,
	     "sent INFORMATIONAL request to delete %s Child SA using IKE SA "PRI_SO,
	     (IS_CHILD_SA_ESTABLISHED(&child->sa) ? "established" : "larval"),
	     pri_so(ike->sa.st_serialno));
}

void submit_v2_delete_exchange(struct ike_sa *ike, struct child_sa *child)
{
	const struct v2_exchange *exchange = &v2_INFORMATIONAL_v2DELETE_exchange;
	pexpect(exchange->initiate->exchange == ISAKMP_v2_INFORMATIONAL);
	if (child == NULL) {
		/*
		 * IKE SA is no longer viable - reviving Child SA's
		 * can't use it to initiate.
		 */
		ike->sa.st_viable_parent = false; /* just to be sure */
	}
	v2_msgid_queue_exchange(ike, child, exchange);
}

bool process_v2DELETE_requests(bool *del_ike, struct ike_sa *ike, struct msg_digest *md,
			       struct pbs_out *pbs)
{
	/*
	 * Pass 1 over Delete Payloads:
	 *
	 * - Count number of IPsec SA Delete Payloads
	 * - notice any IKE SA Delete Payload
	 * - sanity checking
	 */
	unsigned ndp = 0;		/* nr child deletes */

	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2D];
	     p != NULL; p = p->next) {
		struct ikev2_delete *v2del = &p->payload.v2delete;

		switch (v2del->isad_protoid) {
		case IKEv2_SEC_PROTO_IKE:
			if (*del_ike) {
				llog_sa(RC_LOG, ike,
					"Error: INFORMATIONAL Exchange with more than one Delete Payload for the IKE SA");
				return false;
			}

			if (v2del->isad_nrspi != 0 ||
			    v2del->isad_spisize != 0) {
				llog_sa(RC_LOG, ike,
					"IKE SA Delete has non-zero SPI size or number of SPIs");
				return false;
			}

			*del_ike = true;
			break;

		case IKEv2_SEC_PROTO_AH:
		case IKEv2_SEC_PROTO_ESP:
			if (v2del->isad_spisize != sizeof(ipsec_spi_t)) {
				llog_sa(RC_LOG, ike,
					"Child SA Delete Notification has invalid SPI size %u",
					v2del->isad_spisize);
				return false;
			}

			if (v2del->isad_nrspi * v2del->isad_spisize != pbs_left(&p->pbs)) {
				llog_sa(RC_LOG, ike,
					"Child SA Delete Notification payload size is %zu but %u is required",
					pbs_left(&p->pbs),
					v2del->isad_nrspi * v2del->isad_spisize);
				return false;
			}

			ndp++;
			break;

		default:
			llog_sa(RC_LOG, ike,
				"Ignored bogus delete protoid '%d'", v2del->isad_protoid);
		}
	}

	if (*del_ike && ndp != 0) {
		llog_sa(RC_LOG, ike,
			"Odd: INFORMATIONAL Exchange deletes IKE SA and yet also deletes some IPsec SA");
	}

	/*
	 * IKE delete gets an empty response.
	 */
	if (*del_ike) {
		return true;
	}

	/*
	 * Pass 2 over the Delete Payloads:
	 * Actual IPsec SA deletion.
	 * If responding, build response Delete Payloads.
	 * If there is no payload, this loop is a no-op.
	 */

	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2D];
	     p != NULL; p = p->next) {
		struct ikev2_delete *v2del = &p->payload.v2delete;

		switch (v2del->isad_protoid) {
		case IKEv2_SEC_PROTO_IKE:
			llog_passert(ike->sa.logger, HERE, "unexpected IKE delete");

		case IKEv2_SEC_PROTO_AH: /* Child SAs */
		case IKEv2_SEC_PROTO_ESP: /* Child SAs */
		{
			/*
			 * Again two passes.
			 *
			 * First accumulate the SPIs that actually
			 * need to be deleted (deleting the
			 * corresponding states), and second build a
			 * payload of just those SPIs.
			 */
			ipsec_spi_t spi_buf[128];
			uint16_t j = 0;	/* number of SPIs in spi_buf */

			for (unsigned i = 0; i < v2del->isad_nrspi; i++) {

				/*
				 * From 3.11.  Delete Payload.
				 *
				 * [the delete payload will] contain
				 * the IPsec protocol ID of that
				 * protocol (2 for AH, 3 for ESP), and
				 * the SPI is the SPI the sending
				 * endpoint would expect in inbound
				 * ESP or AH packets.
				 *
				 * From our POV, the outbound SPI
				 * (i.e., inbound to the peer).
				 */
				ipsec_spi_t outbound_spi;
				diag_t d = pbs_in_thing( &p->pbs, outbound_spi, "SPI");
				if (d != NULL) {
					llog_diag(RC_LOG, ike->sa.logger, &d, "%s", "");
					return false;
				}

				esb_buf b;
				ldbg_sa(ike, "delete %s Child SA with outbound SPI "PRI_IPSEC_SPI,
					enum_show(&ikev2_delete_protocol_id_names,
						  v2del->isad_protoid, &b),
					pri_ipsec_spi(outbound_spi));

				struct child_sa *child = find_v2_child_sa_by_outbound_spi(ike,
											  v2del->isad_protoid,
											  outbound_spi);
				if (child == NULL) {
					esb_buf b;
					llog_sa(RC_LOG, ike,
						"received delete request for %s Child SA with outbound SPI "PRI_IPSEC_SPI" but corresponding state not found",
						enum_show(&ikev2_delete_protocol_id_names,
							  v2del->isad_protoid, &b),
						pri_ipsec_spi(outbound_spi));
					continue;
				}

				/*
				 * Reverse the SPI.
				 *
				 * The peer expects to be sent the SPI
				 * that they are putting on the front
				 * of packets inbound to us.
				 */
				struct ipsec_proto_info *pr =
					(v2del->isad_protoid == IKEv2_SEC_PROTO_AH
					 ? &child->sa.st_ah
					 : &child->sa.st_esp);
				ipsec_spi_t inbound_spi = pr->inbound.spi;

				ldbg_sa(ike, "%s Child SA with outbound SPI "PRI_IPSEC_SPI" has inbound SPI "PRI_IPSEC_SPI,
					enum_show(&ikev2_delete_protocol_id_names, v2del->isad_protoid, &b),
					pri_ipsec_spi(outbound_spi),
					pri_ipsec_spi(inbound_spi));

				passert(ike->sa.st_serialno == child->sa.st_clonedfrom);
				if (j < elemsof(spi_buf)) {
					spi_buf[j] = inbound_spi;
					j++;
				} else {
					llog_sa(RC_LOG, ike,
						"too many SPIs in Delete Notification payload; ignoring outbound SPI "PRI_IPSEC_SPI,
						pri_ipsec_spi(outbound_spi));
				}
				connection_delete_child(&child, HERE);

			} /* for each spi */

			/* build output Delete Payload */
			struct ikev2_delete v2del_tmp = {
				.isad_protoid = v2del->isad_protoid,
				.isad_spisize = v2del->isad_spisize,
				.isad_nrspi = j,
			};

			/* Emit delete payload header and SPI values */
			struct pbs_out del_pbs;	/* output stream */
			if (!out_struct(&v2del_tmp,
					&ikev2_delete_desc,
					pbs,
					&del_pbs))
				return false;
			if (!pbs_out_raw(&del_pbs, spi_buf,
					 j * sizeof(spi_buf[0]), "local SPIs")) {
				/* already logged */
				return false;
			}

			close_output_pbs(&del_pbs);
			break;
		}

		default:
			/* ignore unrecognized protocol */
			break;
		}
	}

	return true;
}

static stf_status process_v2_INFORMATIONAL_v2DELETE_response(struct ike_sa *ike,
							     struct child_sa *null_child,
							     struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, null_child == NULL);
	PEXPECT(ike->sa.logger, md != NULL);

	so_serial_t dead_sa = ike->sa.st_v2_msgid_windows.initiator.dead_sa;
	if (PBAD(ike->sa.logger, dead_sa == SOS_NOBODY)) {
		return STF_FATAL;
	}

	if (dead_sa == ike->sa.st_serialno) {
		/*
		 * A response to our IKE SA delete request.  Any
		 * Delete payloads are bogus (message should be empty)
		 * and can be ignored.
		 */
		if (md->chain[ISAKMP_NEXT_v2D] != NULL) {
			ldbg(ike->sa.logger, "deleting IKE SA, ignoring delete payloads in response");
		}
		return STF_OK_INITIATOR_DELETE_IKE;
	}

	struct child_sa *dead_child = child_sa_by_serialno(dead_sa);
	if (dead_child == NULL) {
		/* case of crossing deletes? */
		llog(RC_LOG, ike->sa.logger, "Child SA "PRI_SO" no longer exists, ignoring delete response", pri_so(dead_sa));
		return STF_OK;
	}

	if (md->chain[ISAKMP_NEXT_v2D] == NULL) {
		/*
		 * A Child SA delete response always contains a DELETE
		 * payload, it's just that sometimes it is empty.
		 */
		llog(RC_LOG, ike->sa.logger, "delete response missing Delete Payload for Child SA "PRI_SO,
		     pri_so(dead_sa));
		return STF_FATAL;
	}

	/*
	 * Don't even bother looking at the v2Delete payloads.
	 */
	on_delete(&dead_child->sa, skip_send_delete);
	/*
	 * IKE SA is a parent of dead Child SA.  Could a DELETE and
	 * rekey exchange cross causing these pexpect()s to fail?
	 */
	PEXPECT(ike->sa.logger, &ike->sa != &dead_child->sa);
	PEXPECT(ike->sa.logger, ike->sa.st_serialno == dead_child->sa.st_clonedfrom);
	connection_delete_child(&dead_child, HERE);

	return STF_OK;
}

/*
 * This code forces a delete notification for an IKE SA
 *
 * For instance, when a connection is deleted, a delete notification
 * is forced overriding the message window state.
 *
 * XXX: record'n'send call shouldn't be needed.
 *
 * Instead of forcing a delete, this code should use normal state
 * transitions and exchanges to delete things.
 *
 * XXX: record'n'send call can violate RFC
 *
 * Since nothing is waiting for the response, there's nothing to
 * ensure that this send was received before the next is sent.
 */
void record_n_send_n_log_v2_delete(struct ike_sa *ike, where_t where)
{
	dbg_v2_msgid(ike, "hacking around record'n'send'n'log delete for "PRI_SO" "PRI_WHERE,
		     pri_so(ike->sa.st_serialno), pri_where(where));

	llog_sa_delete_n_send(ike, &ike->sa);

	if (ike->sa.st_on_delete.skip_send_delete) {
		llog_pexpect(ike->sa.logger, where,
			     "%s() called when skipping send delete", __func__);
	} else {
		on_delete(&ike->sa, skip_send_delete);
	}

	if (impair.send_no_delete) {
		llog_sa(RC_LOG, ike, "IMPAIR: impair-send-no-delete set - not sending Delete/Notify");
		return;
	}

	v2_msgid_start_record_n_send(ike, &v2_INFORMATIONAL_v2DELETE_exchange);
	/* hack; this call records the delete */
	initiate_v2_INFORMATIONAL_v2DELETE_request(ike, /*child*/NULL, /*md*/NULL);
	send_recorded_v2_message(ike, "delete notification",
				 ike->sa.st_v2_msgid_windows.initiator.outgoing_fragments);
	v2_msgid_finish(ike, NULL/*MD*/, HERE);
}

static const struct v2_transition v2_INFORMATIONAL_v2DELETE_initiate_transition = {
	.story = "initiate Informational Delete IKE or Child SA",
	.from = { &state_v2_ESTABLISHED_IKE_SA, },
	.to = &state_v2_ESTABLISHED_IKE_SA,
	.exchange = ISAKMP_v2_INFORMATIONAL,
	.processor = initiate_v2_INFORMATIONAL_v2DELETE_request,
	.llog_success = llog_v2_success_v2_INFORMATIONAL_v2DELETE_request,
	.timeout_event =  EVENT_RETAIN,
};

static const struct v2_transition v2_INFORMATIONAL_v2DELETE_responder_transition[] = {
	{ .story      = "process Informational Delete IKE or Child SA request",
	  .from = { &state_v2_ESTABLISHED_IKE_SA, },
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .exchange   = ISAKMP_v2_INFORMATIONAL,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(D),
	  .processor  = process_v2_INFORMATIONAL_v2DELETE_request,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN, },
};

static const struct v2_transitions v2_INFORMATIONAL_v2DELETE_responder_transitions = {
	ARRAY_REF(v2_INFORMATIONAL_v2DELETE_responder_transition),
};

static const struct v2_transition v2_INFORMATIONAL_v2DELETE_response_transition[] = {

	{ .story      = "process Informational Delete IKE or Child SA response",
	  .from = { &state_v2_ESTABLISHED_IKE_SA, },
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .exchange   = ISAKMP_v2_INFORMATIONAL,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.optional = v2P(D),
	  .processor = process_v2_INFORMATIONAL_v2DELETE_response,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN, },

};

static const struct v2_transitions v2_INFORMATIONAL_v2DELETE_response_transitions =
{
	ARRAY_REF(v2_INFORMATIONAL_v2DELETE_response_transition),
};

const struct v2_exchange v2_INFORMATIONAL_v2DELETE_exchange = {
	.type = ISAKMP_v2_INFORMATIONAL,
	.subplot = "delete IKE or Child SA",
	.secured = true,
	.initiate = &v2_INFORMATIONAL_v2DELETE_initiate_transition,
	.responder = &v2_INFORMATIONAL_v2DELETE_responder_transitions,
	.response = &v2_INFORMATIONAL_v2DELETE_response_transitions,
};
