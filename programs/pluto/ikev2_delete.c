/* IKEv2 DELETE Exchange, for Libreswan
 *
 * Copyright (C) 2020-2022 Andrew Cagney
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
#include "demux.h"
#include "connections.h"

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
	uint8_t buf[MIN_OUTPUT_UDP_SIZE];

	struct v2_message request;
	if (!open_v2_message("informational exchange delete request",
			     ike, st->st_logger,
			     NULL/*request*/, ISAKMP_v2_INFORMATIONAL,
			     buf, sizeof(buf), &request,
			     ENCRYPTED_PAYLOAD)) {
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
				request.pbs, &del_pbs))
			return false;

		/* Emit values of spi to be sent to the peer */
		if (IS_CHILD_SA(st)) {
			diag_t d = pbs_out_raw(&del_pbs, &st->st_esp.our_spi,
					       sizeof(ipsec_spi_t), "local spis");
			if (d != NULL) {
				llog_diag(RC_LOG_SERIOUS, st->st_logger, &d, "%s", "");
				return false;
			}
		}

		close_output_pbs(&del_pbs);
	}

	if (!close_and_record_v2_message(&request)) {
		return false;
	}

	return true;
}

static stf_status initiate_v2_delete_ike_request(struct ike_sa *ike,
						 struct child_sa *unused_child UNUSED,
						 struct msg_digest *md)
{
	pexpect(md == NULL);
	if (!record_v2_delete(ike, &ike->sa)) {
		/* already logged */
		return STF_INTERNAL_ERROR;
	}
	llog_sa(RC_LOG, ike, "intiating delete");
	return STF_OK;
}

static stf_status initiate_v2_delete_child_request(struct ike_sa *ike,
						   struct child_sa *child,
						   struct msg_digest *md)
{
	pexpect(md == NULL);
	pexpect(child != NULL);

	if (!record_v2_delete(ike, &child->sa)) {
		/* already logged */
		return STF_INTERNAL_ERROR;
	}

	/*
	 * XXX: just assume an SA that isn't established is larval.
	 *
	 * Would be nice to have something indicating larval,
	 * established, zombie.
	 */
	bool established = IS_CHILD_SA_ESTABLISHED(&child->sa);
	llog_sa(RC_LOG, child,
		"deleting %s Child SA using IKE SA #%lu",
		established ? "established" : "larval",
		ike->sa.st_serialno);
	if (!established) {
		/*
		 * Normally the responder would include it's outgoing
		 * SA's SPI, and this end would use that to find /
		 * delete the child.  Here, however, the SA isn't
		 * established so we've no clue as to what the
		 * responder will send back.  If anything.
		 *
		 * Hence signal the Child SA that it should delete
		 * itself.
		 */
		event_force(EVENT_SA_DISCARD, &child->sa);
	}
	return STF_OK;
}

/*
 * XXX: where to put this?
 */

static const struct v2_state_transition v2_delete_ike = {
	.story = "delete IKE SA",
	.state = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_V2_IKE_SA_DELETE,
	.exchange = ISAKMP_v2_INFORMATIONAL,
	.send_role = MESSAGE_REQUEST,
	.processor = initiate_v2_delete_ike_request,
	.llog_success = ldbg_v2_success,
	.timeout_event =  EVENT_RETAIN,
};

static const struct v2_state_transition v2_delete_child = {
	.story = "delete CHILD SA",
	.state = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_V2_ESTABLISHED_IKE_SA,
	.exchange = ISAKMP_v2_INFORMATIONAL,
	.send_role = MESSAGE_REQUEST,
	.processor = initiate_v2_delete_child_request,
	.llog_success = ldbg_v2_success,
	.timeout_event =  EVENT_RETAIN,
};

void submit_v2_delete_exchange(struct ike_sa *ike, struct child_sa *child)
{
	const struct v2_state_transition *transition =
		(child != NULL ? &v2_delete_child : &v2_delete_ike);
	pexpect(transition->exchange == ISAKMP_v2_INFORMATIONAL);
	v2_msgid_queue_initiator(ike, child, transition);
}

bool process_v2D_requests(bool *del_ike, struct ike_sa *ike, struct msg_digest *md,
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
		case PROTO_ISAKMP:
			if (*del_ike) {
				log_state(RC_LOG, &ike->sa,
					  "Error: INFORMATIONAL Exchange with more than one Delete Payload for the IKE SA");
				return false;
			}

			if (v2del->isad_nrspi != 0 || v2del->isad_spisize != 0) {
				log_state(RC_LOG, &ike->sa,
					  "IKE SA Delete has non-zero SPI size or number of SPIs");
				return false;
			}

			*del_ike = true;
			break;

		case PROTO_IPSEC_AH:
		case PROTO_IPSEC_ESP:
			if (v2del->isad_spisize != sizeof(ipsec_spi_t)) {
				log_state(RC_LOG, &ike->sa,
					  "IPsec Delete Notification has invalid SPI size %u",
					  v2del->isad_spisize);
				return false;
			}

			if (v2del->isad_nrspi * v2del->isad_spisize != pbs_left(&p->pbs)) {
				log_state(RC_LOG, &ike->sa,
					  "IPsec Delete Notification payload size is %zu but %u is required",
					  pbs_left(&p->pbs),
					  v2del->isad_nrspi * v2del->isad_spisize);
				return false;
			}

			ndp++;
			break;

		default:
			log_state(RC_LOG, &ike->sa,
				  "Ignored bogus delete protoid '%d'", v2del->isad_protoid);
		}
	}

	if (*del_ike && ndp != 0) {
		log_state(RC_LOG, &ike->sa,
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
		case PROTO_ISAKMP:
			passert_fail(ike->sa.st_logger, HERE, "unexpected IKE delete");

		case PROTO_IPSEC_AH: /* Child SAs */
		case PROTO_IPSEC_ESP: /* Child SAs */
		{
			/* stuff for responding */
			ipsec_spi_t spi_buf[128];
			uint16_t j = 0;	/* number of SPIs in spi_buf */
			uint16_t i;

			for (i = 0; i < v2del->isad_nrspi; i++) {
				ipsec_spi_t spi;

				diag_t d = pbs_in_raw( &p->pbs, &spi, sizeof(spi),"SPI");
				if (d != NULL) {
					llog_diag(RC_LOG, ike->sa.st_logger, &d, "%s", "");
					return false;
				}

				esb_buf b;
				dbg("delete %s SA(0x%08" PRIx32 ")",
				    enum_show(&ikev2_delete_protocol_id_names,
					      v2del->isad_protoid, &b),
				    ntohl((uint32_t) spi));

				/*
				 * From 3.11.  Delete Payload: [the
				 * delete payload will] contain the
				 * IPsec protocol ID of that protocol
				 * (2 for AH, 3 for ESP), and the SPI
				 * is the SPI the sending endpoint
				 * would expect in inbound ESP or AH
				 * packets.
				 *
				 * From our POV, that's the outbound
				 * SPI.
				 */
				struct child_sa *child = find_v2_child_sa_by_outbound_spi(ike,
											  v2del->isad_protoid,
											  spi);

				if (child == NULL) {
					esb_buf b;
					log_state(RC_LOG, &ike->sa,
						  "received delete request for %s SA(0x%08" PRIx32 ") but corresponding state not found",
						  enum_show(&ikev2_delete_protocol_id_names,
							    v2del->isad_protoid, &b),
						  ntohl((uint32_t)spi));
				} else {
					esb_buf b;
					dbg("our side SPI that needs to be deleted: %s SA(0x%08" PRIx32 ")",
					    enum_show(&ikev2_delete_protocol_id_names,
						      v2del->isad_protoid, &b),
					    ntohl((uint32_t)spi));

					/* we just received a delete, don't send another delete */
					child->sa.st_send_delete = DONT_SEND_DELETE;
					passert(ike->sa.st_serialno == child->sa.st_clonedfrom);
					struct ipsec_proto_info *pr =
						(v2del->isad_protoid == PROTO_IPSEC_AH
						 ? &child->sa.st_ah
						 : &child->sa.st_esp);
					if (j < elemsof(spi_buf)) {
						spi_buf[j] = pr->our_spi;
						j++;
					} else {
						log_state(RC_LOG, &ike->sa,
							  "too many SPIs in Delete Notification payload; ignoring 0x%08" PRIx32,
							  ntohl(spi));
					}
					delete_state(&child->sa);
					child = NULL;
				}
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
			diag_t d = pbs_out_raw(&del_pbs,
					       spi_buf,
					       j * sizeof(spi_buf[0]),
					       "local SPIs");
			if (d != NULL) {
				llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
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

bool process_v2D_responses(struct ike_sa *ike, struct msg_digest *md)
{
	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2D];
	     p != NULL; p = p->next) {
		struct ikev2_delete *v2del = &p->payload.v2delete;

		switch (v2del->isad_protoid) {
		case PROTO_ISAKMP:
			passert_fail(ike->sa.st_logger, HERE, "unexpected IKE delete");

		case PROTO_IPSEC_AH: /* Child SAs */
		case PROTO_IPSEC_ESP: /* Child SAs */
		{
			uint16_t i;

			if (v2del->isad_spisize != sizeof(ipsec_spi_t)) {
				log_state(RC_LOG, &ike->sa,
					  "IPsec Delete Notification has invalid SPI size %u",
					  v2del->isad_spisize);
				return false;
			}

			if (v2del->isad_nrspi * v2del->isad_spisize != pbs_left(&p->pbs)) {
				log_state(RC_LOG, &ike->sa,
					  "IPsec Delete Notification payload size is %zu but %u is required",
					  pbs_left(&p->pbs),
					  v2del->isad_nrspi * v2del->isad_spisize);
				return false;
			}

			for (i = 0; i < v2del->isad_nrspi; i++) {
				ipsec_spi_t spi;

				diag_t d = pbs_in_raw( &p->pbs, &spi, sizeof(spi),"SPI");
				if (d != NULL) {
					llog_diag(RC_LOG, ike->sa.st_logger, &d, "%s", "");
					return false;
				}

				esb_buf b;
				dbg("delete %s SA(0x%08" PRIx32 ")",
				    enum_show(&ikev2_delete_protocol_id_names,
					      v2del->isad_protoid, &b),
				    ntohl((uint32_t) spi));

				/*
				 * From 3.11.  Delete Payload: [the
				 * delete payload will] contain the
				 * IPsec protocol ID of that protocol
				 * (2 for AH, 3 for ESP), and the SPI
				 * is the SPI the sending endpoint
				 * would expect in inbound ESP or AH
				 * packets.
				 *
				 * From our POV, that's the outbound
				 * SPI.
				 */
				struct child_sa *dst = find_v2_child_sa_by_outbound_spi(ike,
											v2del->isad_protoid,
											spi);

				if (dst == NULL) {
					esb_buf b;
					log_state(RC_LOG, &ike->sa,
						  "received delete request for %s SA(0x%08" PRIx32 ") but corresponding state not found",
						  enum_show(&ikev2_delete_protocol_id_names,
							    v2del->isad_protoid, &b),
						  ntohl((uint32_t)spi));
				} else {
					esb_buf b;
					dbg("our side SPI that needs to be deleted: %s SA(0x%08" PRIx32 ")",
					    enum_show(&ikev2_delete_protocol_id_names,
						      v2del->isad_protoid, &b),
					    ntohl((uint32_t)spi));

					/* we just received a delete, don't send another delete */
					dst->sa.st_send_delete = DONT_SEND_DELETE;
					/* st is a parent */
					passert(&ike->sa != &dst->sa);
					passert(ike->sa.st_serialno == dst->sa.st_clonedfrom);
					delete_state(&dst->sa);
					dst = NULL;
				}
			} /* for each spi */
			break;
		}

		default:
			/* ignore unrecognized protocol */
			break;
		}
	}  /* for each Delete Payload */
	return true;
}
