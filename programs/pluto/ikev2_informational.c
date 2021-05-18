/* IKEv2 informational exchange, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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
#include "demux.h"
#include "log.h"
#include "connections.h"
#include "ikev2_redirect.h"
#include "ikev2_message.h"
#include "ikev2_send.h"
#include "kernel.h"
#include "pluto_stats.h"

#include "ikev2_informational.h"
#include "ikev2_mobike.h"

static void delete_or_replace_child(struct ike_sa *ike, struct child_sa *child)
{
	/* the CHILD's connection; not IKE's */
	struct connection *c = child->sa.st_connection;

	if (child->sa.st_event == NULL) {
		/*
		 * ??? should this be an assert/expect?
		 */
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "received Delete SA payload: delete CHILD SA #%lu. st_event == NULL",
			  child->sa.st_serialno);
		delete_state(&child->sa);
	} else if (child->sa.st_event->ev_type == EVENT_SA_EXPIRE) {
		/*
		 * this state  was going to EXPIRE: hurry it along
		 *
		 * ??? why is this treated specially.  Can we not
		 * delete_state()?
		 */
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "received Delete SA payload: expire CHILD SA #%lu now",
			  child->sa.st_serialno);
		event_force(EVENT_SA_EXPIRE, &child->sa);
	} else if (c->newest_ipsec_sa == child->sa.st_serialno &&
		   (c->policy & POLICY_UP)) {
		/*
		 * CHILD SA for a permanent connection that we have
		 * initiated.  Replace it now.  Useful if the other
		 * peer is rebooting.
		 */
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "received Delete SA payload: replace CHILD SA #%lu now",
			  child->sa.st_serialno);
		child->sa.st_replace_margin = deltatime(0);
		event_force(EVENT_SA_REPLACE, &child->sa);
	} else {
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "received Delete SA payload: delete CHILD SA #%lu now",
			  child->sa.st_serialno);
		delete_state(&child->sa);
	}
}

/* currently we support only MOBIKE notifies and v2N_REDIRECT notify */
static void process_informational_notify_req(struct msg_digest *md, bool *redirect, bool *ntfy_natd,
		chunk_t *cookie2)
{
	struct payload_digest *ntfy;
	struct state *st = md->v1_st;
	struct ike_sa *ike = ike_sa(st, HERE);
	bool may_mobike = mobike_check_established(st);
	bool ntfy_update_sa = FALSE;
	ip_address redirect_ip;

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_REDIRECT:
			dbg("received v2N_REDIRECT in informational");
			err_t e = parse_redirect_payload(&ntfy->pbs,
							 st->st_connection->accept_redirect_to,
							 NULL,
							 &redirect_ip,
							 ike->sa.st_logger);
			if (e != NULL) {
				log_state(RC_LOG_SERIOUS, st,
					  "warning: parsing of v2N_REDIRECT payload failed: %s", e);
			} else {
				*redirect = TRUE;
				st->st_connection->temp_vars.redirect_ip = redirect_ip;
			}
			return;

		case v2N_UPDATE_SA_ADDRESSES:
			if (may_mobike) {
				ntfy_update_sa = TRUE;
				dbg("Need to process v2N_UPDATE_SA_ADDRESSES");
			} else {
				log_state(RC_LOG, st, "Connection does not allow MOBIKE, ignoring UPDATE_SA_ADDRESSES");
			}
			break;

		case v2N_NO_NATS_ALLOWED:
			if (may_mobike)
				st->st_seen_nonats = TRUE;
			else
				log_state(RC_LOG, st, "Connection does not allow MOBIKE, ignoring v2N_NO_NATS_ALLOWED");
			break;

		case v2N_NAT_DETECTION_DESTINATION_IP:
		case v2N_NAT_DETECTION_SOURCE_IP:
			*ntfy_natd = TRUE;
			dbg("TODO: Need to process NAT DETECTION payload if we are initiator");
			break;

		case v2N_NO_ADDITIONAL_ADDRESSES:
			if (may_mobike) {
				dbg("Received NO_ADDITIONAL_ADDRESSES - no need to act on this");
			} else {
				log_state(RC_LOG, st, "Connection does not allow MOBIKE, ignoring NO_ADDITIONAL_ADDRESSES payload");
			}
			break;

		case v2N_COOKIE2:
			if (may_mobike) {
				/* copy cookie */
				if (ntfy->payload.v2n.isan_length > IKEv2_MAX_COOKIE_SIZE) {
					dbg("MOBIKE COOKIE2 notify payload too big - ignored");
				} else {
					const pb_stream *dc_pbs = &ntfy->pbs;

					*cookie2 = clone_bytes_as_chunk(dc_pbs->cur, pbs_left(dc_pbs),
									"saved cookie2");
					DBG_dump_hunk("MOBIKE COOKIE2 received:", *cookie2);
				}
			} else {
				log_state(RC_LOG, st, "Connection does not allow MOBIKE, ignoring COOKIE2");
			}
			break;

		case v2N_ADDITIONAL_IP4_ADDRESS:
			dbg("ADDITIONAL_IP4_ADDRESS payload ignored (not yet supported)");
			/* not supported yet */
			break;
		case v2N_ADDITIONAL_IP6_ADDRESS:
			dbg("ADDITIONAL_IP6_ADDRESS payload ignored (not yet supported)");
			/* not supported yet */
			break;

		default:
			dbg("Received unexpected %s notify - ignored",
			    enum_name(&ikev2_notify_names, ntfy->payload.v2n.isan_type));
			break;
		}
	}

	if (ntfy_update_sa) {
		if (LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
			log_state(RC_LOG, st, "Ignoring MOBIKE UPDATE_SA since we are behind NAT");
		} else {
			if (!update_mobike_endpoints(ike, md))
				*ntfy_natd = FALSE;
			update_ike_endpoints(ike, md); /* update state sender so we can find it for IPsec SA */
		}
	}

	if (may_mobike && !ntfy_update_sa && *ntfy_natd &&
	    !LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/*
		 * If this is a MOBIKE probe, use the received IP:port
		 * for only this reply packet, without updating IKE
		 * endpoint and without UPDATE_SA.
		 */
		st->st_mobike_remote_endpoint = md->sender;
	}

	if (ntfy_update_sa)
		log_state(RC_LOG, st, "MOBIKE request: updating IPsec SA by request");
	else
		dbg("MOBIKE request: not updating IPsec SA");
}

/*
 *
 ***************************************************************
 *                       INFORMATIONAL                     *****
 ***************************************************************
 *  -
 *
 *
 */

/* RFC 5996 1.4 "The INFORMATIONAL Exchange"
 *
 * HDR, SK {[N,] [D,] [CP,] ...}  -->
 *   <--  HDR, SK {[N,] [D,] [CP], ...}
 */

stf_status process_v2_INFORMATIONAL_request(struct ike_sa *ike,
					    struct child_sa *null_child,
					    struct msg_digest *md)
{
	const bool responding = true;
	pexpect(null_child == NULL);
	int ndp = 0;	/* number Delete payloads for IPsec protocols */
	bool del_ike = false;	/* any IKE SA Deletions? */
	bool seen_and_parsed_redirect = FALSE;

	/*
	 * we need connection and boolean below
	 * in a separate variables because we
	 * do something with them after we delete
	 * the state.
	 *
	 * XXX: which is of course broken; code should return
	 * STF_ZOMBIFY and and let state machine clean things up.
	 */
	struct connection *c = ike->sa.st_connection;
	bool do_unroute = ike->sa.st_sent_redirect && c->kind == CK_PERMANENT;
	chunk_t cookie2 = empty_chunk;

	/*
	 * Process NOTIFY payloads - ignore MOBIKE when deleting
	 */
	bool send_mobike_resp = false;	/* only if responding */

	if (md->chain[ISAKMP_NEXT_v2D] == NULL) {
		if (responding) {
			process_informational_notify_req(md, &seen_and_parsed_redirect, &send_mobike_resp, &cookie2);
		} else {
			if (process_mobike_resp(md)) {
				log_state(RC_LOG, &ike->sa,
					  "MOBIKE response: updating IPsec SA");
			} else {
				dbg("MOBIKE response: not updating IPsec SA");
			}
		}
	} else {
		/*
		 * RFC 7296 1.4.1 "Deleting an SA with INFORMATIONAL Exchanges"
		 */

		/*
		 * Pass 1 over Delete Payloads:
		 *
		 * - Count number of IPsec SA Delete Payloads
		 * - notice any IKE SA Delete Payload
		 * - sanity checking
		 */

		for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2D];
		     p != NULL; p = p->next) {
			struct ikev2_delete *v2del = &p->payload.v2delete;

			switch (v2del->isad_protoid) {
			case PROTO_ISAKMP:
				if (!responding) {
					log_state(RC_LOG, &ike->sa,
						  "Response to Delete improperly includes IKE SA");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (del_ike) {
					log_state(RC_LOG, &ike->sa,
						  "Error: INFORMATIONAL Exchange with more than one Delete Payload for the IKE SA");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (v2del->isad_nrspi != 0 || v2del->isad_spisize != 0) {
					log_state(RC_LOG, &ike->sa,
						  "IKE SA Delete has non-zero SPI size or number of SPIs");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				del_ike = true;
				break;

			case PROTO_IPSEC_AH:
			case PROTO_IPSEC_ESP:
				if (v2del->isad_spisize != sizeof(ipsec_spi_t)) {
					log_state(RC_LOG, &ike->sa,
						  "IPsec Delete Notification has invalid SPI size %u",
						  v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (v2del->isad_nrspi * v2del->isad_spisize != pbs_left(&p->pbs)) {
					log_state(RC_LOG, &ike->sa,
						  "IPsec Delete Notification payload size is %zu but %u is required",
						  pbs_left(&p->pbs),
						  v2del->isad_nrspi * v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				ndp++;
				break;

			default:
				log_state(RC_LOG, &ike->sa,
					  "Ignored bogus delete protoid '%d'", v2del->isad_protoid);
			}
		}

		if (del_ike && ndp != 0)
			log_state(RC_LOG, &ike->sa,
				  "Odd: INFORMATIONAL Exchange deletes IKE SA and yet also deletes some IPsec SA");
	}

	/*
	 * response packet preparation: DELETE or non-delete (eg MOBIKE/keepalive/REDIRECT)
	 *
	 * There can be at most one Delete Payload for an IKE SA.
	 * It means that this very SA is to be deleted.
	 *
	 * For each non-IKE Delete Payload we receive,
	 * we respond with a corresponding Delete Payload.
	 * Note that that means we will have an empty response
	 * if no Delete Payloads came in or if the only
	 * Delete Payload is for an IKE SA.
	 *
	 * If we received NAT detection payloads as per MOBIKE, send answers
	 */

	/*
	 * Variables for generating response.
	 * NOTE: only meaningful if "responding" is true!
	 * These declarations must be placed so early because they must be in scope for
	 * all of the several chunks of code that handle responding.
	 *
	 * XXX: in terms of readability and reliability, this
	 * interleaving of initiator vs response code paths is pretty
	 * screwed up.
	 */

	struct pbs_out reply_stream;
	pb_stream rbody;
	v2SK_payload_t sk;
	zero(&rbody);
	zero(&sk);

	if (responding) {
		/* make sure HDR is at start of a clean buffer */
		reply_stream = open_pbs_out("information exchange reply packet",
					    reply_buffer, sizeof(reply_buffer),
					    ike->sa.st_logger);


		/* authenticated decrypted response - It's alive, alive! */
		dbg("Received an INFORMATIONAL response, updating st_last_liveness, no pending_liveness");
		ike->sa.st_last_liveness = mononow();
		ike->sa.st_pend_liveness = false;

		/* HDR out */

		rbody = open_v2_message(&reply_stream, ike,
					md /* response */,
					ISAKMP_v2_INFORMATIONAL);
		if (!pbs_ok(&rbody)) {
			return STF_INTERNAL_ERROR;
		}

		/* insert an Encryption payload header */

		sk = open_v2SK_payload(ike->sa.st_logger, &rbody, ike);
		if (!pbs_ok(&sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}

		if (send_mobike_resp) {
			stf_status e = add_mobike_response_payloads(
				&cookie2,	/* will be freed */
				md, &sk.pbs);
			if (e != STF_OK)
				return e;
		}
	}

	/*
	 * This happens when we are original initiator,
	 * and we received REDIRECT payload during the active
	 * session.
	 */
	if (seen_and_parsed_redirect)
		event_force(EVENT_v2_REDIRECT, &ike->sa);

	/*
	 * Do the actual deletion.
	 * If responding, build the body of the response.
	 */

	if (!responding && ike->sa.st_state->kind == STATE_IKESA_DEL) {
		/*
		 * this must be a response to our IKE SA delete request
		 * Even if there are are other Delete Payloads,
		 * they cannot matter: we delete the family.
		 */
		delete_ike_family(ike, DONT_SEND_DELETE);
		md->v1_st = NULL;
		ike = NULL;
	} else if (!responding && md->chain[ISAKMP_NEXT_v2D] == NULL) {
		/*
		 * A liveness update response is handled here
		 */
		dbg("Received an INFORMATIONAL non-delete request; updating liveness, no longer pending.");
		ike->sa.st_last_liveness = mononow();
		ike->sa.st_pend_liveness = false;
	} else if (del_ike) {
		/*
		 * If we are deleting the Parent SA, the Child SAs will be torn down as well,
		 * so no point processing the other Delete SA payloads.
		 * We won't catch nonsense in those payloads.
		 *
		 * But wait: we cannot delete the IKE SA until after
		 * we've sent the response packet.  To be continued
		 * below ...
		 */
		passert(responding);
	} else {
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
						return STF_INTERNAL_ERROR;	/* cannot happen */
					}

					esb_buf b;
					dbg("delete %s SA(0x%08" PRIx32 ")",
					    enum_show(&ikev2_delete_protocol_id_names,
						      v2del->isad_protoid, &b),
					    ntohl((uint32_t) spi));

					/*
					 * From 3.11.  Delete Payload:
					 * [the delete payload will]
					 * contain the IPsec protocol
					 * ID of that protocol (2 for
					 * AH, 3 for ESP), and the SPI
					 * is the SPI the sending
					 * endpoint would expect in
					 * inbound ESP or AH packets.
					 *
					 * From our POV, that's the
					 * outbound SPI.
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
						dst->sa.st_dont_send_delete = true;
						/* st is a parent */
						passert(&ike->sa != &dst->sa);
						passert(ike->sa.st_serialno == dst->sa.st_clonedfrom);
						if (!del_ike && responding) {
							struct ipsec_proto_info *pr =
								v2del->isad_protoid == PROTO_IPSEC_AH ?
								&dst->sa.st_ah :
								&dst->sa.st_esp;

							if (j < elemsof(spi_buf)) {
								spi_buf[j] = pr->our_spi;
								j++;
							} else {
								log_state(RC_LOG, &ike->sa,
									  "too many SPIs in Delete Notification payload; ignoring 0x%08" PRIx32,
									  ntohl(spi));
							}
						}
						delete_or_replace_child(ike, dst);
					}
				} /* for each spi */

				if (!del_ike && responding) {
					/* build output Delete Payload */
					struct ikev2_delete v2del_tmp = {
						.isad_protoid = v2del->isad_protoid,
						.isad_spisize = v2del->isad_spisize,
						.isad_nrspi = j,
					};

					/* Emit delete payload header and SPI values */
					pb_stream del_pbs;	/* output stream */

					if (!out_struct(&v2del_tmp,
							&ikev2_delete_desc,
							&sk.pbs,
							&del_pbs))
						return false;
					diag_t d = pbs_out_raw(&del_pbs,
							       spi_buf,
							       j * sizeof(spi_buf[0]),
							       "local SPIs");
					if (d != NULL) {
						llog_diag(RC_LOG_SERIOUS, sk.logger, &d, "%s", "");
						return STF_INTERNAL_ERROR;
					}

					close_output_pbs(&del_pbs);
				}
			}
			break;

			default:
				/* ignore unrecognized protocol */
				break;
			}
		}  /* for each Delete Payload */
	}

	if (responding) {
		/*
		 * We've now build up the content (if any) of the Response:
		 *
		 * - empty, if there were no Delete Payloads or if we are
		 *   responding to v2N_REDIRECT payload (RFC 5685 Chapter 5).
		 *   Treat as a check for liveness.  Correct response is this
		 *   empty Response.
		 *
		 * - if an ISAKMP SA is mentioned in input message,
		 *   we are sending an empty Response, as per standard.
		 *
		 * - for IPsec SA mentioned, we are sending its mate.
		 *
		 * - for MOBIKE, we send NAT NOTIFY payloads and optionally a COOKIE2
		 *
		 * Close up the packet and send it.
		 */

		/* const size_t len = pbs_offset(&sk.pbs); */
		if (!close_v2SK_payload(&sk)) {
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&rbody);
		close_output_pbs(&reply_stream);
;
		stf_status ret = encrypt_v2SK_payload(&sk);
		if (ret != STF_OK)
			return ret;

		struct mobike mobike_remote;

		mobike_switch_remote(md, &mobike_remote);

		/* ??? should we support fragmenting?  Maybe one day. */
		record_v2_message(ike, &reply_stream, "reply packet for process_encrypted_informational_ikev2",
				  MESSAGE_RESPONSE);
		send_recorded_v2_message(ike, "reply packet for process_encrypted_informational_ikev2",
					 MESSAGE_RESPONSE);

		/*
		 * XXX: This code should be neither using record 'n'
		 * send (which leads to RFC violations because it
		 * doesn't wait for an ACK) and/or be deleting the
		 * state midway through a state transition.
		 *
		 * When DEL_IKE, the update isn't needed but what
		 * ever.
		 */
		dbg_v2_msgid(ike, &ike->sa, "XXX: in %s() hacking around record 'n' send bypassing send queue hacking around delete_ike_family()",
			     __func__);
		v2_msgid_update_sent(ike, &ike->sa, md, MESSAGE_RESPONSE);

		mobike_reset_remote(&ike->sa, &mobike_remote);

		/*
		 * ... now we can delete the IKE SA if we want to.
		 *
		 * The response is hopefully empty.
		 */
		if (del_ike) {
			delete_ike_family(ike, DONT_SEND_DELETE);
			md->v1_st = NULL;
			ike = NULL;
		}
	}

	/*
	 * This is a special case. When we have site to site connection
	 * and one site redirects other in IKE_AUTH reply, he doesn't
	 * unroute. It seems like it was easier to add here this part
	 * than in delete_ipsec_sa() in kernel.c where it should be
	 * (at least it seems like it should be there).
	 *
	 * The need for this special case was discovered by running
	 * various test cases.
	 */
	if (do_unroute) {
		unroute_connection(c);
	}

	/* count as DPD/liveness only if there was no Delete */
	if (!del_ike && ndp == 0) {
		if (responding)
			pstats_ike_dpd_replied++;
		else
			pstats_ike_dpd_recv++;
	}
	return STF_OK;
}

stf_status process_v2_INFORMATIONAL_response(struct ike_sa *ike,
					     struct child_sa *null_child,
					     struct msg_digest *md)
{
	const bool responding = false;
	pexpect(null_child == NULL);
	int ndp = 0;	/* number Delete payloads for IPsec protocols */
	bool del_ike = false;	/* any IKE SA Deletions? */
	bool seen_and_parsed_redirect = FALSE;

	/*
	 * we need connection and boolean below
	 * in a separate variables because we
	 * do something with them after we delete
	 * the state.
	 *
	 * XXX: which is of course broken; code should return
	 * STF_ZOMBIFY and and let state machine clean things up.
	 */
	struct connection *c = ike->sa.st_connection;
	bool do_unroute = ike->sa.st_sent_redirect && c->kind == CK_PERMANENT;
	chunk_t cookie2 = empty_chunk;

	/*
	 * Process NOTIFY payloads - ignore MOBIKE when deleting
	 */
	bool send_mobike_resp = false;	/* only if responding */

	if (md->chain[ISAKMP_NEXT_v2D] == NULL) {
		if (responding) {
			process_informational_notify_req(md, &seen_and_parsed_redirect, &send_mobike_resp, &cookie2);
		} else {
			if (process_mobike_resp(md)) {
				log_state(RC_LOG, &ike->sa,
					  "MOBIKE response: updating IPsec SA");
			} else {
				dbg("MOBIKE response: not updating IPsec SA");
			}
		}
	} else {
		/*
		 * RFC 7296 1.4.1 "Deleting an SA with INFORMATIONAL Exchanges"
		 */

		/*
		 * Pass 1 over Delete Payloads:
		 *
		 * - Count number of IPsec SA Delete Payloads
		 * - notice any IKE SA Delete Payload
		 * - sanity checking
		 */

		for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2D];
		     p != NULL; p = p->next) {
			struct ikev2_delete *v2del = &p->payload.v2delete;

			switch (v2del->isad_protoid) {
			case PROTO_ISAKMP:
				if (!responding) {
					log_state(RC_LOG, &ike->sa,
						  "Response to Delete improperly includes IKE SA");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (del_ike) {
					log_state(RC_LOG, &ike->sa,
						  "Error: INFORMATIONAL Exchange with more than one Delete Payload for the IKE SA");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (v2del->isad_nrspi != 0 || v2del->isad_spisize != 0) {
					log_state(RC_LOG, &ike->sa,
						  "IKE SA Delete has non-zero SPI size or number of SPIs");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				del_ike = true;
				break;

			case PROTO_IPSEC_AH:
			case PROTO_IPSEC_ESP:
				if (v2del->isad_spisize != sizeof(ipsec_spi_t)) {
					log_state(RC_LOG, &ike->sa,
						  "IPsec Delete Notification has invalid SPI size %u",
						  v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (v2del->isad_nrspi * v2del->isad_spisize != pbs_left(&p->pbs)) {
					log_state(RC_LOG, &ike->sa,
						  "IPsec Delete Notification payload size is %zu but %u is required",
						  pbs_left(&p->pbs),
						  v2del->isad_nrspi * v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				ndp++;
				break;

			default:
				log_state(RC_LOG, &ike->sa,
					  "Ignored bogus delete protoid '%d'", v2del->isad_protoid);
			}
		}

		if (del_ike && ndp != 0)
			log_state(RC_LOG, &ike->sa,
				  "Odd: INFORMATIONAL Exchange deletes IKE SA and yet also deletes some IPsec SA");
	}

	/*
	 * response packet preparation: DELETE or non-delete (eg MOBIKE/keepalive/REDIRECT)
	 *
	 * There can be at most one Delete Payload for an IKE SA.
	 * It means that this very SA is to be deleted.
	 *
	 * For each non-IKE Delete Payload we receive,
	 * we respond with a corresponding Delete Payload.
	 * Note that that means we will have an empty response
	 * if no Delete Payloads came in or if the only
	 * Delete Payload is for an IKE SA.
	 *
	 * If we received NAT detection payloads as per MOBIKE, send answers
	 */

	/*
	 * Variables for generating response.
	 * NOTE: only meaningful if "responding" is true!
	 * These declarations must be placed so early because they must be in scope for
	 * all of the several chunks of code that handle responding.
	 *
	 * XXX: in terms of readability and reliability, this
	 * interleaving of initiator vs response code paths is pretty
	 * screwed up.
	 */

	struct pbs_out reply_stream;
	pb_stream rbody;
	v2SK_payload_t sk;
	zero(&rbody);
	zero(&sk);

	if (responding) {
		/* make sure HDR is at start of a clean buffer */
		reply_stream = open_pbs_out("information exchange reply packet",
					    reply_buffer, sizeof(reply_buffer),
					    ike->sa.st_logger);


		/* authenticated decrypted response - It's alive, alive! */
		dbg("Received an INFORMATIONAL response, updating st_last_liveness, no pending_liveness");
		ike->sa.st_last_liveness = mononow();
		ike->sa.st_pend_liveness = false;

		/* HDR out */

		rbody = open_v2_message(&reply_stream, ike,
					md /* response */,
					ISAKMP_v2_INFORMATIONAL);
		if (!pbs_ok(&rbody)) {
			return STF_INTERNAL_ERROR;
		}

		/* insert an Encryption payload header */

		sk = open_v2SK_payload(ike->sa.st_logger, &rbody, ike);
		if (!pbs_ok(&sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}

		if (send_mobike_resp) {
			stf_status e = add_mobike_response_payloads(
				&cookie2,	/* will be freed */
				md, &sk.pbs);
			if (e != STF_OK)
				return e;
		}
	}

	/*
	 * This happens when we are original initiator,
	 * and we received REDIRECT payload during the active
	 * session.
	 */
	if (seen_and_parsed_redirect)
		event_force(EVENT_v2_REDIRECT, &ike->sa);

	/*
	 * Do the actual deletion.
	 * If responding, build the body of the response.
	 */

	if (!responding && ike->sa.st_state->kind == STATE_IKESA_DEL) {
		/*
		 * this must be a response to our IKE SA delete request
		 * Even if there are are other Delete Payloads,
		 * they cannot matter: we delete the family.
		 */
		delete_ike_family(ike, DONT_SEND_DELETE);
		md->v1_st = NULL;
		ike = NULL;
	} else if (!responding && md->chain[ISAKMP_NEXT_v2D] == NULL) {
		/*
		 * A liveness update response is handled here
		 */
		dbg("Received an INFORMATIONAL non-delete request; updating liveness, no longer pending.");
		ike->sa.st_last_liveness = mononow();
		ike->sa.st_pend_liveness = false;
	} else if (del_ike) {
		/*
		 * If we are deleting the Parent SA, the Child SAs will be torn down as well,
		 * so no point processing the other Delete SA payloads.
		 * We won't catch nonsense in those payloads.
		 *
		 * But wait: we cannot delete the IKE SA until after
		 * we've sent the response packet.  To be continued
		 * below ...
		 */
		passert(responding);
	} else {
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
						return STF_INTERNAL_ERROR;	/* cannot happen */
					}

					esb_buf b;
					dbg("delete %s SA(0x%08" PRIx32 ")",
					    enum_show(&ikev2_delete_protocol_id_names,
						      v2del->isad_protoid, &b),
					    ntohl((uint32_t) spi));

					/*
					 * From 3.11.  Delete Payload:
					 * [the delete payload will]
					 * contain the IPsec protocol
					 * ID of that protocol (2 for
					 * AH, 3 for ESP), and the SPI
					 * is the SPI the sending
					 * endpoint would expect in
					 * inbound ESP or AH packets.
					 *
					 * From our POV, that's the
					 * outbound SPI.
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
						dst->sa.st_dont_send_delete = true;
						/* st is a parent */
						passert(&ike->sa != &dst->sa);
						passert(ike->sa.st_serialno == dst->sa.st_clonedfrom);
						if (!del_ike && responding) {
							struct ipsec_proto_info *pr =
								v2del->isad_protoid == PROTO_IPSEC_AH ?
								&dst->sa.st_ah :
								&dst->sa.st_esp;

							if (j < elemsof(spi_buf)) {
								spi_buf[j] = pr->our_spi;
								j++;
							} else {
								log_state(RC_LOG, &ike->sa,
									  "too many SPIs in Delete Notification payload; ignoring 0x%08" PRIx32,
									  ntohl(spi));
							}
						}
						delete_or_replace_child(ike, dst);
					}
				} /* for each spi */

				if (!del_ike && responding) {
					/* build output Delete Payload */
					struct ikev2_delete v2del_tmp = {
						.isad_protoid = v2del->isad_protoid,
						.isad_spisize = v2del->isad_spisize,
						.isad_nrspi = j,
					};

					/* Emit delete payload header and SPI values */
					pb_stream del_pbs;	/* output stream */

					if (!out_struct(&v2del_tmp,
							&ikev2_delete_desc,
							&sk.pbs,
							&del_pbs))
						return false;
					diag_t d = pbs_out_raw(&del_pbs,
							       spi_buf,
							       j * sizeof(spi_buf[0]),
							       "local SPIs");
					if (d != NULL) {
						llog_diag(RC_LOG_SERIOUS, sk.logger, &d, "%s", "");
						return STF_INTERNAL_ERROR;
					}

					close_output_pbs(&del_pbs);
				}
			}
			break;

			default:
				/* ignore unrecognized protocol */
				break;
			}
		}  /* for each Delete Payload */
	}

	if (responding) {
		/*
		 * We've now build up the content (if any) of the Response:
		 *
		 * - empty, if there were no Delete Payloads or if we are
		 *   responding to v2N_REDIRECT payload (RFC 5685 Chapter 5).
		 *   Treat as a check for liveness.  Correct response is this
		 *   empty Response.
		 *
		 * - if an ISAKMP SA is mentioned in input message,
		 *   we are sending an empty Response, as per standard.
		 *
		 * - for IPsec SA mentioned, we are sending its mate.
		 *
		 * - for MOBIKE, we send NAT NOTIFY payloads and optionally a COOKIE2
		 *
		 * Close up the packet and send it.
		 */

		/* const size_t len = pbs_offset(&sk.pbs); */
		if (!close_v2SK_payload(&sk)) {
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&rbody);
		close_output_pbs(&reply_stream);
;
		stf_status ret = encrypt_v2SK_payload(&sk);
		if (ret != STF_OK)
			return ret;

		struct mobike mobike_remote;

		mobike_switch_remote(md, &mobike_remote);

		/* ??? should we support fragmenting?  Maybe one day. */
		record_v2_message(ike, &reply_stream, "reply packet for process_encrypted_informational_ikev2",
				  MESSAGE_RESPONSE);
		send_recorded_v2_message(ike, "reply packet for process_encrypted_informational_ikev2",
					 MESSAGE_RESPONSE);

		/*
		 * XXX: This code should be neither using record 'n'
		 * send (which leads to RFC violations because it
		 * doesn't wait for an ACK) and/or be deleting the
		 * state midway through a state transition.
		 *
		 * When DEL_IKE, the update isn't needed but what
		 * ever.
		 */
		dbg_v2_msgid(ike, &ike->sa, "XXX: in %s() hacking around record 'n' send bypassing send queue hacking around delete_ike_family()",
			     __func__);
		v2_msgid_update_sent(ike, &ike->sa, md, MESSAGE_RESPONSE);

		mobike_reset_remote(&ike->sa, &mobike_remote);

		/*
		 * ... now we can delete the IKE SA if we want to.
		 *
		 * The response is hopefully empty.
		 */
		if (del_ike) {
			delete_ike_family(ike, DONT_SEND_DELETE);
			md->v1_st = NULL;
			ike = NULL;
		}
	}

	/*
	 * This is a special case. When we have site to site connection
	 * and one site redirects other in IKE_AUTH reply, he doesn't
	 * unroute. It seems like it was easier to add here this part
	 * than in delete_ipsec_sa() in kernel.c where it should be
	 * (at least it seems like it should be there).
	 *
	 * The need for this special case was discovered by running
	 * various test cases.
	 */
	if (do_unroute) {
		unroute_connection(c);
	}

	/* count as DPD/liveness only if there was no Delete */
	if (!del_ike && ndp == 0) {
		if (responding)
			pstats_ike_dpd_replied++;
		else
			pstats_ike_dpd_recv++;
	}
	return STF_OK;
}

stf_status IKE_SA_DEL_process_v2_INFORMATIONAL_response(struct ike_sa *ike,
							struct child_sa *null_child,
							struct msg_digest *md)
{
	pexpect(null_child == NULL);
	pexpect(md != NULL);
	/*
	 * This must be a response to our IKE SA delete request Even
	 * if there are are other Delete Payloads, they cannot matter:
	 * we delete the family.
	 *
	 * Danger!
	 *
	 * The call to delete_ike_family() deletes this IKE SA.
	 * Signal this up the chain by returning
	 * STF_SKIP_COMPLETE_STATE_TRANSITION.
	 *
	 * Killing .v1_st is an extra safety net.
	 */
	delete_ike_family(ike, DONT_SEND_DELETE);
	ike = NULL;
	md->v1_st = NULL;
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}
