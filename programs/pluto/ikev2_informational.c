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

/*
 ***************************************************************
 *                       Notify                            *****
 ***************************************************************
 */

static bool process_v2N_requests(struct ike_sa *ike, struct msg_digest *md,
				 struct v2SK_payload *sk)
{
	/*
	 * This happens when we are original initiator, and we
	 * received REDIRECT payload during the active session.
	 *
	 * It trumps everything else.  Should delete also be ignored?
	 */
	if (md->pd[PD_v2N_REDIRECT] != NULL) {
		struct pbs_in pbs = md->pd[PD_v2N_REDIRECT]->pbs;
		dbg("received v2N_REDIRECT in informational");
		ip_address redirect_to;
		err_t e = parse_redirect_payload(&pbs, ike->sa.st_connection->accept_redirect_to,
						 NULL, &redirect_to, ike->sa.st_logger);
		if (e != NULL) {
			log_state(RC_LOG_SERIOUS, &ike->sa,
				  "warning: parsing of v2N_REDIRECT payload failed: %s", e);
		} else {
			ike->sa.st_connection->temp_vars.redirect_ip = redirect_to;
			event_force(EVENT_v2_REDIRECT, &ike->sa);
		}
		return true;
	}

	if (!process_v2N_mobike_requests(ike, md, sk)) {
		return false;
	}

	return true;
}

static bool process_v2N_responses(struct ike_sa *ike, struct msg_digest *md)
{
	process_v2N_mobike_responses(ike, md);
	return true;
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
	pexpect(null_child == NULL);
	int ndp = 0;	/* number Delete payloads for IPsec protocols */
	bool del_ike = false;	/* any IKE SA Deletions? */

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

	/* make sure HDR is at start of a clean buffer */
	struct pbs_out reply_stream = open_pbs_out("information exchange reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   ike->sa.st_logger);

	/* HDR out */

	struct pbs_out rbody = open_v2_message(&reply_stream, ike,
					       md /* response */,
					       ISAKMP_v2_INFORMATIONAL);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* insert an Encryption payload header */

	struct v2SK_payload sk = open_v2SK_payload(ike->sa.st_logger, &rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		if (!process_v2N_requests(ike, md, &sk)) {
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}
	}

	if (md->chain[ISAKMP_NEXT_v2D] != NULL) {
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

	/* authenticated decrypted response - It's alive, alive! */
	dbg("Received an INFORMATIONAL response, updating st_last_liveness, no pending_liveness");
	ike->sa.st_last_liveness = mononow();

	/*
	 * Do the actual deletion, build the body of the response.
	 */

	if (del_ike) {
		/*
		 * If we are deleting the Parent SA, the Child SAs
		 * will be torn down as well, so no point processing
		 * the other Delete SA payloads.  We won't catch
		 * nonsense in those payloads.
		 *
		 * But wait: we cannot delete the IKE SA until after
		 * we've sent the response packet.  To be continued
		 * below ...
		 */
	} else {
		/*
		 * Pass 2 over the Delete Payloads: Actual IPsec SA
		 * deletion, build response Delete Payloads.  If there
		 * is no payload, this loop is a no-op.
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
						delete_or_replace_child(ike, dst);
					}
				} /* for each spi */

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
			break;

			default:
				/* ignore unrecognized protocol */
				break;
			}
		}  /* for each Delete Payload */
	}

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

	stf_status ret = encrypt_v2SK_payload(&sk);
	if (ret != STF_OK)
		return ret;

	/* ??? should we support fragmenting?  Maybe one day. */
	record_v2_message(ike, &reply_stream, "v2 INFORMATIONAL response", MESSAGE_RESPONSE);

	/*
	 * ... now we can delete the IKE SA if we want to.
	 * The response is hopefully empty.
	 */
	if (del_ike) {
		/*
		 * Record 'n' send the message inline.  Should be
		 * handling this better.  Perhaps signaling the death
		 * by returning STF_ZOMBIFY?  Tthe IKE SA should
		 * linger so that it can sink retransmits.
		 *
		 * Since the IKE SA is about to disappear the update
		 * isn't needed but what ever (i.e., be consistent).
		 */
		send_recorded_v2_message(ike, "v2_INFORMATIONAL IKE SA Delete response",
					 MESSAGE_RESPONSE);
		dbg_v2_msgid(ike, &ike->sa,
			     "XXX: in %s() hacking around record 'n' send as calling delete_ike_family() inline",
			     __func__);
		v2_msgid_update_sent(ike, &ike->sa, md, MESSAGE_RESPONSE);
		/*
		 * Danger!
		 *
		 * The call to delete_ike_family() deletes this IKE
		 * SA.  Signal this up the chain by returning
		 * STF_SKIP_COMPLETE_STATE_TRANSITION.
		 *
		 * Killing .v1_st is an extra safety net.
		 */
		delete_ike_family(ike, DONT_SEND_DELETE);
		md->v1_st = NULL;
		ike = NULL;
		return STF_SKIP_COMPLETE_STATE_TRANSITION;
	}

	mobike_possibly_send_recorded(ike, md);

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

	/* authenticated decrypted request - It's alive, alive! */
	dbg("Received an INFORMATIONAL request");
	ike->sa.st_last_liveness = mononow();

	/*
	 * Only count empty requests as liveness probes.
	 */
	if (md->chain[ISAKMP_NEXT_v2SK]->payload.v2gen.isag_np == ISAKMP_NEXT_NONE) {
		pstats_ike_dpd_replied++;
	}
	return STF_OK;
}

stf_status process_v2_INFORMATIONAL_response(struct ike_sa *ike,
					     struct child_sa *null_child,
					     struct msg_digest *md)
{
	pexpect(null_child == NULL);
	int ndp = 0;	/* number Delete payloads for IPsec protocols */
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

	/*
	 * Process NOTIFY payloads - ignore MOBIKE when deleting
	 */

	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		if (!process_v2N_responses(ike, md)) {
			return STF_FATAL;
		}
	}

	if (md->chain[ISAKMP_NEXT_v2D] != NULL) {
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
				log_state(RC_LOG, &ike->sa,
					  "Response to Delete improperly includes IKE SA");
				return STF_FAIL + v2N_INVALID_SYNTAX;

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
	 * This happens when we are original initiator,
	 * and we received REDIRECT payload during the active
	 * session.
	 */
	if (seen_and_parsed_redirect)
		event_force(EVENT_v2_REDIRECT, &ike->sa);

	/*
	 * Do the actual deletion.
	 */

	if (md->chain[ISAKMP_NEXT_v2D] != NULL) {
		/*
		 * Pass 2 over the Delete Payloads: Actual IPsec SA
		 * deletion.  If there is no payload, this loop is a
		 * no-op.
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
				for (unsigned i = 0; i < v2del->isad_nrspi; i++) {
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
						delete_or_replace_child(ike, dst);
					}
				} /* for each spi */

			}
			break;

			default:
				/* ignore unrecognized protocol */
				break;
			}
		}  /* for each Delete Payload */
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

	/*
	 * Only count empty responses as liveness.
	 */
	if (md->chain[ISAKMP_NEXT_v2SK]->payload.v2gen.isag_np == ISAKMP_NEXT_NONE) {
		dbg("Received an INFORMATIONAL liveness response");
		ike->sa.st_last_liveness = mononow();
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
