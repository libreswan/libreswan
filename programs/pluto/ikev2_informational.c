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
#include "pluto_stats.h"
#include "routing.h"
#include "ikev2_informational.h"
#include "ikev2_mobike.h"
#include "ikev2_delete.h"

/*
 ***************************************************************
 *                       Notify                            *****
 ***************************************************************
 */

static bool process_v2N_requests(struct ike_sa *ike, struct msg_digest *md,
				 struct pbs_out *pbs)
{
	/*
	 * This happens when we are original initiator, and we
	 * received REDIRECT payload during the active session.
	 *
	 * It trumps everything else.  Should delete also be ignored?
	 */
	if (md->pd[PD_v2N_REDIRECT] != NULL) {
		process_v2_INFORMATIONAL_request_v2N_REDIRECT(ike, md);
		return true;
	}

	if (!process_v2N_mobike_requests(ike, md, pbs)) {
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
	dbg("an informational request needing a response");
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	pexpect(null_child == NULL);

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
	bool do_unroute = ike->sa.st_sent_redirect && is_permanent(c);

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

	struct v2_message response;
	if (!open_v2_message("information exchange reply packet",
			     ike, ike->sa.logger,
			     md/*response*/, ISAKMP_v2_INFORMATIONAL,
			     reply_buffer, sizeof(reply_buffer), &response,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/* HDR out */

	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		if (!process_v2N_requests(ike, md, response.pbs)) {
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
	}

	bool del_ike = false;
	if (md->chain[ISAKMP_NEXT_v2D] != NULL) {
		if (!process_v2D_requests(&del_ike, ike, md, response.pbs)) {
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
	}

	/*
	 * We've now build up the content (if any) of the Response:
	 *
	 * - empty, if there were no Delete Payloads or if we are
	 *   responding to v2N_REDIRECT payload (RFC 5685 Chapter 5).
	 *   Treat as a check for liveness.  Correct response is this
	 *   empty Response.
	 *
	 * - if an ISAKMP SA is mentioned in input message, we are
	 *   sending an empty Response, as per standard.
	 *
	 * - for IPsec SA mentioned, we are sending its mate.
	 *
	 * - for MOBIKE, we send NAT NOTIFY payloads and optionally a
         *   COOKIE2
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
		connection_unroute(c, HERE);
	}

	/*
	 * Only count empty requests as liveness probes.
	 */
	if (md->chain[ISAKMP_NEXT_v2SK]->payload.v2gen.isag_np == ISAKMP_NEXT_NONE) {
		dbg("received an INFORMATIONAL liveness check request");
		pstats_ike_dpd_replied++;
	}

	return STF_OK;
}

stf_status process_v2_INFORMATIONAL_response(struct ike_sa *ike,
					     struct child_sa *null_child,
					     struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_RESPONSE);
	pexpect(null_child == NULL);

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
	bool do_unroute = ike->sa.st_sent_redirect && is_permanent(c);

	/*
	 * Process NOTIFY payloads
	 */

	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		if (!process_v2N_responses(ike, md)) {
			return STF_FATAL;
		}
	}

	if (md->chain[ISAKMP_NEXT_v2D] != NULL) {
		if (!process_v2D_responses(ike, md)) {
			return STF_FATAL;
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
		connection_unroute(c, HERE);
	}

	/*
	 * Only count empty responses as liveness.
	 */
	if (md->chain[ISAKMP_NEXT_v2SK]->payload.v2gen.isag_np == ISAKMP_NEXT_NONE) {
		dbg("received an INFORMATIONAL liveness check response");
		pstats_ike_dpd_recv++;
	}

	return STF_OK;
}

stf_status IKE_SA_DEL_process_v2_INFORMATIONAL_response(struct ike_sa *ike,
							struct child_sa *null_child,
							struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, null_child == NULL);
	PEXPECT(ike->sa.logger, md != NULL);
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
	return STF_OK_INITIATOR_DELETE_IKE;
}
