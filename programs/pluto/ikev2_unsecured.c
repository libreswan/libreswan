/* Process IKEv2 IKE_SA_INIT packets, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2024 Andrew Cagney
 * Copyright (C) 2016-2018 Antony Antony <appu@phenome.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include "pexpect.h"

#include "defs.h"

#include "ikev2_unsecured.h"

#include "demux.h"
#include "ikev2_states.h"
#include "ikev2_send.h"
#include "ikev2.h"
#include "state.h"
#include "log.h"
#include "ikev2_cookie.h"
#include "ikev2_redirect.h"
#include "ikev2_vendorid.h"
#include "ikev2_host_pair.h"
#include "iface.h"
#include "log_limiter.h"
#include "ikev2_ike_sa_init.h"
#include "ikev2_ike_session_resume.h"
#include "ikev2_notification.h"

static void process_v2_UNSECURED_request(struct msg_digest *md)
{

	/*
	 * 3.1.  The IKE Header (Flags)
	 *
	 * * I (Initiator) - This bit MUST be set in messages sent by
	 *   the original initiator of the IKE SA and MUST be cleared
	 *   in messages sent by the original responder.  It is used
	 *   by the recipient to determine which eight octets of the
	 *   SPI were generated by the recipient.  This bit changes to
	 *   reflect who initiated the last rekey of the IKE SA.
	 *
	 * i.e., in the request, I must be set
	 */
	if (!(md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I)) {
		limited_llog(md->logger, UNSECURED_LOG_LIMITER,
			     "IKE_SA_INIT request has I (IKE Initiator) flag clear; dropping packet");
		return;
	}

	/*
	 * 3.1.  The IKE Header (IKE SA Initiator SPI)
	 *
	 * o Initiator's SPI (8 octets) - A value chosen by the
	 *   initiator to identify a unique IKE Security Association.
	 *   This value MUST NOT be zero.
	 *
	 * (it isn't obvious why this rule is needed; exchanges still
	 * work)
	 */
	if (ike_spi_is_zero(&md->hdr.isa_ike_initiator_spi)) {
		limited_llog(md->logger, UNSECURED_LOG_LIMITER,
			     "IKE_SA_INIT request has zero IKE SA Initiator SPI; dropping packet");
		return;
	}

	/*
	 * 3.1.  The IKE Header (IKE SA Responder SPI)
	 *
	 * o Responder's SPI (8 octets) - A value chosen by the
	 *   responder to identify a unique IKE Security Association.
	 *   This value MUST be zero in the first message of an IKE
	 *   initial exchange (including repeats of that message
	 *   including a cookie).
	 *
	 * (since this is the very first message, the initiator can't
	 * know the responder's SPI).
	 */
	if (!ike_spi_is_zero(&md->hdr.isa_ike_responder_spi)) {
		limited_llog(md->logger, UNSECURED_LOG_LIMITER,
			     "IKE_SA_INIT request has non-zero IKE SA Responder SPI; dropping packet");
		return;
	}

	/*
	 * Look for a pre-existing IKE SA responder state using just
	 * the SPIi (SPIr in the message is zero so can't be used).
	 *
	 * XXX: RFC 7296 says this isn't sufficient:
	 *
	 *   2.1.  Use of Retransmission Timers
	 *
	 *   Retransmissions of the IKE_SA_INIT request require some
	 *   special handling.  When a responder receives an
	 *   IKE_SA_INIT request, it has to determine whether the
	 *   packet is a retransmission belonging to an existing
	 *   "half-open" IKE SA (in which case the responder
	 *   retransmits the same response), or a new request (in
	 *   which case the responder creates a new IKE SA and sends a
	 *   fresh response), or it belongs to an existing IKE SA
	 *   where the IKE_AUTH request has been already received (in
	 *   which case the responder ignores it).
	 *
	 *   It is not sufficient to use the initiator's SPI and/or IP
	 *   address to differentiate between these three cases
	 *   because two different peers behind a single NAT could
	 *   choose the same initiator SPI.  Instead, a robust
	 *   responder will do the IKE SA lookup using the whole
	 *   packet, its hash, or the Ni payload.
	 *
	 * But realistically, either there's an IOT device sending out
	 * a hardwired SPIi, or there is a clash and a retry will
	 * generate a new conflicting SPIi.
	 *
	 * If the lookup succeeds then there are several
	 * possibilities:
	 *
	 * State has Message ID == 0:
	 *
	 * Either it really is a duplicate; or it's a second (fake?)
	 * initiator sending the same SPIi at exactly the same time as
	 * the first (wow, what are the odds, it must be our lucky
	 * day!).
	 *
	 * Either way, the duplicate code needs to compare packets and
	 * decide if a retransmit or drop is required.  If the second
	 * initiator is real, then it will timeout and then retry with
	 * a new SPIi.
	 *
	 * State has Message ID > 0:
	 *
	 * Either it is an old duplicate; or, again, it's a second
	 * initiator sending the same SPIi only slightly later (again,
	 * what are the odds!).
	 *
	 * Several choices: let the duplicate code drop the packet,
	 * which is correct for an old duplicate message; or ignore
	 * the existing state and create a new one, which is good for
	 * the second initiator but not so good for an old duplicate.
	 * Given an old duplicate is far more likely, handle that
	 * cleenly - let the duplicate code drop the packet.
	 */
	struct ike_sa *old = find_v2_ike_sa_by_initiator_spi(&md->hdr.isa_ike_initiator_spi,
							     SA_RESPONDER);
	if (old != NULL) {
		intmax_t msgid = md->hdr.isa_msgid;
		PEXPECT(md->logger, msgid == 0); /* per above */
		/* XXX: keep test results happy */
		if (md->fake_clone) {
			llog(RC_LOG, old->sa.logger, "IMPAIR: processing a fake (cloned) message");
		}

		if (old->sa.st_state != &state_v2_IKE_SA_INIT_R) {
			/*
			 * For a duplicate, the IKE SA can't have
			 * advanced beyond IKE_SA_INIT.
			 */
			limited_llog(old->sa.logger, UNSECURED_LOG_LIMITER,
				     "received old IKE_SA_INIT request; packet dropped");
			return;
		}

		/*
		 * The IKE SA hasn't yet started processing IKE AUTH
		 * (or IKE_INTERMEDIATE).  However it may be
		 * accumulating fragments or running background crypto
		 * in preparation.
		 *
		 * Ignore that.  Until the fragments have been
		 * re-assembled and verified they can't be trusted.
		 */

		PEXPECT(old->sa.logger, old->sa.st_v2_msgid_windows.responder.recv == 0);
		PEXPECT(old->sa.logger, old->sa.st_v2_msgid_windows.responder.sent == 0);
		if (old->sa.st_v2_msgid_windows.responder.wip != -1) {
			/*
			 * Started processing (accumulating) the next
			 * packet.  No sense in replying to an older
			 * one.
			 */
			PEXPECT(old->sa.logger, old->sa.st_v2_msgid_windows.responder.wip == 1);
			limited_llog(old->sa.logger, UNSECURED_LOG_LIMITER,
				     "received IKE_SA_INIT request from previous exchange; packet dropped");
		}

		if (hunk_eq(old->sa.st_firstpacket_peer, pbs_in_all(&md->message_pbs))) {
			/*
			 * Clearly a duplicate.
			 *
			 * XXX: Log message matches
			 * is_duplicate_request() - keep test results
			 * happy.
			 */
			limited_llog(old->sa.logger, UNSECURED_LOG_LIMITER,
				     "received duplicate IKE_SA_INIT request; retransmitting response");
			send_recorded_v2_message(old, "IKE_SA_INIT responder retransmit",
						 old->sa.st_v2_msgid_windows.responder.outgoing_fragments);
			return;
		}

		/*
		 * Is this a second IKE_SA_INIT request using the same
		 * SPIi as the existing IKE SA?  Wow!  But lets not go
		 * there.
		 *
		 * XXX: Log message matches is_duplicate_request() -
		 * keep test results happy.
		 */
		limited_llog(old->sa.logger, UNSECURED_LOG_LIMITER,
			     "received too old IKE_SA_INIT retransmit");
		return;
	}

	if (drop_new_exchanges(md->logger) != NULL) {
		/* already debug-logged; log would fill disk */
		return;
	}

	/*
	 * Always check for cookies!
	 *
	 * XXX: why?
	 *
	 * Because the v2N_COOKIE payload is first, parsing and
	 * verifying it should be relatively quick and cheap.  Right?
	 *
	 * No.  The equation uses v2Ni forcing the entire payload to
	 * be parsed.
	 *
	 * The error notification is probably INVALID_SYNTAX, but
	 * could be v2N_UNSUPPORTED_CRITICAL_PAYLOAD.
	 */
	pexpect(!md->message_payloads.parsed);
	md->message_payloads = ikev2_decode_payloads(md->logger, md,
						     &md->message_pbs,
						     md->hdr.isa_np);
	if (md->message_payloads.n != v2N_NOTHING_WRONG) {
		if (require_ddos_cookies()) {
			ldbg(md->logger, "DDOS so not responding to invalid packet");
			return;
		}

		shunk_t data = shunk2(md->message_payloads.data,
				      md->message_payloads.data_size);
		send_v2N_response_from_md(md, md->message_payloads.n,
					  &data, "contains invalid paylod");
		return;
	}

	/*
	 * Do I want a cookie?
	 */
	if (v2_rejected_initiator_cookie(md, require_ddos_cookies())) {
		ldbg(md->logger, "pluto is overloaded and demanding cookies; dropping new exchange");
		return;
	}

	/*
	 * Check for v2N_REDIRECT_SUPPORTED / v2N_REDIRECTED_FROM
	 * notification.  If redirection is a MUST, try to respond
	 * with v2N_REDIRECT and don't continue further.  Otherwise
	 * continue as usual.
	 *
	 * The function below will do everything (and log the result).
	 */
	if (redirect_global(md)) {
		return;
	}

	/*
	 * Check if we would drop the packet based on VID before we
	 * create a state. Move this to ikev2_oppo.c:
	 * drop_oppo_requests()?
	 */
	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2V]; p != NULL; p = p->next) {
		if (vid_is_oppo((char *)p->pbs.cur, pbs_left(&p->pbs))) {
			if (pluto_drop_oppo_null) {
				dbg("Dropped IKE request for Opportunistic IPsec by global policy");
				return;
			}
			ldbg(md->logger, "Processing IKE request for Opportunistic IPsec");
			break;
		}
	}

	/*
	 * Does the message match the (only) expected transition?
	 */
	const struct v2_transition *transition = NULL;
	diag_t d = find_v2_unsecured_request_transition(md->logger, &state_v2_UNSECURED_R,
							md, &transition);
	if (transition == NULL) {
		send_v2N_response_from_md(md, v2N_INVALID_SYNTAX, NULL,
					  "%s", str_diag(d));
		pfree_diag(&d);
		return;
	}

	/*
	 * Is there a connection that matches the message?
	 */
	bool send_reject_response = true;
	struct connection *c = find_v2_host_pair_connection(md, &send_reject_response);
	if (c == NULL) {
		if (send_reject_response) {
			/*
			 * NO_PROPOSAL_CHOSEN is used when the list of
			 * proposals is empty, like when we did not
			 * find any connection to use.
			 *
			 * INVALID_SYNTAX is for errors that a
			 * configuration change could not fix.
			 *
			 * This call will log that the message was
			 * sent.  Should its message be merged with
			 * the above?
			 */
			send_v2N_response_from_md(md, v2N_NO_PROPOSAL_CHOSEN, NULL,
						  "no suitable connection found with IKEv2 policy");
			return;
		}

		endpoint_buf lb, rb;
		enum_buf xb;
		limited_llog(md->logger, UNSECURED_LOG_LIMITER,
			     "dropping %s request from %s received on %s, no suitable connection found with IKEv2 policy",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
			     str_endpoint(&md->sender, &rb),
			     str_endpoint(&md->iface->local_endpoint, &lb));
		return;
	}

	/*
	 * We've committed to creating a state and, presumably,
	 * dedicating real resources to the connection.
	 */
	struct ike_sa *ike = new_v2_ike_sa_responder(c, &state_v2_UNSECURED_R, md);

	statetime_t start = statetime_backdate(&ike->sa, &md->md_inception);
	/* XXX: keep test results happy */
	if (md->fake_clone) {
		llog(RC_LOG, ike->sa.logger, "IMPAIR: processing a fake (cloned) message");
	}
	v2_dispatch(ike, md, transition);
	statetime_stop(&start, "%s()", __func__);
	connection_delref(&c, md->logger);
	return;
}

static void process_v2_UNSECURED_response(struct msg_digest *md)
{
	/*
	 * 3.1.  The IKE Header (Flags)
	 *
	 * * I (Initiator) - This bit MUST be set in messages sent by
	 *   the original initiator of the IKE SA and MUST be cleared
	 *   in messages sent by the original responder.  It is used
	 *   by the recipient to determine which eight octets of the
	 *   SPI were generated by the recipient.  This bit changes to
	 *   reflect who initiated the last rekey of the IKE SA.
	 *
	 * i.e., in the response I must be clear
	 */
	if (md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I) {
		llog_md(md, "IKE_SA_INIT response has I (IKE Initiator) flag set; dropping packet");
		return;
	}

	intmax_t msgid = md->hdr.isa_msgid;
	PASSERT(md->logger, msgid == 0); /* checked in process_v2_UNSECURED_message() */

	/*
	 * 2.6.  IKE SA SPIs and Cookies:
	 *
	 *   When the IKE_SA_INIT exchange does not result in the
	 *   creation of an IKE SA due to INVALID_KE_PAYLOAD,
	 *   NO_PROPOSAL_CHOSEN, or COOKIE, the responder's SPI will
	 *   be zero also in the response message.  However, if the
	 *   responder sends a non-zero responder SPI, the initiator
	 *   should not reject the response for only that reason.
	 *
	 * i.e., can't check response for non-zero SPIr.
	 *
	 * Look for a pre-existing IKE SA responder state using just
	 * the SPIi (SPIr in the message isn't known so can't be
	 * used).
	 *
	 * An IKE_SA_INIT error notification response (INVALID_KE,
	 * COOKIE) should contain a zero SPIr (it must be ignored).
	 *
	 * An IKE_SA_INIT success response will contain an as yet
	 * unknown but non-zero SPIr so looking for it won't work.
	 */
	struct ike_sa *ike = find_v2_ike_sa_by_initiator_spi(&md->hdr.isa_ike_initiator_spi,
							     SA_INITIATOR);
	if (ike == NULL) {
		/*
		 * There should be a state matching the original
		 * initiator's IKE SPIs.  Since there isn't someone's
		 * playing games.  Drop the packet.
		 */
		name_buf xb;
		limited_llog(md->logger, UNSECURED_LOG_LIMITER,
			     "dropping unrecognized %s response with Message ID %jd, no matching IKE SA",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb), msgid);
		return;
	}

	/*
	 * Log too-old messages early.  Else code ends up complaining
	 * that an old message has the wrong exchange type.
	 *
	 * XXX: similar logic is scattered across this file and
	 * ikev2.c.  However, that isn't good reason to re-merge.
	 * Instead ikev2_msgid.c should publish a function to check
	 * this.
	 */

	if (msgid < ike->sa.st_v2_msgid_windows.initiator.recv) {
		name_buf xb;
		limited_llog(ike->sa.logger, UNSECURED_LOG_LIMITER,
			     "dropping %s response with to-old Message ID %jd, IKE SA in state %s has processed response %jd",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb), msgid,
			     ike->sa.st_state->short_name,
			     ike->sa.st_v2_msgid_windows.initiator.recv);
		return;
	}

	if (msgid == ike->sa.st_v2_msgid_windows.initiator.recv) {
		name_buf xb;
		limited_llog(ike->sa.logger, UNSECURED_LOG_LIMITER,
			     "dropping %s response with duplicate Message ID %jd, IKE SA in state %s has already processed response",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb), msgid,
			     ike->sa.st_state->short_name);
		return;
	}

	/*
	 * Weed out current message with wrong exchange.
	 */

	const struct v2_exchange *outstanding_exchange = ike->sa.st_v2_msgid_windows.initiator.exchange;
	if (outstanding_exchange == NULL) {
		name_buf xb;
		limited_llog(ike->sa.logger, UNSECURED_LOG_LIMITER,
			     "dropping unexpected %s response with Message ID %jd, IKE SA in state %s has no outstanding exchange",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb), msgid,
			     ike->sa.st_state->short_name);
		return;
	}

	if (outstanding_exchange->type != md->hdr.isa_xchg) {
		name_buf xb;
		limited_llog(ike->sa.logger, UNSECURED_LOG_LIMITER,
			     "dropping unexpected %s response with Message ID %jd, IKE SA in state %s is waiting for %s response",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb), msgid,
			     ike->sa.st_state->short_name,
			     str_enum_short(&ikev2_exchange_names, outstanding_exchange->type, &xb));
		return;
	}

	/*
	 * Now that the message has the correct type and message ID,
	 * weed out in-progress.
	 */

	if (msgid == ike->sa.st_v2_msgid_windows.initiator.wip) {
		name_buf xb;
		limited_llog(ike->sa.logger, UNSECURED_LOG_LIMITER,
			     "dropping %s response with in-progress Message ID %jd, IKE SA in state %s is currently processing an earlier response with the same ID",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb), msgid,
			     ike->sa.st_state->short_name);
		return;
	}

	/*
	 * XXX: Just to be sure.  This should be completely redundant
	 * as above assures below!?!
	 *
	 * While the larval IKE SA is getting ready, .sent==-1,
	 * .recv==-1, and .wip==0.  Once the message is sent,
	 * .sent==0, .recv==-1, and .wip==-1.
	 */

	if (ike->sa.st_v2_msgid_windows.initiator.sent != 0 ||
	    ike->sa.st_v2_msgid_windows.initiator.wip != -1 ||
	    ike->sa.st_v2_msgid_windows.initiator.recv != -1) {
		/* windows don't seem right */
		name_buf xb;
		llog_pexpect(ike->sa.logger, HERE,
			     "dropping %s response with Message ID %jd, IKE SA in state %s has strange Message IDs",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb), msgid,
			     ike->sa.st_state->short_name);
		return;
	}

	/*
	 * XXX: Probably made redundant by v2_exchange above, but no
	 * harm.
	 */
	if (ike->sa.st_state != &state_v2_IKE_SA_INIT_I &&
	    ike->sa.st_state != &state_v2_IKE_SESSION_RESUME_I) {
		name_buf xb;
		limited_llog(ike->sa.logger, UNSECURED_LOG_LIMITER,
			     "dropping %s response with Message ID %jd, IKE SA is in state %s",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb), msgid,
			     ike->sa.st_state->short_name);
		return;
	}

	ldbg(ike->sa.logger, "unpacking clear payloads");
	md->message_payloads = ikev2_decode_payloads(ike->sa.logger, md,
						     &md->message_pbs,
						     md->hdr.isa_np);
	if (md->message_payloads.n != v2N_NOTHING_WRONG) {
		/* already logged */
		return;
	}

	/* transition? */
	const struct v2_transition *transition = NULL;
	diag_t d = find_v2_unsecured_response_transition(ike, md, &transition);
	if (transition == NULL) {
		lset_t rc_flags = log_limiter_rc_flags(ike->sa.logger, PAYLOAD_ERRORS_LOG_LIMITER);
		if (rc_flags != LEMPTY) {
			llog(rc_flags, ike->sa.logger, "ignoring %s", str_diag(d));
		}
		pfree_diag(&d);
		return;
	}

	statetime_t start = statetime_backdate(&ike->sa, &md->md_inception);
	v2_dispatch(ike, md, transition);
	statetime_stop(&start, "%s()", __func__);
	return;
}

void process_v2_UNSECURED_message(struct msg_digest *md)
{
	/*
	 * The message ID of the initial exchange is always
	 * zero.
	 */
	if (md->hdr.isa_msgid != 0) {
		llog_md(md, "IKE_SA_INIT message has non-zero message ID; dropping packet");
		return;
	}
	/*
	 * Now try to find the state
	 */
	switch (v2_msg_role(md)) {

	case MESSAGE_REQUEST:
		process_v2_UNSECURED_request(md);
		break;

	case MESSAGE_RESPONSE:
		process_v2_UNSECURED_response(md);
		break;

	default:
		bad_case(v2_msg_role(md));
	}

}

V2_STATE(UNSECURED_R,
	 "larval unsecured IKE SA responder",
	 CAT_HALF_OPEN_IKE_SA, /*secured*/false,
	 &v2_IKE_SA_INIT_exchange, &v2_IKE_SESSION_RESUME_exchange);
