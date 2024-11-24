/* IKEv2 LIVENESS probe
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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
#include "log.h"
#include "connections.h"
#include "iface.h"
#include "kernel.h"
#include "ikev2_informational.h"
#include "pluto_stats.h"
#include "timer.h"
#include "server.h"
#include "ikev2.h"			/* for struct v2_transition */
#include "ikev2_liveness.h"
#include "ikev2_states.h"
#include "demux.h"			/* for v2_msg_role() */
#include "ikev2_mobike.h"		/* for mobike_possibly_send_recorded() */

static ikev2_state_transition_fn initiate_v2_INFORMATIONAL_liveness_request;
static ikev2_state_transition_fn process_v2_INFORMATIONAL_liveness_request;
static ikev2_state_transition_fn process_v2_INFORMATIONAL_liveness_response;

void submit_v2_liveness_exchange(struct ike_sa *ike, so_serial_t who_for)
{
	const struct v2_exchange *exchange = &v2_INFORMATIONAL_liveness_exchange;
	if (!v2_ike_sa_can_initiate_exchange(ike, exchange)) {
		llog_sa(RC_LOG, ike,
			"liveness: IKE SA in state %s but should be in state ESTABLISHED_IKE_SA; liveness for "PRI_SO" ignored",
			ike->sa.st_state->short_name,
			pri_so(who_for));
		return;
	}

	pexpect(exchange->initiate.transition->exchange == ISAKMP_v2_INFORMATIONAL);
	v2_msgid_queue_exchange(ike, NULL, exchange);
}

static void schedule_liveness(struct child_sa *child, deltatime_t time_since_last_contact,
			      const char *reason)
{
	struct connection *c = child->sa.st_connection;
	deltatime_t delay = c->config->dpd.delay;
	/*
	 * Wait DELAY from the time of the last contact; not NOW.
	 * Which means DELAY is reduced.  But don't be too frequent.
	 */
	delay = deltatime_sub(delay, time_since_last_contact);
	delay = deltatime_max(delay, deltatime(MIN_LIVENESS));
	LDBGP_JAMBUF(DBG_BASE, child->sa.logger, buf) {
		deltatime_buf db;
		endpoint_buf remote_buf;
		jam(buf, "liveness: #%lu scheduling next check for %s in %s seconds",
		    child->sa.st_serialno,
		    str_endpoint(&child->sa.st_remote_endpoint, &remote_buf),
		    str_deltatime(delay, &db));
		if (deltatime_cmp(time_since_last_contact, !=, deltatime(0))) {
			deltatime_buf lcb;
			jam(buf, " (%s was %s seconds ago)",
			    reason, str_deltatime(time_since_last_contact, &lcb));
		} else {
			jam(buf, " (%s)", reason);
		}
	}
	event_schedule(EVENT_v2_LIVENESS, delay, &child->sa);
}

static bool recent_last_contact(struct child_sa *child,
				deltatime_t time_since_last_contact,
				const char *reason)
{
	/*
	 * Add MIN_LIVENESS (probably 1) of fuzz so that anything
	 * close to DELAY doesn't cause a re-schedule.
	 */
	deltatime_t fuzz_since_last_contact = deltatime_add(time_since_last_contact,
							    deltatime(MIN_LIVENESS));
	LDBGP_JAMBUF(DBG_BASE, child->sa.logger, buf) {
		jam_string(buf, "time_since_last_contact=");
		jam_deltatime(buf, time_since_last_contact);
		jam_string(buf, " -> ");
		jam_string(buf, "fuzz_since_last_contact=");
		jam_deltatime(buf, fuzz_since_last_contact);
	}

	if (deltatime_cmp(fuzz_since_last_contact, <, child->sa.st_connection->config->dpd.delay)) {
		/*
		 * Too little time has passed since the last contact
		 * (i.e., too small); schedule a new liveness check.
		 */
		schedule_liveness(child, time_since_last_contact, reason);
		return true;
	}
	return false;
}

/*
 * The RFC (2.4.  State Synchronization and Connection Timeouts) as
 * this to say:
 *
 *   To be a good network citizen, retransmission times MUST increase
 *   exponentially to avoid flooding the network and making an
 *   existing congestion situation worse.  If there has only been
 *   outgoing traffic on all of the SAs associated with an IKE SA, it
 *   is essential to confirm liveness of the other endpoint to avoid
 *   black holes.  If no cryptographically protected messages have
 *   been received on an IKE SA or any of its Child SAs recently, the
 *   system needs to perform a liveness check in order to prevent
 *   sending messages to a dead peer.  (This is sometimes called "dead
 *   peer detection" or "DPD", although it is really detecting live
 *   peers, not dead ones.)  Receipt of a fresh cryptographically
 *   protected message on an IKE SA or any of its Child SAs ensures
 *   liveness of the IKE SA and all of its Child SAs.
 *
 * However:
 *
 * Only checking incoming packets does not demonstrate liveness.  Just
 * that half the channel is working.  All the incoming packets could
 * be retransmits.
 *
 * note: this mutates *st by calling get_sa_bundle_info
 */

void event_v2_liveness(struct state *st)
{
	const monotime_t now = mononow();

	passert(st->st_ike_version == IKEv2);
	struct ike_sa *ike = ike_sa(st, HERE);
	if (ike == NULL) {
		/* already logged */
		dbg("liveness: state #%lu has no IKE SA; deleting orphaned child",
		    st->st_serialno);
		event_force(EVENT_v2_DISCARD, st);
		return;
	}
	struct child_sa *child = pexpect_child_sa(st);
	if (child == NULL) {
		return;
	}

	struct connection *c = child->sa.st_connection;

	/*
	 * If the child is lingering (replaced but not yet deleted),
	 * don't do liveness.
	 */
	if (c->established_child_sa != child->sa.st_serialno) {
		dbg("liveness: #%lu was replaced by #%lu so not needed",
		    child->sa.st_serialno, c->established_child_sa);
		return;
	}

	/*
	 * If the IKE SA is waiting for a response to it's last
	 * request, reschedule the liveness probe.
	 *
	 * If the exchange succeeds, there's been a round trip and
	 * things are alive.
	 *
	 * If the exchange fails, liveness will be triggered.
	 */
	if (v2_msgid_request_outstanding(ike)) {
		schedule_liveness(child, /*time-since-last-exchange*/deltatime(0),
				  "request outstanding");
		return;
	}

	/*
	 * If the IKE SA has a request outstanding, reschedule the
	 * liveness probe.
	 *
	 * For instance, the last exchange list finished, and the next
	 * exchange is about to start.  If that exchange fails
	 * liveness will be triggered.
	 */
	if (v2_msgid_request_pending(ike)) {
		schedule_liveness(child, /*time-since-last-exchange*/deltatime(0),
				  "request pending");
		return;
	}

	/*
	 * If this IKE SA recently completed an exchange, reschedule
	 * the liveness probe.
	 *
	 * Since this end initiated the exchange and got a response, a
	 * recent round-trip probe worked.
	 */
	struct v2_msgid_window *our = &ike->sa.st_v2_msgid_windows.initiator;
	pexpect(!is_monotime_epoch(our->last_recv));
	if (recent_last_contact(child, monotimediff(now, our->last_recv),
				"successful exchange")) {
		return;
	}

	/*
	 * If this IKE SA recently received a new message request from
	 * the peer, reschedule the liveness probe.
	 *
	 * The arrival of a new message request #N can only happen
	 * (ignoring mobike) once the peer has received our response
	 * to the previous message request #N-1.
	 *
	 * The only issue is that while the PEER->US message was
	 * recent, the US->PEER message could be ancient.  Not to
	 * worry, the next liveness check will pick this up.  The
	 * alternative is to save second-last-contact and use that.
	 *
	 * The more likely scenario is that the other end is
	 * constantly sending liveness probes so this end can skip
	 * them.
	 */
	struct v2_msgid_window *peer = &ike->sa.st_v2_msgid_windows.responder;
	if (recent_last_contact(child, monotimediff(now, peer->last_recv),
				"peer contact")) {
		return;
	}

	/*
	 * If there's been recent traffic flowing in through the CHILD
	 * SA and it was less than .dpd_delay ago then re-schedule the
	 * probe.
	 *
	 * Per above, the RFC says:
	 *
	 *   If no cryptographically protected messages have been
	 *   received on ... Child SAs recently,
	 *
	 * XXX: But is this useful?  Liveness should be checking
	 * round-trip but this is just looking at incoming data -
	 * outgoing data could lost and this traffic is all
	 * re-transmit requests ...
 	 */

	struct ipsec_proto_info *const first_ipsec_proto =
		(child->sa.st_esp.protocol == &ip_protocol_esp ? &child->sa.st_esp :
		 child->sa.st_ah.protocol == &ip_protocol_ah ? &child->sa.st_ah :
		 child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? &child->sa.st_ipcomp :
		 NULL);
	if (get_ipsec_traffic(child, first_ipsec_proto, DIRECTION_INBOUND)) {
		deltatime_t since =
			realtimediff(realnow(), first_ipsec_proto->inbound.last_used);
		if (recent_last_contact(child, since, "recent IPsec traffic")) {
			return;
		}
	}

	endpoint_buf remote_buf;
	dbg("liveness: #%lu queueing liveness probe for %s using #%lu",
	    child->sa.st_serialno,
	    str_endpoint(&child->sa.st_remote_endpoint, &remote_buf),
	    ike->sa.st_serialno);
	submit_v2_liveness_exchange(ike, child->sa.st_serialno);

	/* in case above screws up? */
	schedule_liveness(child, /*time-since-last-exchange*/deltatime(0),
			  "backup for liveness probe");
}

stf_status initiate_v2_INFORMATIONAL_liveness_request(struct ike_sa *ike,
						      struct child_sa *child,
						      struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, child == NULL);
	PEXPECT(ike->sa.logger, md == NULL);

	pstats_ike_dpd_sent++;
	if (!record_v2_INFORMATIONAL_request("liveness probe informational request",
					     ike->sa.logger, ike, /*child*/NULL,
					     NULL/*no payloads to emit*/)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

stf_status process_v2_INFORMATIONAL_liveness_request(struct ike_sa *ike,
							    struct child_sa *child,
							    struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, child == NULL);

	ldbg(ike->sa.logger, "received an INFORMATIONAL liveness check request");
	pstats_ike_dpd_replied++;

	/*
	 * Expect an empty message; as matched by transition.
	 */
	PEXPECT(ike->sa.logger, md->chain[ISAKMP_NEXT_v2SK]->payload.v2gen.isag_np == ISAKMP_NEXT_NONE);

	/*
	 * The response is always empty.
	 */
	if (!record_v2_INFORMATIONAL_response("liveness response",
					      ike->sa.logger,
					      ike, /*child*/NULL, md,
					      /*emit-function*/NULL)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * If the source port isn't as expected, and mobike is
	 * enabled, also send the liveness probe back to the alternate
	 * port.
	 *
	 * The RFC, in <<3.5.  Changing Addresses in IPsec SAs>> says
	 * that the initiator:
	 *
	 *    o Updates the IKE_SA with the new addresses, and sets
	 *      the "pending_update" flag in the IKE_SA.
	 *
	 *    o If there are outstanding IKEv2 requests (requests for
	 *      which the initiator has not yet received a reply),
	 *      continues retransmitting them using the addresses in
	 *      the IKE_SA (the new addresses).
	 *
	 * Which means that the peer sending a liveness probe from an
	 * old and failed interface may switch and send the same
	 * liveness probe from the new working interface and expect a
	 * response to be sent back to same.
	 *
	 * This tries to handle this.
	 */
	mobike_possibly_send_recorded(ike, md);

	return STF_OK;
}

stf_status process_v2_INFORMATIONAL_liveness_response(struct ike_sa *ike,
						      struct child_sa *null_child,
						      struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_RESPONSE);
	PEXPECT(ike->sa.logger, null_child == NULL);

	ldbg(ike->sa.logger, "received an INFORMATIONAL liveness check response");
	pstats_ike_dpd_recv++;
	return STF_OK;
}

/*
 * The exchange.
 */

static const struct v2_transition v2_INFORMATIONAL_liveness_initiate_transition = {
	.story = "liveness probe",
	.to = &state_v2_ESTABLISHED_IKE_SA,
	.exchange = ISAKMP_v2_INFORMATIONAL,
	.processor = initiate_v2_INFORMATIONAL_liveness_request,
	.llog_success = ldbg_v2_success, /* shhh, don't clutter up logs with LIVENESS */
	.timeout_event =  EVENT_RETAIN,
};

static const struct v2_transition v2_INFORMATIONAL_liveness_responder_transition[] = {
	{ .story      = "Informational Request (liveness probe)",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .exchange   = ISAKMP_v2_INFORMATIONAL,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  /* strictly match empty message */
	  .encrypted_payloads.exact_match = true,
	  .encrypted_payloads.optional = LEMPTY,
	  .encrypted_payloads.required = LEMPTY,
	  .processor  = process_v2_INFORMATIONAL_liveness_request,
	  .llog_success = ldbg_v2_success, /* shhh, don't clutter up logs with LIVENESS */
	  .timeout_event = EVENT_RETAIN, },
};

static const struct v2_transitions v2_INFORMATIONAL_liveness_responder_transitions = {
	ARRAY_REF(v2_INFORMATIONAL_liveness_responder_transition),
};

static const struct v2_transition v2_INFORMATIONAL_liveness_response_transition[] = {
	{ .story      = "Informational Response (liveness probe)",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags = { .release_whack = true, },
	  .exchange   = ISAKMP_v2_INFORMATIONAL,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(SK),
	  .processor  = process_v2_INFORMATIONAL_liveness_response,
	  .llog_success = ldbg_v2_success, /* shhh, don't clutter up logs with LIVENESS */
	  .timeout_event = EVENT_RETAIN, },
};

static const struct v2_transitions v2_INFORMATIONAL_liveness_response_transitions = {
	ARRAY_REF(v2_INFORMATIONAL_liveness_response_transition),
};

const struct v2_exchange v2_INFORMATIONAL_liveness_exchange = {
	.type = ISAKMP_v2_INFORMATIONAL,
	.subplot = "liveness probe",
	.secured = true,
	.initiate.from = { &state_v2_ESTABLISHED_IKE_SA, },
	.initiate.transition = &v2_INFORMATIONAL_liveness_initiate_transition,
	.responder = &v2_INFORMATIONAL_liveness_responder_transitions,
	.response = &v2_INFORMATIONAL_liveness_response_transitions,
};
