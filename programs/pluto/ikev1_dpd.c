/*
 * IPsec IKE Dead Peer Detection / Liveness code.
 *
 * Copyright (C) 2003 Ken Bantoft        <ken@xelerance.com>
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 FURUSO Shinichi <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Andrey Alexandrenko <aalexandrenko@telco-tech.de>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2015 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2016 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>


#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "server.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "whack.h"
#include "ip_address.h"
#include "pending.h" /* for flush_pending_by_connection */

#include "ikev1_dpd.h"
#include "pluto_x509.h"

#include "pluto_stats.h"

/*
 * Initialize RFC 3706 Dead Peer Detection
 *
 * @param st An initialized state structure
 * @return void
 *
 * How DPD works.
 *
 * There are two kinds of events that can be scheduled.
 * At most one of them is schedule at any given time.
 *
 * The EVENT_DPD_TIMEOUT event, if it ever goes off, means that
 * neither the ISAKMP SA nor the IPsec SA has *RECEIVED* any DPD
 * events lately.
 *
 * 0) So, every time we receive a DPD (R_U_THERE or R_U_ACK), then
 *    we delete any DPD event (EVENT_DPD or EVENT_DPD_TIMEOUT), and
 *    we schedule a new DPD_EVENT (sending) for "delay" in the future.
 *
 * 1) When the DPD_EVENT goes off, we check the phase 2 (if there is one)
 *    SA to see if there was incoming traffic. If there was, then we are happy,
 *    we set a new DPD_EVENT, and we are done.
 *
 * 2) If there was no phase 2 activity, we check if there was a recent enough
 *    DPD activity (st->st_last_dpd). If so, we just reschedule, and do
 *    nothing.
 *
 * 3) Otherwise, we send a DPD R_U_THERE message, and set the
 *    EVENT_DPD_TIMEOUT on the phase 1.
 *
 * One thing to realize when looking at "ipsec whack --listevents" output,
 * is there there will only be DPD_EVENT_TIMEOUT events if there are
 * outstanding R_U_THERE messages.
 *
 * The above is the basic idea, but things are a bit more complicated because
 * multiple phase 2s can share the same phase 1 ISAKMP SA. Each phase 2 state
 * has its own DPD_EVENT.
 *
 * The st_last_dpd member that is used is always the one from the phase 1.
 * So, if there are multiple phase 2s, then if any of them receive DPD data
 * they will update the st_last_dpd, so the test in #2 will avoid the traffic
 * for all by one phase 2.
 *
 * Note that the EVENT_DPD are attached to phase 2s (typically), while the
 * EVENT_DPD_TIMEOUT are attached to phase 1s only.
 *
 * Finally, if the connection is using NAT-T, then we ignore the phase 2
 * activity check, because in the case of a unidirectional stream (VoIP for
 * a conference call, for instance), we may not send enough traffic to keep
 * the NAT port mapping valid.
 *
 */

stf_status dpd_init(struct state *st)
{
	bool peer_supports_dpd = st->hidden_variables.st_peer_supports_dpd;
	bool want_dpd = dpd_active_locally(st);

	if (IS_IKE_SA(st)) { /* so we log this only once */
		dbg("DPD: dpd_init() called on ISAKMP SA");

		if (!peer_supports_dpd) {
			dbg("DPD: Peer does not support Dead Peer Detection");
			if (want_dpd)
				log_state(RC_LOG_SERIOUS, st,
					  "Configured DPD (RFC 3706) support not enabled because remote peer did not advertise DPD support");
			return STF_OK;
		} else {
			dbg("DPD: Peer supports Dead Peer Detection");
		}

		if (!want_dpd) {
			dbg("DPD: not initializing DPD because DPD is disabled locally");
			return STF_OK;
		}
	} else {
		dbg("DPD: dpd_init() called on IPsec SA");
		if (!peer_supports_dpd || !want_dpd) {
			dbg("DPD: Peer does not support Dead Peer Detection");
			return STF_OK;
		}

		/* find the IKE SA */
		struct state *p1st = find_state_ikev1(&st->st_ike_spis, 0);
		if (p1st == NULL) {
			log_state(RC_LOG_SERIOUS, st,
				  "could not find phase 1 state for DPD");
			return STF_FAIL;
		}

		if (st->st_dpd_event == NULL || ev_before(st->st_dpd_event,
			st->st_connection->dpd_delay))
		{
			event_delete(EVENT_DPD, st);
			event_schedule(EVENT_DPD, st->st_connection->dpd_delay, st);
		}
	}
	return STF_OK;
}

/*
 * Only schedule a new timeout if there isn't one currently,
 * or if it would be sooner than the current timeout.
 */
static void dpd_sched_timeout(struct state *p1st, monotime_t nw, deltatime_t timeout)
{
	passert(deltasecs(timeout) > 0);
	if (p1st->st_dpd_event == NULL ||
	    monobefore(monotime_add(nw, timeout), p1st->st_dpd_event->ev_time)) {
		dbg("DPD: scheduling timeout to %jd", deltasecs(timeout));
		event_delete(EVENT_DPD, p1st);
		event_schedule(EVENT_DPD_TIMEOUT, timeout, p1st);
	}
}

/**
 * DPD Out Initiator
 *
 * @param p2st A state struct that is already in phase2
 * @return void
 */
static void dpd_outI(struct state *p1st, struct state *st, bool eroute_care,
		     deltatime_t delay, deltatime_t timeout)
{
	uint32_t seqno;

	connection_buf cib;
	dbg("DPD: processing for state #%lu ("PRI_CONNECTION")",
	    st->st_serialno, pri_connection(st->st_connection, &cib));

	/* if peer doesn't support DPD, DPD should never have started */
	pexpect(st->hidden_variables.st_peer_supports_dpd);	/* ??? passert? */
	if (!st->hidden_variables.st_peer_supports_dpd) {
		dbg("DPD: peer does not support dpd");
		return;
	}

	/* If there is no IKE state, there can be no DPD */
	pexpect(IS_ISAKMP_SA_ESTABLISHED(p1st->st_state));	/* ??? passert? */
	if (!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state)) {
		dbg("DPD: no phase1 state, so no DPD");
		return;
	}

	/* find out when now is */
	monotime_t nw = mononow();

	/*
	 * pick least recent activity value, since with multiple phase 2s,
	 * it may well be that one phase 2 is very active, while the other
	 * for some reason, gets stomped upon by some network screw up.
	 *
	 * (this would only happen if the network was sensitive to different
	 *  SPI#, since for NAT-T, all traffic should be on the same UDP port.
	 *  At worst, this means that we send a bit more traffic then we need
	 *  to when there are multiple SAs and one is much less active.
	 *
	 * ??? the code actually picks the most recent.  So much for comments.
	 */
	monotime_t last = !monobefore(p1st->st_last_dpd, st->st_last_dpd) ?
		p1st->st_last_dpd : st->st_last_dpd;

	monotime_t next_time = monotime_add(last, delay);
	deltatime_t next_delay = monotimediff(next_time, nw);

	/* has there been enough activity of late? */
	if (deltatime_cmp(next_delay, >, deltatime(0))) {
		/* Yes, just reschedule "phase 2" */
		monotime_buf mb1, mb2;
		dbg("DPD: not yet time for dpd event: %s < %s",
		    str_monotime(nw, &mb1),
		    str_monotime(next_time, &mb2));
		event_schedule(EVENT_DPD, next_delay, st);
		return;
	}

	next_delay = delay;

	/*
	 * check the phase 2, if we are supposed to,
	 * and return if it is active recently
	 */
	if (eroute_care && st->hidden_variables.st_nat_traversal == LEMPTY &&
			!was_eroute_idle(st, delay))
	{
		dbg("DPD: out event not sent, phase 2 active");

		/* update phase 2 time stamp only */
		st->st_last_dpd = nw;

		/*
		 * Since there was activity, kill any EVENT_DPD_TIMEOUT that might
		 * be waiting. This can happen when a R_U_THERE_ACK is lost, and
		 * subsequently traffic started flowing over the SA again, and no
		 * more DPD packets are sent to cancel the outstanding DPD timer.
		 */
		if (p1st->st_dpd_event != NULL &&
		    p1st->st_dpd_event->ev_type == EVENT_DPD_TIMEOUT) {
			dbg("DPD: deleting p1st DPD event");
			event_delete(EVENT_DPD, p1st);
		}

		event_schedule(EVENT_DPD, next_delay, st);
		return;
	}

	if (st != p1st) {
		/*
		 * reschedule next event, since we cannot do it from the activity
		 * routine.
		 */
		event_schedule(EVENT_DPD, next_delay, st);
	}

	if (p1st->st_dpd_seqno == 0) {
		/* Get a non-zero random value that has room to grow */
		get_rnd_bytes((uint8_t *)&p1st->st_dpd_seqno,
			      sizeof(p1st->st_dpd_seqno));
		p1st->st_dpd_seqno &= 0x7fff;
		p1st->st_dpd_seqno++;
	}
	seqno = htonl(p1st->st_dpd_seqno);

	/* make sure that the timeout occurs. We do this before the send,
	 * because the send may fail due to network issues, etc, and
	 * the timeout has to occur anyway
	 */
	dpd_sched_timeout(p1st, nw, timeout);

	endpoint_buf b;
	dbg("DPD: sending R_U_THERE %u to %s (state #%lu)",
	    p1st->st_dpd_seqno,
	    str_endpoint(&p1st->st_remote_endpoint, &b),
	    p1st->st_serialno);

	if (send_isakmp_notification(p1st, R_U_THERE,
				     &seqno, sizeof(seqno)) != STF_IGNORE) {
		log_state(RC_LOG_SERIOUS, st,
			  "DPD: could not send R_U_THERE");
		return;
	}

	st->st_last_dpd = nw;
	p1st->st_last_dpd = nw;
	p1st->st_dpd_expectseqno = p1st->st_dpd_seqno++;
	pstats_ike_dpd_sent++;
}

static void p1_dpd_outI1(struct state *p1st)
{
	deltatime_t delay = p1st->st_connection->dpd_delay;
	deltatime_t timeout = p1st->st_connection->dpd_timeout;

	dpd_outI(p1st, p1st, TRUE, delay, timeout);
}

static void p2_dpd_outI1(struct state *p2st)
{
	struct state *st;
	deltatime_t delay = p2st->st_connection->dpd_delay;
	deltatime_t timeout = p2st->st_connection->dpd_timeout;

	st = find_phase1_state(p2st->st_connection,
		ISAKMP_SA_ESTABLISHED_STATES);

	if (st == NULL) {
		log_state(RC_LOG_SERIOUS, p2st,
			  "DPD: could not find newest phase 1 state - initiating a new one");
		liveness_action(p2st);
		return;
	}

	if (st->st_connection->newest_ipsec_sa != p2st->st_serialno) {
		dbg("DPD: no need to send or schedule DPD for replaced IPsec SA");
		return;
	}

	dpd_outI(st, p2st, TRUE, delay, timeout);
}

void dpd_event(struct state *st)
{
	passert(st != NULL);


	if (IS_PHASE1(st->st_state->kind) || IS_PHASE15(st->st_state->kind))
		p1_dpd_outI1(st);
	else
		p2_dpd_outI1(st);
}

/**
 * DPD in Initiator, out Responder
 *
 * @param st A state structure (the phase 1 state)
 * @param n A notification (isakmp_notification)
 * @param pbs A PB Stream
 * @return stf_status
 */
stf_status dpd_inI_outR(struct state *p1st,
			struct isakmp_notification *const n,
			pb_stream *pbs)
{
	monotime_t nw = mononow();
	uint32_t seqno;

	if (!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state)) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: received R_U_THERE for unestablished ISKAMP SA");
		return STF_IGNORE;
	}
	if (n->isan_spisize != COOKIE_SIZE * 2 ||
	    pbs_left(pbs) < COOKIE_SIZE * 2) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: R_U_THERE has invalid SPI length (%d)",
			  n->isan_spisize);
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	if (!memeq(pbs->cur, p1st->st_ike_spis.initiator.bytes, COOKIE_SIZE)) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		dbg("DPD: R_U_THERE has invalid icookie (tolerated)");
	}
	pbs->cur += COOKIE_SIZE;

	if (!memeq(pbs->cur, p1st->st_ike_spis.responder.bytes, COOKIE_SIZE)) {
		dbg("DPD: R_U_THERE has invalid rcookie (tolerated)");
	}
	pbs->cur += COOKIE_SIZE;

	if (pbs_left(pbs) != sizeof(seqno)) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: R_U_THERE has invalid data length (%d)",
			  (int) pbs_left(pbs));
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	seqno = ntohl(*(uint32_t *)pbs->cur);
	if (p1st->st_dpd_peerseqno && seqno <= p1st->st_dpd_peerseqno) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: received old or duplicate R_U_THERE");
		if (p1st->st_dpd_rdupcount >= DPD_RETRANS_MAX) {
			log_state(RC_LOG_SERIOUS, p1st,
				  "DPD: received %d or more duplicate R_U_THERE's - will no longer answer",
				  DPD_RETRANS_MAX);
			return STF_IGNORE;
		} else {
			/*
			 * Needed to work around openbsd bug (isakmpd/dpd.c
			 * around line 350) where they forget to increase
			 * isakmp_sa->dpd_seq on unanswered DPD probe violating
			 * RFC 3706 Section 7 "Security Considerations"
			 */
			log_state(RC_LOG_SERIOUS, p1st,
				  "DPD: received less than %d duplicate R_U_THERE's - will reluctantly answer",
				  DPD_RETRANS_MAX);
			p1st->st_dpd_rdupcount++;
		}
	} else {
		p1st->st_dpd_rdupcount = 0;
	}

	monotime_buf nwb;
	connection_buf cib;
	dbg("DPD: received R_U_THERE seq:%u monotime: %s (state=#%lu name="PRI_CONNECTION")",
	    seqno, str_monotime(nw, &nwb),
	    p1st->st_serialno,
	    pri_connection(p1st->st_connection, &cib));

	p1st->st_dpd_peerseqno = seqno;

	if (send_isakmp_notification(p1st, R_U_THERE_ACK,
				     pbs->cur, pbs_left(pbs)) != STF_IGNORE) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: could not send R_U_THERE_ACK");
		return STF_IGNORE;
	}

	/* update the time stamp */
	p1st->st_last_dpd = nw;

	pstats_ike_dpd_replied++;

	/*
	 * since there was activity, kill any EVENT_DPD_TIMEOUT that might
	 * be waiting.
	 */
	if (p1st->st_dpd_event != NULL &&
	    p1st->st_dpd_event->ev_type == EVENT_DPD_TIMEOUT)
		event_delete(EVENT_DPD, p1st);

	return STF_IGNORE;
}

/**
 * DPD out Responder
 *
 * @param st A state structure (phase 1)
 * @param n A notification (isakmp_notification)
 * @param pbs A PB Stream
 * @return stf_status
 */
stf_status dpd_inR(struct state *p1st,
		   struct isakmp_notification *const n,
		   pb_stream *pbs)
{
	uint32_t seqno;

	if (!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state)) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: received R_U_THERE_ACK for unestablished ISKAMP SA");
		return STF_FAIL;
	}

	if (n->isan_spisize != COOKIE_SIZE * 2 ||
	    pbs_left(pbs) < COOKIE_SIZE * 2) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: R_U_THERE_ACK has invalid SPI length (%d)",
			  n->isan_spisize);
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	if (!memeq(pbs->cur, p1st->st_ike_spis.initiator.bytes, COOKIE_SIZE)) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		dbg("DPD: R_U_THERE_ACK has invalid icookie");
	}
	pbs->cur += COOKIE_SIZE;

	if (!memeq(pbs->cur, p1st->st_ike_spis.responder.bytes, COOKIE_SIZE)) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		dbg("DPD: R_U_THERE_ACK has invalid rcookie");
	}
	pbs->cur += COOKIE_SIZE;

	if (pbs_left(pbs) != sizeof(seqno)) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: R_U_THERE_ACK has invalid data length (%d)",
			  (int) pbs_left(pbs));
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	seqno = ntohl(*(uint32_t *)pbs->cur);
	dbg("DPD: R_U_THERE_ACK, seqno received: %u expected: %u (state=#%lu)",
	    seqno, p1st->st_dpd_expectseqno, p1st->st_serialno);

	if (seqno == p1st->st_dpd_expectseqno) {
		/* update the time stamp */
		p1st->st_last_dpd = mononow();
		p1st->st_dpd_expectseqno = 0;
	} else if (!p1st->st_dpd_expectseqno) {
		log_state(RC_LOG_SERIOUS, p1st,
			  "DPD: unexpected R_U_THERE_ACK packet with sequence number %u",
			  seqno);
		/* do not update time stamp, so we'll send a new one sooner */
	}

	pstats_ike_dpd_recv++;

	/*
	 * since there was activity, kill any EVENT_DPD_TIMEOUT that might
	 * be waiting.
	 */
	if (p1st->st_dpd_event != NULL &&
	    p1st->st_dpd_event->ev_type == EVENT_DPD_TIMEOUT)
		event_delete(EVENT_DPD, p1st);

	return STF_IGNORE;
}

/**
 * DPD Timeout Function
 *
 * This function is called when a timeout DPD_EVENT occurs.  We set clear/trap
 * both the SA and the eroutes, depending on what the connection definition
 * tells us (either 'hold' or 'clear')
 *
 * @param st A state structure that is fully negotiated
 * @return void
 */
void dpd_timeout(struct state *st)
{
	liveness_action(st);
}
