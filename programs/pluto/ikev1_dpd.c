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
#include "demux.h"      /* needs packet.h */
#include "kernel.h"     /* needs connections.h */
#include "routing.h"
#include "log.h"
#include "server.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "whack.h"
#include "ip_address.h"
#include "pending.h" /* for flush_pending_by_connection */
#include "ikev1.h"			/* for established_isakmp_for_state() */
#include "ikev1_dpd.h"
#include "pluto_x509.h"
#include "ikev1_delete.h"
#include "pluto_stats.h"
#include "ikev1_msgid.h"
#include "ikev1_hash.h"
#include "ikev1_message.h"
#include "send.h"

static stf_status send_dpd_notification(struct ike_sa *ike,
					uint16_t type, const void *data,
					size_t len);

/**
 * DPD Timeout Function
 *
 * This function is called when a timeout DPD_EVENT occurs.  We set
 * clear/trap both the SA and the eroutes, depending on what the
 * connection definition tells us (either 'hold' or 'clear')
 *
 * Delete all states that were created for a given connection.
 *
 * In addition to the currently established Child/IKE SAs, this will
 * also clean up larval and dying State.
 *
 * @param st A state structure that is fully negotiated
 * @return void
 */

void event_v1_dpd_timeout(struct state *tbd_st)
{
	/*
	 * So that the logger is valid after TBD_ST's been deleted,
	 * create a clone of TBD_ST's logger and kill the TBD_ST
	 * pointer.
	 */
	struct logger *logger = clone_logger(tbd_st->logger, HERE);
	struct connection *c = connection_addref(tbd_st->st_connection, logger);

	tbd_st = NULL; /* kill TBD_ST; can no longer be trusted */
	llog(RC_LOG, logger, "DPD action - putting connection into hold");

	/*
	 * IKEv1 needs children to be deleted before the parent;
	 * otherwise the child has no way to send its delete message.
	 */

	/*
	 * If the connection has an (established) ISAKMP SA, then use
	 * that to find any siblings of TBD_ST.
	 *
	 * Of course this assumes that .established_ike_sa is set.
	 */

	struct ike_sa *ike = ike_sa_by_serialno(c->established_ike_sa);
	if (ike != NULL) {
		pdbg(ike->sa.logger, "no longer viable");
		ike->sa.st_viable_parent = false; /*needed?*/
		struct state_filter sf = {
			.clonedfrom = ike->sa.st_serialno,
			.search = {
				.order = NEW2OLD,
				.verbose.logger = &global_logger,
				.where = HERE,
			},
		};
		while (next_state(&sf)) {
			struct child_sa *child = pexpect_child_sa(sf.st);
			pdbg(logger, "delete IPsec SA "PRI_SO" which is a sibling",
			     pri_so(child->sa.st_serialno));
			state_attach(&child->sa, logger);
			llog_n_maybe_send_v1_delete(ike, &child->sa, HERE);
			connection_delete_child(&child, HERE);
		}
	}

	/*
	 * Now zap any children.
	 */
	{
		struct state_filter sf = {
			.connection_serialno = c->serialno,
			.search = {
				.order = NEW2OLD,
				.verbose.logger = &global_logger,
				.where = HERE,
			},
		};
		while (next_state(&sf)) {
			/* on first pass, ignore established ISAKMP SA's */
			if (IS_PARENT_SA(sf.st)) {
				continue;
			}
			state_attach(sf.st, logger);
			pdbg(logger,
			     "delete IPsec SA "PRI_SO" which shares the connection",
			     pri_so(sf.st->st_serialno));
			struct ike_sa *isakmp = /* could be NULL */
				established_isakmp_sa_for_state(sf.st, /*viable-parent*/false);
			llog_n_maybe_send_v1_delete(isakmp, sf.st, HERE);
			struct child_sa *child = pexpect_child_sa(sf.st);
			connection_delete_child(&child, HERE);
		}
	}

	/*
	 * Finally zap any parents.
	 */
	{
		struct state_filter sf = {
			.connection_serialno = c->serialno,
			.search = {
				.order = NEW2OLD,
				.verbose.logger = &global_logger,
				.where = HERE,
			},
		};
		while (next_state(&sf)) {
			if (!PEXPECT(logger, IS_PARENT_SA(sf.st))) {
				continue;
			}
			state_attach(sf.st, logger);
			pdbg(logger,
			     "delete ISAKMP SA "PRI_SO" which shares the connection",
			     pri_so(sf.st->st_serialno));
			struct ike_sa *isakmp = /* could be NULL */
				established_isakmp_sa_for_state(sf.st, /*viable-parent*/false);
			llog_n_maybe_send_v1_delete(isakmp, sf.st, HERE);
			struct ike_sa *ike = pexpect_ike_sa(sf.st);
			connection_delete_ike(&ike, HERE);
		}
	}

	connection_delref(&c, logger);
	free_logger(&logger, HERE);
}

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
	bool want_dpd = dpd_active_locally(st->st_connection);

	if (IS_IKE_SA(st)) { /* so we log this only once */
		pdbg(st->logger,
		     "DPD: dpd_init() called on ISAKMP SA");

		if (!peer_supports_dpd) {
			pdbg(st->logger,
			     "DPD: Peer does not support Dead Peer Detection");
			if (want_dpd)
				llog(RC_LOG, st->logger,
				     "Configured DPD (RFC 3706) support not enabled because remote peer did not advertise DPD support");
			return STF_OK;
		} else {
			pdbg(st->logger, "DPD: Peer supports Dead Peer Detection");
		}

		if (!want_dpd) {
			pdbg(st->logger,
			     "DPD: not initializing DPD because DPD is disabled locally");
			return STF_OK;
		}
	} else {
		pdbg(st->logger, "DPD: dpd_init() called on IPsec SA");
		if (!peer_supports_dpd || !want_dpd) {
			pdbg(st->logger, "DPD: Peer does not support Dead Peer Detection");
			return STF_OK;
		}

		/*
		 * See if the IKE (ISAKMP) SA that was used to create
		 * the Child SA is still around.
		 *
		 * If it is then it can be used to send the DPD
		 * message.  If it isn't (for instance peer deleted
		 * it) then this operation is doomed (technically, the
		 * a new ISAKMP can be establish and used, but why
		 * bother).
		 */
		struct ike_sa *p1st = find_v1_isakmp_sa(&st->st_ike_spis);
		if (p1st == NULL) {
			llog(RC_LOG, st->logger,
			     "could not find phase 1 state for DPD");
			return STF_FAIL_v1N;
		}

		if (st->st_v1_dpd_event == NULL ||
		    deltatime_cmp(monotimediff(st->st_v1_dpd_event->ev_time, mononow()),
				  <,
				  st->st_connection->config->dpd.delay)) {
			event_delete(EVENT_v1_DPD, st);
			event_schedule(EVENT_v1_DPD, st->st_connection->config->dpd.delay, st);
		}
	}
	return STF_OK;
}

/*
 * Only schedule a new timeout if there isn't one currently,
 * or if it would be sooner than the current timeout.
 */
static void dpd_sched_timeout(struct ike_sa *p1, const monotime_t now, deltatime_t timeout)
{
	PASSERT(p1->sa.logger, deltasecs(timeout) > 0);
	if (p1->sa.st_v1_dpd_event == NULL ||
	    monotime_cmp(monotime_add(now, timeout), <, p1->sa.st_v1_dpd_event->ev_time)) {
		ldbg_sa(p1, "DPD: scheduling timeout to %jd", deltasecs(timeout));
		event_delete(EVENT_v1_DPD, &p1->sa);
		event_schedule(EVENT_v1_DPD_TIMEOUT, timeout, &p1->sa);
	}
}

/**
 * DPD Out Initiator
 *
 * @param p2st A state struct that is already in phase2
 * @return void
 */
static void dpd_outI(struct ike_sa *p1, struct state *st,
		     deltatime_t delay, deltatime_t timeout)
{
	uint32_t seqno;

	pdbg(st->logger, "DPD: processing");

	/* if peer doesn't support DPD, DPD should never have started */
	if (!PEXPECT(st->logger, st->hidden_variables.st_peer_supports_dpd)) {
		return;
	}

	/* If there is no established P1 state, there can be no DPD */
	if (!PEXPECT(p1->sa.logger, IS_V1_ISAKMP_SA_ESTABLISHED(&p1->sa))) {
		return;
	}

	/* find out when now is */
	const monotime_t now = mononow();

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
	monotime_t last = monotime_max(p1->sa.st_last_dpd, st->st_last_dpd);

	monotime_t next_time = monotime_add(last, delay);
	deltatime_t next_delay = monotimediff(next_time, now);

	/* has there been enough activity of late? */
	if (deltatime_cmp(next_delay, >, deltatime(0))) {
		/* Yes, just reschedule "phase 2" */
		monotime_buf mb1, mb2;
		dbg("DPD: not yet time for dpd event: %s < %s",
		    str_monotime(now, &mb1),
		    str_monotime(next_time, &mb2));
		event_schedule(EVENT_v1_DPD, next_delay, st);
		return;
	}

	next_delay = delay;

	/*
	 * check the phase 2, if we are supposed to,
	 * and return if it is active recently
	 */
	if (st->hidden_variables.st_nat_traversal == LEMPTY &&
	    !was_eroute_idle(pexpect_child_sa(st), delay)) {
		dbg("DPD: out event not sent, phase 2 active");

		/* update phase 2 time stamp only */
		st->st_last_dpd = now;

		/*
		 * Since there was activity, kill any
		 * EVENT_v1_DPD_TIMEOUT that might be waiting. This
		 * can happen when a R_U_THERE_ACK is lost, and
		 * subsequently traffic started flowing over the SA
		 * again, and no more DPD packets are sent to cancel
		 * the outstanding DPD timer.
		 */
		if (p1->sa.st_v1_dpd_event != NULL &&
		    p1->sa.st_v1_dpd_event->ev_type == EVENT_v1_DPD_TIMEOUT) {
			dbg("DPD: deleting p1st DPD event");
			event_delete(EVENT_v1_DPD, &p1->sa);
		}

		event_schedule(EVENT_v1_DPD, next_delay, st);
		return;
	}

	if (st != &p1->sa) {
		/*
		 * Reschedule next event, since we cannot do it from
		 * the activity routine.
		 */
		event_schedule(EVENT_v1_DPD, next_delay, st);
	}

	if (p1->sa.st_dpd_seqno == 0) {
		/* Get a non-zero random value that has room to grow */
		get_rnd_bytes((uint8_t *)&p1->sa.st_dpd_seqno,
			      sizeof(p1->sa.st_dpd_seqno));
		p1->sa.st_dpd_seqno &= 0x7fff;
		p1->sa.st_dpd_seqno++;
	}
	seqno = htonl(p1->sa.st_dpd_seqno);

	/* make sure that the timeout occurs. We do this before the send,
	 * because the send may fail due to network issues, etc, and
	 * the timeout has to occur anyway
	 */
	dpd_sched_timeout(p1, now, timeout);

	endpoint_buf b;
	dbg("DPD: sending R_U_THERE %u to %s (state #%lu)",
	    p1->sa.st_dpd_seqno,
	    str_endpoint(&p1->sa.st_remote_endpoint, &b),
	    p1->sa.st_serialno);

	if (send_dpd_notification(p1, v1N_R_U_THERE,
				  &seqno, sizeof(seqno)) != STF_IGNORE) {
		llog(RC_LOG, st->logger,
		     "DPD: could not send R_U_THERE");
		return;
	}

	st->st_last_dpd = now;
	p1->sa.st_last_dpd = now;
	p1->sa.st_dpd_expectseqno = p1->sa.st_dpd_seqno++;
	pstats_ike_dpd_sent++;
}

static void p1_dpd_outI1(struct ike_sa *p1)
{
	deltatime_t delay = p1->sa.st_connection->config->dpd.delay;
	deltatime_t timeout = p1->sa.st_connection->config->dpd.timeout;

	dpd_outI(p1, &p1->sa, delay, timeout);
}

static void p2_dpd_outI1(struct child_sa *p2)
{
	deltatime_t delay = p2->sa.st_connection->config->dpd.delay;
	deltatime_t timeout = p2->sa.st_connection->config->dpd.timeout;

	struct ike_sa *p1 = established_isakmp_sa_for_state(&p2->sa, /*viable-parent*/true);
	if (p1 == NULL) {
		llog(RC_LOG, p2->sa.logger,
		     "DPD: could not find newest phase 1 state - initiating a new one");
		event_v1_dpd_timeout(&p2->sa);
		return;
	}

	if (p1->sa.st_connection->established_child_sa != p2->sa.st_serialno) {
		pdbg(p1->sa.logger,
		     "DPD: no need to send or schedule DPD for replaced IPsec SA");
		return;
	}

	dpd_outI(p1, &p2->sa, delay, timeout);
}

void event_v1_dpd(struct state *st)
{
	passert(st != NULL);
	if (IS_PARENT_SA(st)) {
		struct ike_sa *p1 = pexpect_parent_sa(st);
		p1_dpd_outI1(p1);
	} else {
		struct child_sa *p2 = pexpect_child_sa(st);
		p2_dpd_outI1(p2);
	}
}

/**
 * DPD in Initiator, out Responder
 *
 * @param st A state structure (the phase 1 state)
 * @param n A notification (isakmp_notification)
 * @param pbs A PB Stream
 * @return stf_status
 */
stf_status dpd_inI_outR(struct state *p1sa,
			struct isakmp_notification *const n,
			struct pbs_in *pbs)
{
	if (!PEXPECT(p1sa->logger, IS_PARENT_SA(p1sa))) {
		return STF_INTERNAL_ERROR;
	}

	struct ike_sa *p1 = pexpect_parent_sa(p1sa);
	const monotime_t now = mononow();

	if (!IS_V1_ISAKMP_SA_ESTABLISHED(&p1->sa)) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: received R_U_THERE for unestablished ISKAMP SA");
		return STF_IGNORE;
	}
	if (n->isan_spisize != COOKIE_SIZE * 2 ||
	    pbs_left(pbs) < COOKIE_SIZE * 2) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: R_U_THERE has invalid SPI length (%d)",
		     n->isan_spisize);
		return STF_FAIL_v1N + v1N_PAYLOAD_MALFORMED;
	}

	if (!memeq(pbs->cur, p1->sa.st_ike_spis.initiator.bytes, COOKIE_SIZE)) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		dbg("DPD: R_U_THERE has invalid icookie (tolerated)");
	}
	pbs->cur += COOKIE_SIZE;

	if (!memeq(pbs->cur, p1->sa.st_ike_spis.responder.bytes, COOKIE_SIZE)) {
		dbg("DPD: R_U_THERE has invalid rcookie (tolerated)");
	}
	pbs->cur += COOKIE_SIZE;

	uint32_t seqno;
	if (pbs_left(pbs) != sizeof(seqno)) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: R_U_THERE has invalid data length (%d)",
		     (int) pbs_left(pbs));
		return STF_FAIL_v1N + v1N_PAYLOAD_MALFORMED;
	}

	seqno = ntohl(*(uint32_t *)pbs->cur);
	if (p1->sa.st_dpd_peerseqno && seqno <= p1->sa.st_dpd_peerseqno) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: received old or duplicate R_U_THERE");
		if (p1->sa.st_dpd_rdupcount >= DPD_RETRANS_MAX) {
			llog(RC_LOG, p1->sa.logger,
			     "DPD: received %d or more duplicate R_U_THERE's - will no longer answer",
			     DPD_RETRANS_MAX);
			return STF_IGNORE;
		}
		/*
		 * Needed to work around openbsd bug (isakmpd/dpd.c
		 * around line 350) where they forget to increase
		 * isakmp_sa->config->dpd.seq on unanswered DPD probe
		 * violating RFC 3706 Section 7 "Security
		 * Considerations"
		 */
		llog(RC_LOG, p1->sa.logger,
		     "DPD: received less than %d duplicate R_U_THERE's - will reluctantly answer",
		     DPD_RETRANS_MAX);
		p1->sa.st_dpd_rdupcount++;

	} else {
		p1->sa.st_dpd_rdupcount = 0;
	}

	monotime_buf nwb;
	connection_buf cib;
	dbg("DPD: received R_U_THERE seq:%u monotime: %s (state=#%lu name="PRI_CONNECTION")",
	    seqno, str_monotime(now, &nwb),
	    p1->sa.st_serialno,
	    pri_connection(p1->sa.st_connection, &cib));

	p1->sa.st_dpd_peerseqno = seqno;

	if (send_dpd_notification(p1, v1N_R_U_THERE_ACK,
				  pbs->cur, pbs_left(pbs)) != STF_IGNORE) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: could not send R_U_THERE_ACK");
		return STF_IGNORE;
	}

	/* update the time stamp */
	p1->sa.st_last_dpd = now;

	pstats_ike_dpd_replied++;

	/*
	 * Since there was activity, kill any EVENT_v1_DPD_TIMEOUT
	 * that might be waiting.
	 */
	if (p1->sa.st_v1_dpd_event != NULL &&
	    p1->sa.st_v1_dpd_event->ev_type == EVENT_v1_DPD_TIMEOUT)
		event_delete(EVENT_v1_DPD_TIMEOUT, &p1->sa);

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
stf_status dpd_inR(struct state *p1sa,
		   struct isakmp_notification *const n,
		   struct pbs_in *pbs)
{
	if (!PEXPECT(p1sa->logger, IS_PARENT_SA(p1sa))) {
		return STF_INTERNAL_ERROR;
	}

	struct ike_sa *p1 = pexpect_parent_sa(p1sa);

	if (!IS_V1_ISAKMP_SA_ESTABLISHED(&p1->sa)) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: received R_U_THERE_ACK for unestablished ISKAMP SA");
		return STF_FAIL_v1N;
	}

	if (n->isan_spisize != COOKIE_SIZE * 2 ||
	    pbs_left(pbs) < COOKIE_SIZE * 2) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: R_U_THERE_ACK has invalid SPI length (%d)",
		     n->isan_spisize);
		return STF_FAIL_v1N + v1N_PAYLOAD_MALFORMED;
	}

	if (!memeq(pbs->cur, p1->sa.st_ike_spis.initiator.bytes, COOKIE_SIZE)) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		pdbg(p1->sa.logger, "DPD: R_U_THERE_ACK has invalid icookie");
	}
	pbs->cur += COOKIE_SIZE;

	if (!memeq(pbs->cur, p1->sa.st_ike_spis.responder.bytes, COOKIE_SIZE)) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		dbg("DPD: R_U_THERE_ACK has invalid rcookie");
	}
	pbs->cur += COOKIE_SIZE;

	uint32_t seqno;
	if (pbs_left(pbs) != sizeof(seqno)) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: R_U_THERE_ACK has invalid data length (%d)",
		     (int) pbs_left(pbs));
		return STF_FAIL_v1N + v1N_PAYLOAD_MALFORMED;
	}

	seqno = ntohl(*(uint32_t *)pbs->cur);
	pdbg(p1->sa.logger,
	     "DPD: R_U_THERE_ACK, seqno received: %u expected: %u (state=#%lu)",
	     seqno, p1->sa.st_dpd_expectseqno, p1->sa.st_serialno);

	if (seqno == p1->sa.st_dpd_expectseqno) {
		/* update the time stamp */
		p1->sa.st_last_dpd = mononow();
		p1->sa.st_dpd_expectseqno = 0;
	} else if (!p1->sa.st_dpd_expectseqno) {
		llog(RC_LOG, p1->sa.logger,
		     "DPD: unexpected R_U_THERE_ACK packet with sequence number %u",
		     seqno);
		/* do not update time stamp, so we'll send a new one sooner */
	}

	pstats_ike_dpd_recv++;

	/*
	 * Since there was activity, kill any EVENT_v1_DPD_TIMEOUT
	 * that might be waiting.
	 */
	if (p1->sa.st_v1_dpd_event != NULL &&
	    p1->sa.st_v1_dpd_event->ev_type == EVENT_v1_DPD_TIMEOUT)
		event_delete(EVENT_v1_DPD_TIMEOUT, &p1->sa);

	return STF_IGNORE;
}

stf_status send_dpd_notification(struct ike_sa *ike,
				 uint16_t type, const void *data,
				 size_t len)
{
	msgid_t msgid;
	struct pbs_out rbody;

	msgid = generate_msgid(&ike->sa);

	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), ike->sa.logger);

	/* HDR* */
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
			.isa_msgid = msgid,
		};
		hdr.isa_ike_initiator_spi = ike->sa.st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = ike->sa.st_ike_spis.responder;
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream, &rbody))
			return STF_INTERNAL_ERROR;
	}

	struct v1_hash_fixup hash_fixup;
	if (!emit_v1_HASH(V1_HASH_1, "notification",
			  IMPAIR_v1_NOTIFICATION_EXCHANGE,
			  &ike->sa, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* NOTIFY */
	{
		struct pbs_out notify_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_protoid = PROTO_ISAKMP,
			.isan_spisize = COOKIE_SIZE * 2,
			.isan_type = type,
		};
		if (!out_struct(&isan, &isakmp_notification_desc, &rbody,
				&notify_pbs) ||
		    !out_raw(ike->sa.st_ike_spis.initiator.bytes, COOKIE_SIZE, &notify_pbs,
			     "notify icookie") ||
		    !out_raw(ike->sa.st_ike_spis.responder.bytes, COOKIE_SIZE, &notify_pbs,
			     "notify rcookie"))
			return STF_INTERNAL_ERROR;

		if (data != NULL && len > 0)
			if (!out_raw(data, len, &notify_pbs, "notify data"))
				return STF_INTERNAL_ERROR;

		close_output_pbs(&notify_pbs);
	}

	fixup_v1_HASH(&ike->sa, &hash_fixup, msgid, rbody.cur);

	/*
	 * For NOTIFICATION / DELETE messages we don't need to
	 * maintain a state because there are no retransmissions ...
	 */
	struct crypt_mac iv = new_phase2_iv(ike, msgid,
					    "IKE sending DPD", HERE);
	if (!close_and_encrypt_v1_message(ike, &rbody, &iv)) {
		return STF_INTERNAL_ERROR;
	}

	send_pbs_out_using_state(&ike->sa, "ISAKMP notify", &reply_stream);

	return STF_IGNORE;
}
