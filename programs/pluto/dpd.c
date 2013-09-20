/* IPsec IKE Dead Peer Detection code.
 * Copyright (C) 2003 Ken Bantoft        <ken@xelerance.com>
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 FURUSO Shinichi <Shinichi.Furuso@jp.sony.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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
#include <sys/time.h>           /* for gettimeofday */

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "lswtime.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#endif
#include "connections.h"        /* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "whack.h"

#include "pending.h" /* for flush_pending_by_connection */

#include "dpd.h"
#include "x509more.h"

/**
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
 * has its own DPD_EVENT. Further, we start a DPD_EVENT for phase 1 when it
 * gets established. This is because the phase 2 may never actually succeed
 * (usually due to authorization issues, which may be DNS or otherwise related)
 * and if the responding end dies (gets restarted, or the conn gets reloaded
 * with the right policy), then we may have a bum phase 1 SA, and we can not
 * re-negotiate. (This happens WAY too often)
 *
 * The phase 2 dpd_init() will attempt to kill the phase 1 DPD_EVENT, if it
 * can, to reduce the amount of work.
 *
 * The st_last_dpd member which is used is always the one from the phase 1.
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
	/**
	 * Used to store the 1st state
	 */
#ifdef HAVE_LABELED_IPSEC
	if (st->st_connection->loopback) {
		libreswan_log(
			"dpd is not required for ipsec connections over loopback");
		return STF_OK;
	}
#endif
	struct state *p1st;

	/* find the related Phase 1 state */
	p1st = find_state_ikev1(st->st_icookie, st->st_rcookie, 0);

	if (p1st == NULL) {
		loglog(RC_LOG_SERIOUS, "could not find phase 1 state for DPD");

		/*
		 * if the phase 1 state has gone away, it really should have
		 * deleted all of its children.
		 * Why would this happen? because a quick mode SA can take
		 * some time to create (DNS lookups for instance), and the phase 1
		 * might have been taken down for some reason in the meantime.
		 * We really can not do anything here --- attempting to invoke
		 * the DPD action would be a good idea, but we really should
		 * do that outside this function.
		 */
		return STF_FAIL;
	}

	/* if it was enabled, and we haven't turned it on already */
	if (p1st->hidden_variables.st_dpd) {
		time_t n = now();
		libreswan_log("Dead Peer Detection (RFC 3706): enabled");

		if (st->st_dpd_event == NULL ||
		    (st->st_connection->dpd_delay + n) <
		    st->st_dpd_event->ev_time) {
			if (st->st_dpd_event != NULL)
				delete_dpd_event(st);
			event_schedule(EVENT_DPD, st->st_connection->dpd_delay,
				       st);
		}
	} else {
		libreswan_log(
			"Dead Peer Detection (RFC 3706): not enabled because peer did not advertise it");
	}

	if (p1st != st) {
		/* st was not a phase 1 SA, so kill the DPD_EVENT on the phase 1 */
		if (p1st->st_dpd_event != NULL &&
		    p1st->st_dpd_event->ev_type == EVENT_DPD)
			delete_dpd_event(p1st);
	}
	return STF_OK;
}

bool was_eroute_idle(struct state *st, time_t since_when);

/*
 * Only schedule a new timeout if there isn't one currently,
 * or if it would be sooner than the current timeout.
 */
static void dpd_sched_timeout(struct state *p1st, time_t tm, time_t timeout)
{
	passert(timeout > 0);
	if (p1st->st_dpd_event == NULL ||
	    p1st->st_dpd_event->ev_time > tm + timeout) {
		DBG(DBG_DPD, DBG_log("DPD: scheduling timeout to %lu",
				     (unsigned long)timeout));
		if (p1st->st_dpd_event != NULL)
			delete_dpd_event(p1st);
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
		     time_t delay, time_t timeout)
{
	time_t tm;
	time_t last;
	u_int32_t seqno;
	bool eroute_idle;
	time_t nextdelay;

	DBG(DBG_DPD,
	    DBG_log("DPD: processing for state #%lu (\"%s\")",
		    st->st_serialno,
		    st->st_connection->name));

	/* If no DPD, then get out of here */
	if (!st->hidden_variables.st_dpd)
		return;

	/* If there is no state, there can be no DPD */
	if (!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state))
		return;

	/* find out when now is */
	tm = now();

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
	 */
	last = (p1st->st_last_dpd < st->st_last_dpd ?
		st->st_last_dpd : p1st->st_last_dpd );

	nextdelay = last + delay - tm;

	/* has there been enough activity of late? */
	if (nextdelay > 0) {
		/* Yes, just reschedule "phase 2" */
		DBG(DBG_DPD,
		    DBG_log("DPD: not yet time for dpd event: %lu < %lu",
			    (unsigned long)tm,
			    (unsigned long)(last + delay)));
		event_schedule(EVENT_DPD, nextdelay, st);
		return;
	}

	/* now plan next check time */
	if (nextdelay < 1)
		nextdelay = delay;

	/*
	 * check the phase 2, if we are supposed to,
	 * and return if it is active recently
	 */
	if (eroute_care && !st->hidden_variables.st_nat_traversal) {

		eroute_idle = was_eroute_idle(st, delay);
		if (!eroute_idle) {
			DBG(DBG_DPD,
			    DBG_log("DPD: out event not sent, phase 2 active"));

			/* update phase 2 time stamp only */
			st->st_last_dpd = tm;

			/*
			 * Since there was activity, kill any EVENT_DPD_TIMEOUT that might
			 * be waiting. This can happen when a R_U_THERE_ACK is lost, and
			 * subsequently traffic started flowing over the SA again, and no
			 * more DPD packets are sent to cancel the outstanding DPD timer.
			 */
			if (p1st->st_dpd_event != NULL &&
			    p1st->st_dpd_event->ev_type == EVENT_DPD_TIMEOUT)
				delete_dpd_event(p1st);

			event_schedule(EVENT_DPD, nextdelay, st);
			return;
		}
	}

	if (st != p1st) {
		/*
		 * reschedule next event, since we can not do it from the activity
		 * routine.
		 */
		event_schedule(EVENT_DPD, nextdelay, st);
	}

	if (!p1st->st_dpd_seqno) {
		/* Get a non-zero random value that has room to grow */
		get_rnd_bytes((u_char *)&p1st->st_dpd_seqno,
			      sizeof(p1st->st_dpd_seqno));
		p1st->st_dpd_seqno &= 0x7fff;
		p1st->st_dpd_seqno++;
	}
	seqno = htonl(p1st->st_dpd_seqno);

	/* make sure that the timeout occurs. We do this before the send,
	 * because the send may fail due to network issues, etc, and
	 * the timeout has to occur anyway
	 */
	dpd_sched_timeout(p1st, tm, timeout);

	DBG(DBG_DPD, DBG_log("DPD: sending R_U_THERE %u to %s:%d (state #%lu)",
			     p1st->st_dpd_seqno,
			     ip_str(&p1st->st_remoteaddr),
			     p1st->st_remoteport,
			     p1st->st_serialno));

	if (send_isakmp_notification(p1st, R_U_THERE,
				     &seqno, sizeof(seqno)) != STF_IGNORE) {
		loglog(RC_LOG_SERIOUS, "DPD: could not send R_U_THERE");
		return;
	}

	st->st_last_dpd = tm;
	p1st->st_last_dpd = tm;
	p1st->st_dpd_expectseqno = p1st->st_dpd_seqno++;

}

void p1_dpd_outI1(struct state *p1st)
{
	time_t delay = p1st->st_connection->dpd_delay;
	time_t timeout = p1st->st_connection->dpd_timeout;

	dpd_outI(p1st, p1st, FALSE, delay, timeout);
}

void p2_dpd_outI1(struct state *p2st)
{
	struct state *st;
	time_t delay = p2st->st_connection->dpd_delay;
	time_t timeout = p2st->st_connection->dpd_timeout;

	/* find the related Phase 1 state */
	st = find_phase1_state(p2st->st_connection,
			       ISAKMP_SA_ESTABLISHED_STATES);

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: could not find newest phase 1 state");
		return;
	}

	dpd_outI(st, p2st, TRUE, delay, timeout);
}

void dpd_event(struct state *st)
{
	if (st == NULL)
		return;

	if (IS_PHASE1(st->st_state) || IS_PHASE15(st->st_state ))
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
	time_t tm = now();
	u_int32_t seqno;

	if (!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state)) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: received R_U_THERE for unestablished ISKAMP SA");
		return STF_IGNORE;
	}
	if (n->isan_spisize != COOKIE_SIZE * 2 || pbs_left(pbs) < COOKIE_SIZE *
	    2) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: R_U_THERE has invalid SPI length (%d)",
		       n->isan_spisize);
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	if (memcmp(pbs->cur, p1st->st_icookie, COOKIE_SIZE) != 0) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		DBG(DBG_DPD,
		    DBG_log("DPD: R_U_THERE has invalid icookie (tolerated)"));
	}
	pbs->cur += COOKIE_SIZE;

	if (memcmp(pbs->cur, p1st->st_rcookie, COOKIE_SIZE) != 0) {
		DBG(DBG_DPD,
		    DBG_log("DPD: R_U_THERE has invalid rcookie (tolerated)"));
	}
	pbs->cur += COOKIE_SIZE;

	if (pbs_left(pbs) != sizeof(seqno)) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: R_U_THERE has invalid data length (%d)", (int) pbs_left(
			       pbs));
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	seqno = ntohl(*(u_int32_t *)pbs->cur);
	if (p1st->st_dpd_peerseqno && seqno <= p1st->st_dpd_peerseqno) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: received old or duplicate R_U_THERE");
		return STF_IGNORE;
	}

	DBG(DBG_DPD,
	    DBG_log(
		    "DPD: received R_U_THERE seq:%u time:%lu (state=#%lu name=\"%s\")",
		    seqno,
		    (unsigned long)tm,
		    p1st->st_serialno, p1st->st_connection->name));

	p1st->st_dpd_peerseqno = seqno;

	if (send_isakmp_notification(p1st, R_U_THERE_ACK,
				     pbs->cur, pbs_left(pbs)) != STF_IGNORE) {
		loglog(RC_LOG_SERIOUS, "DPD: could not send R_U_THERE_ACK");
		return STF_IGNORE;
	}

	/* update the time stamp */
	p1st->st_last_dpd = tm;

	/*
	 * since there was activity, kill any EVENT_DPD_TIMEOUT that might
	 * be waiting.
	 */
	if (p1st->st_dpd_event != NULL &&
	    p1st->st_dpd_event->ev_type == EVENT_DPD_TIMEOUT)
		delete_dpd_event(p1st);

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
	time_t tm = now();
	u_int32_t seqno;

	if (!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state)) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: recevied R_U_THERE_ACK for unestablished ISKAMP SA");
		return STF_FAIL;
	}

	if (n->isan_spisize != COOKIE_SIZE * 2 || pbs_left(pbs) < COOKIE_SIZE *
	    2) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: R_U_THERE_ACK has invalid SPI length (%d)",
		       n->isan_spisize);
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	if (memcmp(pbs->cur, p1st->st_icookie, COOKIE_SIZE) != 0) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		DBG(DBG_DPD,
		    DBG_log("DPD: R_U_THERE_ACK has invalid icookie"));
	}
	pbs->cur += COOKIE_SIZE;

	if (memcmp(pbs->cur, p1st->st_rcookie, COOKIE_SIZE) != 0) {
		/* RFC states we *SHOULD* check cookies, not MUST.  So invalid
		   cookies are technically valid, as per Geoffrey Huang */
		DBG(DBG_DPD,
		    DBG_log("DPD: R_U_THERE_ACK has invalid rcookie"));
	}
	pbs->cur += COOKIE_SIZE;

	if (pbs_left(pbs) != sizeof(seqno)) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: R_U_THERE_ACK has invalid data length (%d)", (int) pbs_left(
			       pbs));
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	seqno = ntohl(*(u_int32_t *)pbs->cur);
	DBG(DBG_DPD,
	    DBG_log(
		    "DPD: R_U_THERE_ACK, seqno received: %u expected: %u (state=#%lu)",
		    seqno, p1st->st_dpd_expectseqno, p1st->st_serialno));

	if (seqno == p1st->st_dpd_expectseqno) {
		/* update the time stamp */
		p1st->st_last_dpd = tm;
		p1st->st_dpd_expectseqno = 0;
	} else if (!p1st->st_dpd_expectseqno) {
		loglog(RC_LOG_SERIOUS,
		       "DPD: unexpected R_U_THERE_ACK packet with sequence number %u",
		       seqno);
		/* do not update time stamp, so we'll send a new one sooner */
	}

	/*
	 * since there was activity, kill any EVENT_DPD_TIMEOUT that might
	 * be waiting.
	 */
	if (p1st->st_dpd_event != NULL &&
	    p1st->st_dpd_event->ev_type == EVENT_DPD_TIMEOUT)
		delete_dpd_event(p1st);

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
	struct connection *c = st->st_connection;
	int action = c->dpd_action;

	/** delete the state, which is probably in phase 2 */
	set_cur_connection(c);

	libreswan_log("DPD: No response from peer - declaring peer dead");

	switch (action) {
	case DPD_ACTION_HOLD:
		/** dpdaction=hold - Wipe the SA's but %trap the eroute so we don't
		    leak traffic.  Also, being in %trap means new packets will
		    force an initiation of the conn again.  */
		libreswan_log("DPD: Putting connection into %%trap");
		if (c->kind == CK_INSTANCE) {
			DBG(DBG_DPD,
			    DBG_log(
				    "DPD: warning dpdaction=hold on instance futile - will be deleted"));
		}
		delete_states_by_connection(c, TRUE);
		break;

	case DPD_ACTION_CLEAR:
		/** dpdaction=clear - Wipe the SA & eroute - everything */

		libreswan_log("DPD: Clearing Connection");
		/*
		 * For CK_INSTANCE, delete_states_by_connection() will clear
		 * Note that delete_states_by_connection changes c->kind but we need
		 * to remember what it was to know if we still need to unroute after delete
		 */
		if (c->kind == CK_INSTANCE) {
			delete_states_by_connection(c, TRUE);
		} else {
			flush_pending_by_connection(c); /* remove any partial negotiations that are failing */
			delete_states_by_connection(c, TRUE);
			DBG(DBG_DPD,
			    DBG_log("DPD: unrouting connection (%s)",
				    enum_name(&connection_kind_names,
					      c->kind)));
			unroute_connection(c); /* --unroute */
		}
		break;

	case DPD_ACTION_RESTART:
		/* dpdaction=restart - immediately renegotiate connections to the same peer. */
		libreswan_log(
			"DPD: Restarting all connections that share this peer");
		restart_connections_by_peer(c);
		break;

	default:
		bad_case(action);
	}
	reset_cur_connection();
}
