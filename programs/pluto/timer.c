/*
 * timer event handling
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "kernel.h"	/* needs connections.h */
#include "server.h"
#include "log.h"
#include "rnd.h"
#include "timer.h"
#include "whack.h"
#include "ikev1_dpd.h"
#include "ikev2.h"
#include "pending.h" /* for flush_pending_by_connection */
#include "ikev1_xauth.h"
#include "kernel.h" /* for scan_shunts() */
#include "kernel_pfkey.h" /* for pfkey_scan_shunts */

#include "nat_traversal.h"

#include "pluto_sd.h"

static unsigned long retrans_delay(struct state *st, unsigned long delay_ms)
{
	struct connection *c = st->st_connection;
	unsigned long delay_cap = deltamillisecs(c->r_timeout); /* ms */
	u_int8_t x = st->st_retransmit++;	/* ??? odd type */

	/*
	 * Very carefully calculate capped exponential backoff.
	 * The test is expressed as a right shift to avoid overflow.
	 * Even then, we must avoid a right shift of the width of
	 * the data or more since it is not defined by the C standard.
	 * Surely a bound of 12 (factor of 2048) is safe and more than enough.
	 */

	delay_ms = (x > MAXIMUM_RETRANSMITS_PER_EXCHANGE ||
			delay_cap >> x < delay_ms) ?
		delay_cap : delay_ms << x;

	if (x > 1 && delay_ms == delay_cap)
	{
		/* if delay_ms > c->r_timeout no re-transmit */
		x--;
		unsigned long delay_p = (x > MAXIMUM_RETRANSMITS_PER_EXCHANGE ||
				delay_cap >> x < delay_ms) ?  delay_cap :
			delay_ms << x;
		if (delay_p == delay_ms) /* previus delay was already caped retrun zero */
			delay_ms = 0;
	}

	if (delay_ms > 0) {
		whack_log(RC_RETRANSMISSION,
				"%s: retransmission; will wait %lums for response",
				enum_name(&state_names, st->st_state),
				(unsigned long)delay_ms);
	}
	return delay_ms;
}

/*
 * This file has the event handling routines. Events are
 * kept as a linked list of event structures. These structures
 * have information like event type, expiration time and a pointer
 * to event specific data (for example, to a state structure).
 */

/* Time to retransmit, or give up.
 *
 * Generally, we'll only try to send the message
 * MAXIMUM_RETRANSMISSIONS times.  Each time we double
 * our patience.
 *
 * As a special case, if this is the first initiating message
 * of a Main Mode exchange, and we have been directed to try
 * forever, we'll extend the number of retransmissions to
 * MAXIMUM_RETRANSMISSIONS_INITIAL times, with all these
 * extended attempts having the same patience.  The intention
 * is to reduce the bother when nobody is home.
 *
 * Since IKEv1 is not reliable for the Quick Mode responder,
 * we'll extend the number of retransmissions as well to
 * improve the reliability.
 */
static void retransmit_v1_msg(struct state *st)
{
	unsigned long delay_ms = 0;	/* relative time; 0 means NO */
	struct connection *c = st->st_connection;
	unsigned long try = st->st_try;
	unsigned long try_limit = c->sa_keying_tries;

	/* Paul: this line can stay attempt 3 of 2 because the cleanup happens when over the maximum */
	DBG(DBG_CONTROL, {
		ipstr_buf b;
		char cib[CONN_INST_BUF];
		DBG_log("handling event EVENT_v1_RETRANSMIT for %s \"%s\"%s #%lu attempt %lu of %lu",
			ipstr(&c->spd.that.host_addr, &b),
			c->name, fmt_conn_instance(c, cib),
			st->st_serialno, try, try_limit);
	});

	if (DBGP(IMPAIR_RETRANSMITS)) {
		libreswan_log(
			"supressing retransmit because IMPAIR_RETRANSMITS is set");
		delay_ms = 0;
		try = 0;
	} else {
		delay_ms = c->r_interval;
	}

	if (delay_ms != 0)
		delay_ms = retrans_delay(st, delay_ms);

	if (delay_ms != 0) {
		resend_ike_v1_msg(st, "EVENT_v1_RETRANSMIT");
		event_schedule_ms(EVENT_v1_RETRANSMIT, delay_ms, st);
	} else {
		/* check if we've tried rekeying enough times.
		 * st->st_try == 0 means that this should be the only try.
		 * c->sa_keying_tries == 0 means that there is no limit.
		 */
		const char *details = "";

		switch (st->st_state) {
		case STATE_MAIN_I3:
		case STATE_AGGR_I2:
			details = ".  Possible authentication failure: no acceptable response to our first encrypted message";
			break;
		case STATE_MAIN_I1:
		case STATE_AGGR_I1:
			details = ".  No response (or no acceptable response) to our first IKEv1 message";
			break;
		case STATE_QUICK_I1:
			if (c->newest_ipsec_sa == SOS_NOBODY) {
				details = ".  No acceptable response to our first Quick Mode message: perhaps peer likes no proposal";
			}
			break;
		default:
			break;
		}
		loglog(RC_NORETRANSMISSION,
			"max number of retransmissions (%d) reached %s%s",
			st->st_retransmit,
			enum_show(&state_names, st->st_state),
			details);
		if (try != 0 && (try <= try_limit || try_limit == 0)) {
			/*
			 * A lot like EVENT_SA_REPLACE, but over again.
			 * Since we know that st cannot be in use,
			 * we can delete it right away.
			 */
			char story[80]; /* arbitrary limit */

			try++;
			snprintf(story, sizeof(story), try_limit == 0 ?
				"starting keying attempt %ld of an unlimited number" :
				"starting keying attempt %ld of at most %ld",
				try, try_limit);

			/* ??? DBG and real-world code mixed */
			if (!DBGP(DBG_WHACKWATCH)) {
				if (st->st_whack_sock != NULL_FD) {
					/*
					 * Release whack because the observer
					 * will get bored.
					 */
					loglog(RC_COMMENT,
						"%s, but releasing whack",
						story);
					release_pending_whacks(st, story);
				} else if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
					/* no whack: just log */
					libreswan_log("%s", story);
				}
			} else if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				loglog(RC_COMMENT, "%s", story);
			}

			if (try % 3 == 0 &&
				LIN(POLICY_IKEV2_ALLOW | POLICY_IKEV2_PROPOSE,
					c->policy)) {
				/*
				 * so, let's retry with IKEv2, alternating
				 * every three messages
				 */
				c->failed_ikev2 = FALSE;
				loglog(RC_COMMENT,
					"next attempt will be IKEv2");
			}
			ipsecdoi_replace(st, LEMPTY, LEMPTY, try);
		}
		delete_state(st);
		/* note: no md->st to clear */
	}
}

static void retransmit_v2_msg(struct state *st)
{
	unsigned long delay_ms = 0;  /* relative time; 0 means NO */
	struct connection *c;
	unsigned long try;
	unsigned long try_limit;
	const char *details = "";
	struct state *pst = state_with_serialno(st->st_clonedfrom);

	passert(st != NULL);
	c = st->st_connection;
	try_limit = c->sa_keying_tries;
	try = st->st_try + 1;

	/* Paul: this line can stay attempt 3 of 2 because the cleanup happens when over the maximum */
	DBG(DBG_CONTROL, {
		ipstr_buf b;
		char cib[CONN_INST_BUF];
		DBG_log("handling event EVENT_v2_RETRANSMIT for %s \"%s\"%s #%lu attempt %lu of %lu",
			ipstr(&c->spd.that.host_addr, &b),
			c->name, fmt_conn_instance(c, cib),
			st->st_serialno, try, try_limit);
		if (pst != NULL)
			DBG_log("and parent for %s \"%s\"%s #%lu attempt %lu of %lu",
				ipstr(&c->spd.that.host_addr, &b),
				c->name, fmt_conn_instance(c, cib),
				pst->st_serialno, pst->st_try, try_limit);
	});

	if (DBGP(IMPAIR_RETRANSMITS)) {
		libreswan_log(
			"supressing retransmit because IMPAIR_RETRANSMITS is set");
		delay_ms = 0;
		try = 0;
	} else {
		delay_ms = c->r_interval;
	}

	if (delay_ms != 0) {
		delay_ms = retrans_delay(st, delay_ms);

		if (delay_ms != 0) {
			send_ike_msg(st, "EVENT_v2_RETRANSMIT");
			event_schedule_ms(EVENT_v2_RETRANSMIT, delay_ms, st);
			return;
		}
	}

	/*
	 * check if we've tried rekeying enough times.
	 * st->st_try == 0 means that this should be the only try.
	 * c->sa_keying_tries == 0 means that there is no limit.
	 */
	switch (st->st_state) {
	case STATE_PARENT_I2:
		details = ".  Possible authentication failure: no acceptable response to our first encrypted message";
		break;
	case STATE_PARENT_I1:
		details = ".  No response (or no acceptable response) to our first IKEv2 message";
		break;
	default:
		details = ".  No response (or no acceptable response) to our IKEv2 message";
		break;
	}

	if (DBGP(DBG_OPPO) || ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY)) {
		/* too spammy for OE */
		loglog(RC_NORETRANSMISSION,
			"max number of retransmissions (%d) reached %s%s",
			st->st_retransmit,
			enum_show(&state_names, st->st_state),
			details);
	}

	/* XXX try can never be 0?! */
	if (try != 0 && (try <= try_limit || try_limit == 0)) {
		/*
		 * A lot like EVENT_SA_REPLACE, but over again.
		 * Since we know that st cannot be in use,
		 * we can delete it right away.
		 */
		char story[80]; /* arbitrary limit */

		snprintf(story, sizeof(story), try_limit == 0 ?
			"starting keying attempt %ld of an unlimited number" :
			"starting keying attempt %ld of at most %ld",
			try, try_limit);

		if (st->st_whack_sock != NULL_FD) {
			/*
			 * Release whack because the observer will
			 * get bored.
			 */
			loglog(RC_COMMENT, "%s, but releasing whack",
				story);
			release_pending_whacks(st, story);
		} else if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			/* no whack: just log to syslog */
			libreswan_log("%s", story);
		}

		if (try % 3 == 0 && (c->policy & POLICY_IKEV1_ALLOW)) {
			/*
			 * so, let's retry with IKEv1, alternating every
			 * three messages
			 */
			c->failed_ikev2 = TRUE;
			loglog(RC_COMMENT, "next attempt will be IKEv1");
		}
		ipsecdoi_replace(st, LEMPTY, LEMPTY, try);
	} else {
		DBG(DBG_CONTROL, DBG_log("maximum number of keyingtries reached - deleting state"));
	}
	/*
	 * XXX There should not have been a child sa unless this was a timeout of
	 * our CREATE_CHILD_SA request. But our code has moved from parent to child
	 */
	// passert(IS_PARENT_SA(st)); in the glorious future

	delete_state(st);
	if (pst != NULL) {
		delete_state(pst);
	}
	/* note: no md->st to clear */
}

/* note: this mutates *st by calling get_sa_info */
static void liveness_check(struct state *st)
{
	struct state *pst;
	deltatime_t last_msg_age;

	struct connection *c = st->st_connection;

	passert(st->st_ikev2);

	/* this should be called on a child sa */
	if (IS_CHILD_SA(st)) {
		pst = state_with_serialno(st->st_clonedfrom);
		if (pst == NULL) {
			DBG(DBG_DPD,
				DBG_log("liveness_check error, no parent state"));
			return;
		}
	} else {
		pst = st;
	}

	/*
	 * don't bother sending the check and reset
	 * liveness stats if there has been incoming traffic
	 */
	if (get_sa_info(st, TRUE, &last_msg_age) &&
		deltaless(last_msg_age, c->dpd_timeout)) {
		pst->st_pend_liveness = FALSE;
		pst->st_last_liveness.mono_secs = UNDEFINED_TIME;
	} else {
		monotime_t tm = mononow();
		monotime_t last_liveness = pst->st_last_liveness;
		time_t timeout;

		/* ensure that the very first liveness_check works out */
		if (last_liveness.mono_secs == UNDEFINED_TIME) {
			pst->st_last_liveness = last_liveness = tm;
			DBG(DBG_DPD, DBG_log("liveness initial timestamp set"));
		}

		DBG(DBG_DPD,
			DBG_log("liveness_check - last_liveness: %ld, tm: %ld",
				(long)last_liveness.mono_secs,
				(long)tm.mono_secs));

		/* ??? MAX the hard way */
		if (deltaless(c->dpd_timeout, deltatimescale(3, 1, c->dpd_delay)))
			timeout = deltasecs(c->dpd_delay) * 3;
		else
			timeout = deltasecs(c->dpd_timeout);

		if (pst->st_pend_liveness &&
		    deltasecs(monotimediff(tm, last_liveness)) >= timeout) {
			DBG(DBG_DPD,
				DBG_log("liveness_check - peer has not responded in %ld seconds, with a timeout of %ld, taking action",
					(long)deltasecs(monotimediff(tm, last_liveness)),
					(long)timeout));
			switch (c->dpd_action) {
			case DPD_ACTION_CLEAR:
				liveness_clear_connection(c, "IKEv2 liveness action");
				return;

			case DPD_ACTION_RESTART:
				libreswan_log("IKEv2 peer liveness - restarting all connections that share this peer");
				restart_connections_by_peer(c);
				return;

			case DPD_ACTION_HOLD:
				DBG(DBG_DPD,
						DBG_log("liveness_check - handling default by rescheduling"));
				break;

			default:
				bad_case(c->dpd_action);
			}

		} else {
			stf_status ret = ikev2_send_informational(st);

			DBG(DBG_DPD,
				DBG_log("liveness_check - peer is missing - giving them some time to come back"));

			if (ret != STF_OK) {
				DBG(DBG_DPD,
					DBG_log("failed to send informational"));
				return; /* this prevents any new scheduling ??? */
			}
		}
	}

	DBG(DBG_DPD,
		DBG_log("liveness_check - peer is ok"));
	delete_liveness_event(st);
	event_schedule(EVENT_v2_LIVENESS,
		deltasecs(c->dpd_delay) >= MIN_LIVENESS ?
			deltasecs(c->dpd_delay) : MIN_LIVENESS,
		st);
}

static void ikev2_log_v2_sa_expired(struct state *st, enum event_type type)
{
	DBG(DBG_LIFECYCLE, {
		struct connection *c = st->st_connection;
		char story[80] = "";
		if (type == EVENT_v2_SA_REPLACE_IF_USED) {
			deltatime_t last_used_age;
			/* why do we only care about inbound traffic? */
			/* because we cannot tell the difference sending out to a dead SA? */
			if (get_sa_info(st, TRUE, &last_used_age)) {
				snprintf(story, sizeof(story),
					"last used %lds ago < %ld ",
					(long)deltasecs(last_used_age),
					(long)deltasecs(c->sa_rekey_margin));
			} else {
				snprintf(story, sizeof(story),
					"unknown usage - get_sa_info() failed");
			}

			DBG_log("replacing stale %s SA %s",
				IS_IKE_SA(st) ? "ISAKMP" : "IPsec",
				story);
		}
	});
}

static void ikev2_expire_parent(struct state *st, deltatime_t last_used_age)
{
	struct connection *c = st->st_connection;
	struct state *pst = state_with_serialno(st->st_clonedfrom);
	passert(pst != NULL); /* no orphan child allowed */

	/* we observed no traffic, let IPSEC SA and IKE SA expire */
	DBG(DBG_LIFECYCLE,
		DBG_log("not replacing unused IPSEC SA #%lu: last used %lds ago > %ld let it and the parent #%lu expire",
			st->st_serialno,
			(long)deltasecs(last_used_age),
			(long)deltasecs(c->sa_rekey_margin),
			pst->st_serialno));

	delete_event(pst);
	event_schedule(EVENT_SA_EXPIRE, 0, pst);
}

static event_callback_routine timer_event_cb;
static void timer_event_cb(evutil_socket_t fd UNUSED, const short event UNUSED, void *arg)
{
	struct pluto_event *ev = arg;
	enum event_type type;
	struct state *st;
	char statenum[64];

	type = ev->ev_type;
	st = ev->ev_state;

	if (st != NULL) {
		snprintf(statenum, sizeof(statenum), " for %s state #%lu",
			(st->st_clonedfrom == SOS_NOBODY) ? "parent" : "child",
			st->st_serialno);
	}
	DBG(DBG_CONTROL, DBG_log("handling event %s%s",
				enum_show(&timer_event_names, type), (st == NULL) ? "" : statenum));


	passert(GLOBALS_ARE_RESET());

	if (st != NULL)
		set_cur_state(st);

	/*
	 * Check that st is as expected for the event type.
	 *
	 * For an event type associated with a state, remove the backpointer
	 * from the appropriate slot of the state object.
	 *
	 * We'll eventually either schedule a new event, or delete the state.
	 */
	switch (type) {
	case EVENT_REINIT_SECRET:
	case EVENT_SHUNT_SCAN:
	case EVENT_PENDING_DDNS:
	case EVENT_PENDING_PHASE2:
	case EVENT_LOG_DAILY:
	case EVENT_SD_WATCHDOG:
	case EVENT_NAT_T_KEEPALIVE:
		passert(st == NULL);
		break;

	case EVENT_v1_SEND_XAUTH:
		passert(st != NULL && st->st_send_xauth_event == ev);
		DBG_log("event EVENT_v1_SEND_XAUTH #%lu %s", st->st_serialno,
				enum_name(&state_names, st->st_state));
		st->st_send_xauth_event = NULL;
		break;

	case EVENT_v1_RETRANSMIT:
	case EVENT_v2_RETRANSMIT:
	case EVENT_SA_REPLACE:
	case EVENT_SA_REPLACE_IF_USED:
	case EVENT_v2_SA_REPLACE_IF_USED:
	case EVENT_v2_SA_REPLACE_IF_USED_IKE:
	case EVENT_v2_RESPONDER_TIMEOUT:
	case EVENT_SA_EXPIRE:
	case EVENT_SO_DISCARD:
	case EVENT_CRYPTO_FAILED:
		passert(st != NULL && st->st_event == ev);
		st->st_event = NULL;
		break;

	case EVENT_v2_RELEASE_WHACK:
		passert(st != NULL && st->st_rel_whack_event == ev);
		DBG_log("event EVENT_v2_RELEASE_WHACK st_rel_whack_event=NULL #%lu %s",  st->st_serialno, enum_name(&state_names, st->st_state));
		st->st_rel_whack_event = NULL;
		break;

	case EVENT_v2_LIVENESS:
		passert(st != NULL && st->st_liveness_event == ev);
		st->st_liveness_event = NULL;
		break;

	case EVENT_DPD:
	case EVENT_DPD_TIMEOUT:
		passert(st != NULL && st->st_dpd_event == ev);
		st->st_dpd_event = NULL;
		break;

	default:
		bad_case(type);
	}

	/* now do the actual event's work */
	switch (type) {
	case EVENT_REINIT_SECRET:
		DBG(DBG_CONTROL,
			DBG_log("event EVENT_REINIT_SECRET handled"));
		init_secret();
		break;

	case EVENT_SHUNT_SCAN:
		if (!kernel_ops->policy_lifetime) {
			/* KLIPS or MAST - scan eroutes */
			pfkey_scan_shunts();
		} else {
			/* eventually obsoleted via policy expire msg from kernel */
			expire_bare_shunts();
		}
		break;

	case EVENT_PENDING_DDNS:
		connection_check_ddns();
		break;

	case EVENT_PENDING_PHASE2:
		connection_check_phase2();
		break;

	case EVENT_LOG_DAILY:
		daily_log_event();
		break;

#ifdef USE_SYSTEMD_WATCHDOG
	case EVENT_SD_WATCHDOG:
		sd_watchdog_event();
		break;
#endif

	case EVENT_NAT_T_KEEPALIVE:
		nat_traversal_ka_event();
		break;

	case EVENT_v2_RELEASE_WHACK:
		DBG(DBG_CONTROL, DBG_log("%s releasing whack for #%lu %s (sock=%d)",
					enum_show(&timer_event_names, type),
					st->st_serialno,
					enum_name(&state_names, st->st_state),
					st->st_whack_sock));
		release_pending_whacks(st, "realse whack");
		break;

	case EVENT_v1_RETRANSMIT:
		retransmit_v1_msg(st);
		break;

	case EVENT_v1_SEND_XAUTH:
		xauth_send_request(st);
		break;

	case EVENT_v2_RETRANSMIT:
		retransmit_v2_msg(st);
		break;

	case EVENT_v2_LIVENESS:
		liveness_check(st);
		break;

	case EVENT_SA_REPLACE:
	case EVENT_SA_REPLACE_IF_USED:
	case EVENT_v2_SA_REPLACE_IF_USED:
	case EVENT_v2_SA_REPLACE_IF_USED_IKE:
	{
		struct connection *c = st->st_connection;
		so_serial_t newest;
		deltatime_t last_used_age;

		if (IS_IKE_SA(st)) {
			newest = c->newest_isakmp_sa;
			DBG(DBG_LIFECYCLE, DBG_log("EVENT_SA_REPLACE{IF_USED} picked newest_isakmp_sa #%lu",
						newest));
		} else {
			newest = c->newest_ipsec_sa;
			DBG(DBG_LIFECYCLE, DBG_log("EVENT_SA_REPLACE{IF_USED} picked newest_ipsec_sa #%lu",
						newest));
		}

		if (newest != SOS_NOBODY && newest > st->st_serialno) {
			/* not very interesting: no need to replace */
			DBG(DBG_LIFECYCLE, DBG_log(
					"not replacing stale %s SA: #%lu will do",
					IS_IKE_SA(st) ?
					"ISAKMP" : "IPsec", newest));
		} else if (type == EVENT_v2_SA_REPLACE_IF_USED &&
				get_sa_info(st, TRUE, &last_used_age) &&
				deltaless(c->sa_rekey_margin, last_used_age)) {
			ikev2_expire_parent(st, last_used_age);
			break;
		} else if (type == EVENT_v2_SA_REPLACE_IF_USED_IKE) {
				struct state *cst = state_with_serialno(c->newest_ipsec_sa);
				if (cst == NULL)
					break;
				DBG(DBG_LIFECYCLE, DBG_log( "#%lu check last used on newest IPSec SA #%lu",
							st->st_serialno, cst->st_serialno));
				if (get_sa_info(cst, TRUE, &last_used_age) &&
					deltaless(c->sa_rekey_margin, last_used_age))
				{
					delete_liveness_event(cst);
					delete_event(cst);
					event_schedule(EVENT_SA_EXPIRE, 0, cst);
					ikev2_expire_parent(cst, last_used_age);
					break;
				} else {
					ikev2_log_v2_sa_expired(st, type);
					ipsecdoi_replace(st, LEMPTY, LEMPTY, 1);
				}

		} else if (type == EVENT_SA_REPLACE_IF_USED &&
				!monobefore(mononow(), monotimesum(st->st_outbound_time, c->sa_rekey_margin)))
		{
			/*
			 * we observed no recent use: no need to replace
			 *
			 * The sampling effects mean that st_outbound_time
			 * could be up to SHUNT_SCAN_INTERVAL more recent
			 * than actual traffic because the sampler looks at
			 * change over that interval.
			 * st_outbound_time could also not yet reflect traffic
			 * in the last SHUNT_SCAN_INTERVAL.
			 * We expect that SHUNT_SCAN_INTERVAL is smaller than
			 * c->sa_rekey_margin so that the effects of this will
			 * be unimportant.
			 * This is just an optimization: correctness is not
			 * at stake.
			 */
			DBG(DBG_LIFECYCLE, DBG_log(
					"not replacing stale %s SA: inactive for %lds",
					IS_IKE_SA(st) ? "ISAKMP" : "IPsec",
					(long)deltasecs(monotimediff(mononow(),
						st->st_outbound_time))));
		} else {
			ikev2_log_v2_sa_expired(st, type);
			ipsecdoi_replace(st, LEMPTY, LEMPTY, 1);
		}


		delete_liveness_event(st);
		delete_dpd_event(st);
		event_schedule(EVENT_SA_EXPIRE, deltasecs(st->st_margin), st);
	}
	break;

	case EVENT_v2_RESPONDER_TIMEOUT:
	case EVENT_SA_EXPIRE:
	{
		const char *satype;
		so_serial_t latest;
		struct connection *c;

		passert(st != NULL);
		c = st->st_connection;

		if (IS_IKE_SA(st)) {
			satype = "ISAKMP";
			latest = c->newest_isakmp_sa;
			DBG(DBG_LIFECYCLE, DBG_log("EVENT_SA_EXPIRE picked newest_isakmp_sa"));
		} else {
			satype = "IPsec";
			latest = c->newest_ipsec_sa;
			DBG(DBG_LIFECYCLE, DBG_log("EVENT_SA_EXPIRE picked newest_ipsec_sa"));
		}

		if (st->st_serialno < latest) {
			/* not very interesting: already superseded */
			DBG(DBG_LIFECYCLE, DBG_log(
				"%s SA expired (superseded by #%lu)",
					satype, latest));
		} else if (!IS_IKE_SA_ESTABLISHED(st)) {
			/* not very interesting: failed IKE attempt */
			DBG(DBG_LIFECYCLE, DBG_log(
				"un-established partial ISAKMP SA timeout (%s)",
					type == EVENT_SA_EXPIRE ? "SA expired" : "Responder timeout"));
		} else {
				libreswan_log("%s %s (%s)", satype,
					type == EVENT_SA_EXPIRE ? "SA expired" : "Responder timeout",
					(c->policy & POLICY_DONT_REKEY) ?
						"--dontrekey" : "LATEST!");
		}
	}
	/* FALLTHROUGH */
	case EVENT_SO_DISCARD:
		/* Delete this state object.  It must be in the hash table. */
#if 0           /* delete_state will take care of this better ? */
		if (st->st_suspended_md != NULL) {
			release_any_md(&st->st_suspended_md);
			unset_suspended(st);
		}
#endif
		if (st->st_ikev2 && IS_IKE_SA(st)) {
			/* IKEv2 parent, delete children too */
			delete_my_family(st, FALSE);
			/* note: no md->st to clear */
		} else {
			delete_state(st);
			/* note: no md->st to clear */
		}
		break;

	case EVENT_DPD:
		dpd_event(st);
		break;

	case EVENT_DPD_TIMEOUT:
		dpd_timeout(st);
		break;

	case EVENT_CRYPTO_FAILED:
		DBG(DBG_LIFECYCLE,
			DBG_log("event crypto_failed on state #%lu, aborting",
				st->st_serialno));
		delete_state(st);
		/* note: no md->st to clear */
		break;

	default:
		bad_case(type);
	}

	pfree(ev);
	reset_cur_state();
}

static void delete_pluto_event(struct pluto_event **evp)
{
	struct pluto_event *e = *evp;

	if (e == NULL) {
		DBG(DBG_CONTROLMORE, DBG_log("%s cannot delete NULL event", __func__));
		return;
	}
	/* ??? when would e->ev be NULL? */
	if (e->ev != NULL) {
		event_free(e->ev);
		e->ev = NULL;
	}
	pfree(e);
	*evp = NULL;
}

/*
 * Delete an event.
 */
void delete_event(struct state *st)
{
	/* ??? isn't this a bug?  Should we not passert? */
	if (st->st_event == NULL) {
		DBG(DBG_CONTROLMORE,
				DBG_log("state: #%lu requesting to delete non existing event",
					st->st_serialno));
		return;
	}
	DBG(DBG_CONTROLMORE,
			DBG_log("state: #%lu requesting %s to be deleted",
				st->st_serialno,
				enum_show(&timer_event_names,
					st->st_event->ev_type)));

	if (st->st_event->ev_type == EVENT_v1_RETRANSMIT || st->st_event->ev_type == EVENT_v2_RETRANSMIT)
		st->st_retransmit = 0;
	delete_pluto_event(&st->st_event);
}

void delete_liveness_event(struct state *st)
{
	DBG(DBG_DPD | DBG_CONTROL,
			DBG_log("state: #%lu requesting event %s to be deleted",
				st->st_serialno,
				(st->st_liveness_event != NULL ?
				 enum_show(&timer_event_names,
					 st->st_liveness_event->ev_type) :
				 "none")));

	if (st->st_liveness_event != NULL)
		delete_pluto_event(&st->st_liveness_event);
}

/*
 * Delete a DPD event.
 */
void delete_dpd_event(struct state *st)
{
	DBG(DBG_DPD | DBG_CONTROL,
		DBG_log("state: %lu requesting DPD event %s to be deleted",
			st->st_serialno,
			(st->st_dpd_event != NULL ?
				enum_show(&timer_event_names,
					st->st_dpd_event->ev_type) :
				"none")));
	delete_pluto_event(&st->st_dpd_event);
}

/*
 * dump list of events to whacklog
 */
void timer_list(void)
{
#if 0
/* AA_2015 not yet ported to libevent */

	monotime_t nw;
	struct p_event *ev = evlist;

	if (ev == (struct p_event *) NULL) {
		/* Just paranoid */
		whack_log(RC_LOG, "no events are queued");
		return;
	}

	nw = mononow();

	whack_log(RC_LOG, "It is now: %ld seconds since monotonic epoch",
		(unsigned long)nw.mono_secs);

	while (ev != NULL) {
		int type = ev->ev_type;
		struct state *st = ev->ev_state;

		whack_log(RC_LOG, "event %s is schd: %ld (in %lds) #%lu",
			enum_show(&timer_event_names, type),
			(long)ev->ev_time.mono_secs,
			(long)deltasecs(monotimediff(ev->ev_time, nw)),
			st == NULL ? SOS_NOBODY : st->st_serialno);

		if (st != NULL && st->st_connection != NULL) {
			char cib[CONN_INST_BUF];
			whack_log(RC_LOG, "    connection: \"%s\"",
				st->st_connection->name,
				fmt_conn_instance(st->st_connection, cib));
		}

		ev = ev->ev_next;
	}
#endif
}

/*
 * XXX --- hack alert, but I want to avoid adding new pluto-level
 *   command line arguments for now --- they need to all be whack
 * level items, and all command line arguments go away.
 */

#if 0 /* ??? no longer in use */
static unsigned long envnumber(const char *name,
			     unsigned long lwb, unsigned long upb,
			     unsigned long def)
{
	const char *s = getenv(name);
	unsigned long res;
	err_t ugh;

	if (s == NULL)
		return def;

	ugh = ttoulb(s, 0, 10, upb, &res);
	if (ugh == NULL && res < lwb)
		ugh = "too small";
	if (ugh != NULL) {
		libreswan_log("environment variable %s is \"%s\", %s",
			name, s, ugh);
		return def;
	}
	DBG(DBG_CONTROL,
		DBG_log("environment variable %s: '%lu",
			name, res));
	return res;
}
#endif

/*
 * This routine places an event in the event list.
 * Delay should really be a deltatime_t but this is easier
 */
static void event_schedule_tv(enum event_type type, const struct timeval delay, struct state *st)
{
	const char *en = enum_name(&timer_event_names, type);
	struct pluto_event *ev = alloc_thing(struct pluto_event, en);

	DBG(DBG_LIFECYCLE, DBG_log("event_schedule_tv called for about %lu seconds and change",
		delay.tv_sec));

	/*
	 * Scheduling a month into the future is most likely a bug.
	 * pexpect() causes us to flag this in our test cases
	 * But do allow (unwise) people to set insame > 1m lifetimes
	 */
	pexpect(delay.tv_sec < 3600 * 24 * 31);

	ev->ev_type = type;

	/* ??? ev_time lacks required precision */
	ev->ev_time = monotimesum(mononow(), deltatime(delay.tv_sec));

	ev->ev_state = st;
	ev->ev = pluto_event_new(NULL_FD, EV_TIMEOUT, timer_event_cb, ev, &delay);

	/*
	 * If the event is associated with a state, put a backpointer to the
	 * event in the state object, so we can find and delete the event
	 * if we need to (for example, if we receive a reply).
	 * (There are actually three classes of event associated
	 * with a state.)
	 */
	if (st != NULL) {
		switch (type) {
		case EVENT_DPD:
		case EVENT_DPD_TIMEOUT:
			passert(st->st_dpd_event == NULL);
			st->st_dpd_event = ev;
			break;

		case EVENT_v2_LIVENESS:
			passert(st->st_liveness_event == NULL);
			st->st_liveness_event = ev;
			break;

		case EVENT_RETAIN:
			/* no new event */
			break;

		case EVENT_v2_RELEASE_WHACK:
			passert(st->st_rel_whack_event == NULL);
			st->st_rel_whack_event = ev;
			break;

		case  EVENT_v1_SEND_XAUTH:
			passert(st->st_send_xauth_event == NULL);
			st->st_send_xauth_event = ev;
			break;

		default:
			passert(st->st_event == NULL);
			st->st_event = ev;
			break;
		}
	}

	DBG(DBG_CONTROL, {
			if (st == NULL) {
				DBG_log("inserting event %s, timeout in %lu.%06lu seconds",
					en,
					(unsigned long)delay.tv_sec,
					(unsigned long)delay.tv_usec);
			} else {
				DBG_log("inserting event %s, timeout in %lu.%06lu seconds for #%lu",
					en,
					(unsigned long)delay.tv_sec,
					(unsigned long)delay.tv_usec,
					ev->ev_state->st_serialno);
			}
		});
}

void event_schedule_ms(enum event_type type, unsigned long delay_ms, struct state *st)
{
	struct timeval delay;

	DBG(DBG_LIFECYCLE, DBG_log("event_schedule_ms called for about %lu ms", delay_ms));

	delay.tv_sec = delay_ms / 1000;
	delay.tv_usec = (delay_ms % 1000) * 1000;
	event_schedule_tv(type, delay, st);
}

void event_schedule(enum event_type type, time_t delay_sec, struct state *st)
{
	struct timeval delay;

	DBG(DBG_LIFECYCLE, DBG_log("event_schedule called for %lu seconds", delay_sec));

	/* unexpectedly far away, pexpect will flag in test cases */
	pexpect(delay_sec < 3600 * 24 * 31);
	delay.tv_sec = delay_sec;
	delay.tv_usec = 0;
	event_schedule_tv(type, delay, st);
}
