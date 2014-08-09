/*
 * timer event handling
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
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

#include "nat_traversal.h"

/*
 * This file has the event handling routines. Events are
 * kept as a linked list of event structures. These structures
 * have information like event type, expiration time and a pointer
 * to event specific data (for example, to a state structure).
 */

static struct event *evlist = (struct event *) NULL;

static unsigned int event_retransmit_delay_0 = EVENT_RETRANSMIT_DELAY_0;
static unsigned int maximum_retransmissions  = MAXIMUM_RETRANSMISSIONS;	/* exponent: must be small */
unsigned int maximum_retransmissions_initial = MAXIMUM_RETRANSMISSIONS_INITIAL;	/* exponent: must be small */
static unsigned int maximum_retransmissions_quick_r1 =
	MAXIMUM_RETRANSMISSIONS_QUICK_R1;

/*
 * This routine places an event in the event list.
 * Delay should really be a monotime_t but this is easier
 */
void event_schedule(enum event_type type, time_t delay, struct state *st)
{
	struct event *ev = alloc_thing(struct event,
				"struct event in event_schedule()");

	passert(delay >= 0);
	ev->ev_type = type;
	ev->ev_time = monotimesum(mononow(), deltatime(delay));
	ev->ev_state = st;

	/*
	 * If the event is associated with a state, put a backpointer to the
	 * event in the state object, so we can find and delete the event
	 * if we need to (for example, if we receive a reply).
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
		default:
			passert(st->st_event == NULL);
			st->st_event = ev;
			break;
		}
	}

	DBG(DBG_CONTROL, {
			if (st == NULL) {
				DBG_log("inserting event %s, timeout in %lu seconds",
					enum_show(&timer_event_names, type),
					(unsigned long)delay);
			} else {
				DBG_log("inserting event %s, timeout in %lu seconds for #%lu",
					enum_show(&timer_event_names, type),
					(unsigned long)delay,
					ev->ev_state->st_serialno);
			}
		});

	if (evlist == NULL || !monobefore(evlist->ev_time, ev->ev_time)) {
		DBG(DBG_CONTROLMORE, DBG_log("event added at head of queue"));
		ev->ev_next = evlist;
		evlist = ev;
	} else {
		struct event *evt;

		for (evt = evlist; evt->ev_next != NULL; evt = evt->ev_next)
			if (!monobefore(evt->ev_next->ev_time, ev->ev_time))
				break;

		DBG(DBG_CONTROLMORE, {
				if (evt->ev_state == NULL) {
					DBG_log("event added after event %s",
						enum_show(&timer_event_names,
							evt->ev_type));
				} else {
					DBG_log("event added after event %s for #%lu",
						enum_show(&timer_event_names,
							evt->ev_type),
						evt->ev_state->st_serialno);
				}
			});

		ev->ev_next = evt->ev_next;
		evt->ev_next = ev;
	}
}

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
	time_t delay = 0;	/* relative time; 0 means NO */
	struct connection *c;
	unsigned long try;
	unsigned long try_limit;

	passert(st != NULL);
	c = st->st_connection;

	try = st->st_try;
	try_limit = c->sa_keying_tries;

	DBG(DBG_CONTROL, {
		ipstr_buf b;
		DBG_log("handling event EVENT_v1_RETRANSMIT for %s \"%s\" #%lu attempt %lu of %lu",
			ipstr(&c->spd.that.host_addr, &b),
			c->name, st->st_serialno, try, try_limit);
	});

	/* first calculate delay as the value BEFORE backoff */
	if (st->st_retransmit < maximum_retransmissions) {
		delay = event_retransmit_delay_0;
	} else if ((st->st_state == STATE_MAIN_I1 ||
			st->st_state == STATE_AGGR_I1) &&
		c->sa_keying_tries == 0 &&
		st->st_retransmit < maximum_retransmissions_initial) {
		delay = event_retransmit_delay_0;
	} else if (st->st_state == STATE_QUICK_R1 &&
		st->st_retransmit < maximum_retransmissions_quick_r1) {
		delay = event_retransmit_delay_0;
	}

	if (DBGP(IMPAIR_RETRANSMITS)) {
		libreswan_log(
			"supressing retransmit because IMPAIR_RETRANSMITS is set");
		delay = 0;
		try = 0;
	}

	if (delay != 0) {
		/*
		 * Very carefully calculate capped exponential backoff.
		 * The test is expressed as a right shift to avoid overflow.
		 * Even then, we must avoid a right shift of the width of
		 * the data or more since it is not defined by the C standard.
		 * Surely a bound of 8 (factor of 256) is safe and more than enough.
		 */
		u_int8_t x = st->st_retransmit++;	/* ??? odd type */

		delay = (x > 8 ||
			EVENT_RETRANSMIT_DELAY_CAP >> x < delay) ?
			EVENT_RETRANSMIT_DELAY_CAP : delay << x;

		whack_log(RC_RETRANSMISSION,
			"%s: retransmission; will wait %lus for response",
			enum_name(&state_names, st->st_state),
			(unsigned long)delay);
		resend_ike_v1_msg(st, "EVENT_v1_RETRANSMIT");
		event_schedule(EVENT_v1_RETRANSMIT, delay, st);
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
		if (try != 0 && try != try_limit) {
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
				} else {
					/* no whack: just log to syslog */
					libreswan_log("%s", story);
				}
			} else {
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
	}
}

static void retransmit_v2_msg(struct state *st)
{
	time_t delay = 0;
	struct connection *c;
	unsigned long try;
	unsigned long try_limit;
	const char *details = "";

	passert(st != NULL);
	c = st->st_connection;
	try_limit = c->sa_keying_tries;
	try = st->st_try + 1;

	DBG(DBG_CONTROL, {
		ipstr_buf b;
		DBG_log("handling event EVENT_v2_RETRANSMIT for %s \"%s\" #%lu attempt %lu of %lu",
			ipstr(&c->spd.that.host_addr, &b), c->name,
			st->st_serialno, try, try_limit);
	});

	/* first calculate delay as the value BEFORE backoff */
	if (st->st_retransmit < maximum_retransmissions) {
		delay = event_retransmit_delay_0;
	} else if (st->st_state == STATE_PARENT_I1 &&
		c->sa_keying_tries == 0 &&
		st->st_retransmit < maximum_retransmissions_initial) {
		delay = event_retransmit_delay_0;
	} else if ((st->st_state == STATE_PARENT_I2 ||
			st->st_state == STATE_PARENT_I3) &&
		st->st_retransmit < maximum_retransmissions_quick_r1) {
		delay = event_retransmit_delay_0;
	}

	if (DBGP(IMPAIR_RETRANSMITS)) {
		libreswan_log(
			"supressing retransmit because IMPAIR_RETRANSMITS is set");
		delay = 0;
		try = 0;
	}

	if (delay != 0) {
		/*
		 * Very carefully calculate capped exponential backoff.
		 * The test is expressed as a right shift to avoid overflow.
		 * Even then, we must avoid a right shift of the width of
		 * the data or more since it is not defined by the C standard.
		 * Surely a bound of 8 (factor of 256) is safe and more than enough.
		 */
		u_int8_t x = st->st_retransmit++;	/* ??? odd type */

		delay = (x > 8 ||
			EVENT_RETRANSMIT_DELAY_CAP >> x < delay) ?
			EVENT_RETRANSMIT_DELAY_CAP : delay << x;

		whack_log(RC_RETRANSMISSION,
			"%s: retransmission; will wait %lus for response",
			enum_name(&state_names, st->st_state),
			(unsigned long)delay);
		send_ike_msg(st, "EVENT_v2_RETRANSMIT");
		event_schedule(EVENT_v2_RETRANSMIT, delay, st);
		return;
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
		break;
	}

	loglog(RC_NORETRANSMISSION,
		"max number of retransmissions (%d) reached %s%s",
		st->st_retransmit,
		enum_show(&state_names, st->st_state),
		details);

	if (try != 0 && try != try_limit) {
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

		/* ??? DBG and real-world code mixed */
		if (!DBGP(DBG_WHACKWATCH)) {
			if (st->st_whack_sock != NULL_FD) {
				/*
				 * Release whack because the observer will
				 * get bored.
				 */
				loglog(RC_COMMENT, "%s, but releasing whack",
					story);
				release_pending_whacks(st, story);
			} else {
				/* no whack: just log to syslog */
				libreswan_log("%s", story);
			}
		} else {
			loglog(RC_COMMENT, "%s", story);
		}

		if (try % 3 == 0 &&
			(c->policy & POLICY_IKEV1_DISABLE) == LEMPTY) {
			/*
			 * so, let's retry with IKEv1, alternating every
			 * three messages
			 */
			c->failed_ikev2 = TRUE;
			loglog(RC_COMMENT, "next attempt will be IKEv1");
		}
		ipsecdoi_replace(st, LEMPTY, LEMPTY, try);
	}

	delete_state(st);
}

/*
 * Handle events at head of list, if it is their time.
 */
void handle_timer_event(void)
{
	while (evlist != NULL && !monobefore(mononow(), evlist->ev_time)) {
		handle_next_timer_event();
	}
}

static void liveness_check(struct state *st)
{
	struct state *pst;
	struct connection *c = st->st_connection;
	deltatime_t last_msg_age;

	passert(st->st_ikev2);

	/* this should be called on a child sa */
	if (IS_CHILD_SA(st)) {
		pst = state_with_serialno(st->st_clonedfrom);
		if (pst == NULL) {
			DBG(DBG_CONTROL,
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
		if (last_liveness.mono_secs == UNDEFINED_TIME)
			last_liveness = tm;

		DBG(DBG_CONTROL,
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
			DBG(DBG_CONTROL,
				DBG_log("liveness_check - peer has not responded in %ld seconds, with a timeout of %ld, taking action",
					(long)deltasecs(monotimediff(tm, last_liveness)),
					(long)timeout));
			switch (c->dpd_action) {
			case DPD_ACTION_CLEAR:
				libreswan_log(
					"IKEv2 peer liveness - clearing connection");
				delete_states_by_connection(c, TRUE);
				unroute_connection(c);
				return;

			case DPD_ACTION_RESTART:
				libreswan_log("IKEv2 peer liveness - restarting all connections that share this peer");
				restart_connections_by_peer(c);
				return;

			case DPD_ACTION_HOLD:
				DBG(DBG_CONTROL,
					DBG_log("liveness_check - handling default by rescheduling"));
				break;

			default:
				bad_case(c->dpd_action);
			}

		} else {
			stf_status ret = ikev2_send_informational(st);

			if (ret != STF_OK) {
				DBG(DBG_CONTROL,
					DBG_log("failed to send informational"));
				return;
			}
		}
	}

	DBG(DBG_CONTROL,
		DBG_log("liveness_check - peer is ok"));
	delete_liveness_event(st);
	event_schedule(EVENT_v2_LIVENESS,
		deltasecs(c->dpd_delay) >= MIN_LIVENESS ?
			deltasecs(c->dpd_delay) : MIN_LIVENESS,
		st);
}

void handle_next_timer_event(void)
{
	struct event *ev = evlist;
	enum event_type type;
	struct state *st;

	if (ev == (struct event *) NULL)
		return;

	evlist = evlist->ev_next;	/* Ok, we'll handle this event */
	type = ev->ev_type;
	st = ev->ev_state;

	DBG(DBG_CONTROL, {
		DBG_log("handling event %s",
			enum_show(&timer_event_names, type));
		if (evlist != (struct event *) NULL) {
			DBG_log("event after this is %s in %ld seconds",
				enum_show(&timer_event_names, evlist->ev_type),
				(long) deltasecs(monotimediff(evlist->ev_time, mononow())));
		} else {
			DBG_log("no more events are scheduled");
		}
	});

	/*
	 * for state-associated events, pick up the state pointer
	 * and remove the backpointer from the state object.
	 * We'll eventually either schedule a new event, or delete the state.
	 */
	passert(GLOBALS_ARE_RESET());
	if (st != NULL) {
		if (type == EVENT_DPD || type == EVENT_DPD_TIMEOUT) {
			passert(st->st_dpd_event == ev);
			st->st_dpd_event = NULL;
		} else if (type == EVENT_v2_LIVENESS) {
			passert(st->st_liveness_event == ev);
			st->st_liveness_event = NULL;
		} else {
			passert(st->st_event == ev);
			st->st_event = NULL;
		}
		set_cur_state(st);
	}

	switch (type) {
	case EVENT_REINIT_SECRET:
		passert(st == NULL);
		DBG(DBG_CONTROL,
			DBG_log("event EVENT_REINIT_SECRET handled"));
		init_secret();
		break;

#ifdef KLIPS
	case EVENT_SHUNT_SCAN:
		passert(st == NULL);
		scan_proc_shunts();
		break;
#endif

	case EVENT_PENDING_DDNS:
		passert(st == NULL);
		connection_check_ddns();
		break;

	case EVENT_PENDING_PHASE2:
		passert(st == NULL);
		connection_check_phase2();
		break;

	case EVENT_LOG_DAILY:
		daily_log_event();
		break;

	case EVENT_v1_RETRANSMIT:
		retransmit_v1_msg(st);
		break;

	case EVENT_v2_RETRANSMIT:
		retransmit_v2_msg(st);
		break;

	case EVENT_v2_LIVENESS:
		liveness_check(st);
		break;

	case EVENT_SA_REPLACE:
	case EVENT_SA_REPLACE_IF_USED:
	{
		struct connection *c = st->st_connection;
		so_serial_t newest = IS_IKE_SA(st) ?
			c->newest_isakmp_sa : c->newest_ipsec_sa;

		if (newest != SOS_NOBODY && newest > st->st_serialno) {
			/* not very interesting: no need to replace */
			DBG(DBG_LIFECYCLE,
				libreswan_log(
					"not replacing stale %s SA: #%lu will do",
					IS_IKE_SA(st) ?
					"ISAKMP" : "IPsec", newest));
		} else if (type == EVENT_SA_REPLACE_IF_USED &&
			!monobefore(mononow(), monotimesum(st->st_outbound_time, c->sa_rekey_margin))) {
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
			/* ??? we are abusing the DBG mechanism to control
			 * normal log output.
			 */
			DBG(DBG_LIFECYCLE,
				libreswan_log(
					"not replacing stale %s SA: inactive for %lds",
					IS_IKE_SA(st) ? "ISAKMP" : "IPsec",
					(long)deltasecs(monotimediff(mononow(),
						st->st_outbound_time))));
		} else {
			/* ??? we are abusing the DBG mechanism to control
			 * normal log output.
			 */
			DBG(DBG_LIFECYCLE,
				libreswan_log("replacing stale %s SA",
					IS_IKE_SA(st) ? "ISAKMP" : "IPsec"));
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
		} else {
			satype = "IPsec";
			latest = c->newest_ipsec_sa;
		}

		if (st->st_serialno < latest) {
			/* not very interesting: already superseded */
			DBG(DBG_LIFECYCLE,
				libreswan_log("%s SA expired (superseded by #%lu)",
					satype, latest));
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
			set_suspended(st, NULL);
		}
#endif
		if (st->st_ikev2 && IS_IKE_SA(st)) {
			/* IKEv2 parent, delete children too */
			delete_my_family(st, FALSE);
		} else {
			delete_state(st);
		}
		break;

	case EVENT_DPD:
		dpd_event(st);
		break;

	case EVENT_DPD_TIMEOUT:
		dpd_timeout(st);
		break;

	case EVENT_NAT_T_KEEPALIVE:
		nat_traversal_ka_event();
		break;

	case EVENT_CRYPTO_FAILED:
		DBG(DBG_CONTROL,
			DBG_log("event crypto_failed on state #%lu, aborting",
				st->st_serialno));
		delete_state(st);
		break;

	default:
		loglog(RC_LOG_SERIOUS,
			"INTERNAL ERROR: ignoring unknown expiring event %s",
			enum_show(&timer_event_names, type));
	}

	pfree(ev);
	reset_cur_state();
}

/*
 * Return the time until the next event in the queue
 * expires (positive), or 0 if one has expired, or -1 if no events in queue.
 */
long next_event(void)
{
	monotime_t nw;

	if (evlist == (struct event *) NULL) {
		DBG(DBG_CONTROLMORE, DBG_log("no pending events"));
		return -1;
	}

	nw = mononow();

	DBG(DBG_CONTROL, {
			if (evlist->ev_state == NULL) {
				DBG_log("next event %s in %ld seconds",
					enum_show(&timer_event_names,
						evlist->ev_type),
					(long)deltasecs(monotimediff(evlist->ev_time, nw)));
			} else {
				DBG_log("next event %s in %ld seconds for #%lu",
					enum_show(&timer_event_names,
						evlist->ev_type),
					(long)deltasecs(monotimediff(evlist->ev_time, nw)),
					evlist->ev_state->st_serialno);
			}
		});

	if (monobefore(nw, evlist->ev_time))
		return deltasecs(monotimediff(evlist->ev_time, nw));
	else
		return 0;
}

/*
 * Delete an event.
 */
void delete_event(struct state *st)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("deleting event for #%ld", st->st_serialno));
	if (st->st_event != (struct event *) NULL) {
		struct event **ev;

		for (ev = &evlist;; ev = &(*ev)->ev_next) {
			if (*ev == NULL) {
				DBG(DBG_CONTROL,
					DBG_log("event %s to be deleted not found",
						enum_show(&timer_event_names,
							st->st_event->ev_type)));
				break;
			}
			if ((*ev) == st->st_event) {
				*ev = (*ev)->ev_next;

				if (st->st_event->ev_type == EVENT_v1_RETRANSMIT)
					st->st_retransmit = 0;
				pfree(st->st_event);
				st->st_event = (struct event *) NULL;

				break;
			}
		}
	}
}

void delete_liveness_event(struct state *st)
{
	if (st->st_liveness_event != NULL) {
		struct event **ev;

		DBG(DBG_CONTROL,
			DBG_log("state %ld deleting liveness event",
				st->st_serialno));

		for (ev = &evlist;; ev = &(*ev)->ev_next) {
			if (*ev == NULL) {
				DBG(DBG_CONTROL,
					DBG_log("liveness event not found"));
				break;
			}
			if ((*ev) == st->st_liveness_event) {
				*ev = (*ev)->ev_next;
				pfree(st->st_liveness_event);
				st->st_liveness_event = NULL;
				break;
			}
		}
	}
}

/*
 * Delete a DPD event.
 */
void attributed_delete_dpd_event(struct state *st, const char *file, int lineno)
{
	DBG(DBG_DPD | DBG_CONTROL,
		DBG_log("state: %ld requesting DPD event %s to be deleted by %s:%d",
			st->st_serialno,
			(st->st_dpd_event != NULL ?
				enum_show(&timer_event_names,
					st->st_dpd_event->ev_type) :
				"none"),
			file, lineno));

	if (st->st_dpd_event != (struct event *) NULL) {
		struct event **ev;

		for (ev = &evlist;; ev = &(*ev)->ev_next) {
			if (*ev == NULL) {
				DBG(DBG_DPD | DBG_CONTROL,
					DBG_log("DPD event %s to be deleted not found",
						enum_show(&timer_event_names,
							st->st_dpd_event->ev_type)));
				break;
			}
			if ((*ev) == st->st_dpd_event) {
				*ev = (*ev)->ev_next;
				pfree(st->st_dpd_event);
				st->st_dpd_event = (struct event *) NULL;
				break;
			}
		}
	}
}

/*
 * dump list of events to whacklog
 */
void timer_list(void)
{
	monotime_t nw;
	struct event *ev = evlist;

	if (ev == (struct event *) NULL) { /* Just paranoid */
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
			st != NULL ? st->st_serialno : 0);

		if (st != NULL && st->st_connection != NULL)
			whack_log(RC_LOG, "    connection: \"%s\"",
				st->st_connection->name);

		ev = ev->ev_next;
	}
}

/*
 * XXX --- hack alert, but I want to avoid adding new pluto-level
 *   command line arguments for now --- they need to all be whack
 * level items, and all command line arguments go away.
 */

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

void init_timer(void)
{
	event_retransmit_delay_0 = envnumber("PLUTO_EVENT_RETRANSMIT_DELAY", 1, secs_per_minute, event_retransmit_delay_0);
	maximum_retransmissions = envnumber("PLUTO_MAXIMUM_RETRANSMISSIONS", 0, 20, maximum_retransmissions);
	maximum_retransmissions_initial = envnumber("PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL", 0, 20, maximum_retransmissions_initial);
	maximum_retransmissions_quick_r1 = envnumber("PLUTO_MAXIMUM_RETRANSMISSIONS_QUICK_R1", 0, 20, maximum_retransmissions_quick_r1);
}
