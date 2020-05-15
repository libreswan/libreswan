/* timer event handling
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
 * Copyright (C) 2017-2020 Andrew Cagney <cagney@gnu.org>
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
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev1_dpd.h"
#include "ikev2.h"
#include "ikev2_redirect.h"
#include "pending.h" /* for flush_pending_by_connection */
#include "ikev1_xauth.h"
#include "xauth.h"
#include "kernel.h"		/* for kernel_ops */
#include "nat_traversal.h"
#include "pluto_sd.h"
#include "retry.h"
#include "fetch.h"		/* for check_crls() */
#include "pluto_stats.h"
#include "iface.h"
#include "ikev2_liveness.h"

struct pluto_event **state_event(struct state *st, enum event_type type)
{
	/*
	 * Return a pointer to the event in the state object.
	 *
	 * XXX: why not just have an array and index it by KIND?
	 */
	switch (type) {
	case EVENT_v2_ADDR_CHANGE:
		return &st->st_addr_change_event;
		break;

	case EVENT_DPD:
	case EVENT_DPD_TIMEOUT:
		return &st->st_dpd_event;

	case EVENT_v2_LIVENESS:
		return &st->st_liveness_event;

	case EVENT_v2_RELEASE_WHACK:
		return &st->st_rel_whack_event;

	case EVENT_v1_SEND_XAUTH:
		return &st->st_send_xauth_event;

	case EVENT_RETRANSMIT:
		return &st->st_retransmit_event;

	case EVENT_SO_DISCARD:
	case EVENT_SA_REKEY:
	case EVENT_SA_REPLACE:
	case EVENT_SA_EXPIRE:
	case EVENT_v1_SA_REPLACE_IF_USED:
	case EVENT_CRYPTO_TIMEOUT:
	case EVENT_PAM_TIMEOUT:
	case EVENT_v2_INITIATE_CHILD:
	case EVENT_v2_REDIRECT:
		/*
		 * Many of these don't make sense - however that's
		 * what happens when (the replaced) default: is used.
		 */
		return &st->st_event;

	case EVENT_RETAIN:
	case EVENT_NULL:
		return NULL;
	}
	bad_case(type);
}

/*
 * This file has the event handling routines. Events are
 * kept as a linked list of event structures. These structures
 * have information like event type, expiration time and a pointer
 * to event specific data (for example, to a state structure).
 */

static event_callback_routine timer_event_cb;
static void timer_event_cb(evutil_socket_t unused_fd UNUSED,
			   const short unused_event UNUSED,
			   void *arg)
{
	threadtime_t inception = threadtime_start();

	/*
	 * Get rid of the old timer event before calling the timer
	 * event processor (was deleting the old timer after calling
	 * the processor giving the impression that the processor's
	 * just created event was being deleted).
	 */
	struct state *st;
	enum event_type type;
	const char *event_name;
	{
		struct pluto_event *ev = arg;
		dbg("%s: processing event@%p", __func__, ev);
		passert(ev != NULL);
		type = ev->ev_type;
		event_name = enum_short_name(&timer_event_names, type);
		st = ev->ev_state;	/* note: *st might be changed; XXX: why? */
		passert(st != NULL);

		dbg("handling event %s for %s state #%lu",
		    enum_show(&timer_event_names, type),
		    (st->st_clonedfrom == SOS_NOBODY) ? "parent" : "child",
		    st->st_serialno);

#if 0
		/*
		 * XXX: this line, which is a merger of the above two
		 * lines, leaks into the expected test output causing
		 * failures.
		 */
		dbg("%s: processing %s-event@%p for %s SA #%lu in state %s",
		    __func__, event_name, ev,
		    IS_IKE_SA(st) ? "IKE" : "CHILD",
		    st->st_serialno, st->st_state->short_name);
#endif

		struct pluto_event **evp = state_event(st, type);
		if (evp == NULL) {
			LOG_PEXPECT("#%lu has no .st_event field for %s",
				    st->st_serialno, enum_name(&timer_event_names, type));
			return;
		}
		if (*evp != ev) {
			LOG_PEXPECT("#%lu .st_event is %p but should be %s-pe@%p",
				    st->st_serialno, *evp,
				    enum_name(&timer_event_names, (*evp)->ev_type),
				    ev);
			return;
		}
		delete_pluto_event(evp);
		arg = ev = *evp = NULL; /* all gone */
	}

	pexpect_reset_globals();
	so_serial_t old_state = push_cur_state(st);
	pexpect(old_state == SOS_NOBODY); /* since globals are reset */
	statetime_t start = statetime_backdate(st, &inception);

	/*
	 * Check that st is as expected for the event type.
	 *
	 * For an event type associated with a state, remove the
	 * backpointer from the appropriate slot of the state object.
	 *
	 * We'll eventually either schedule a new event, or delete the
	 * state.
	 */
	switch (type) {

	case EVENT_v2_ADDR_CHANGE:
		dbg("#%lu IKEv2 local address change", st->st_serialno);
		ikev2_addr_change(st);
		break;

	case EVENT_v2_RELEASE_WHACK:
		dbg("%s releasing whack for #%lu %s (sock="PRI_FD")",
		    enum_show(&timer_event_names, type),
		    st->st_serialno,
		    st->st_state->name,
		    pri_fd(st->st_whack_sock));
		release_pending_whacks(st, "release whack");
		break;

	case EVENT_RETRANSMIT:
		dbg("IKEv%d retransmit event", st->st_ike_version);
		switch (st->st_ike_version) {
		case IKEv2:
			retransmit_v2_msg(st);
			break;
		case IKEv1:
			retransmit_v1_msg(st);
			break;
		default:
			bad_case(st->st_ike_version);
		}
		break;

	case EVENT_v1_SEND_XAUTH:
		dbg("XAUTH: event EVENT_v1_SEND_XAUTH #%lu %s",
		    st->st_serialno, st->st_state->name);
		xauth_send_request(st);
		break;

	case EVENT_v2_INITIATE_CHILD:
		ikev2_child_outI(st);
		break;

	case EVENT_v2_LIVENESS:
		liveness_check(st);
		break;

	case EVENT_SA_REKEY:
		pexpect(st->st_ike_version == IKEv2);
		v2_event_sa_rekey(st);
		break;

	case EVENT_SA_REPLACE:
	case EVENT_v1_SA_REPLACE_IF_USED:
		switch (st->st_ike_version) {
		case IKEv2:
			pexpect(type == EVENT_SA_REPLACE);
			v2_event_sa_replace(st);
			break;
		case IKEv1:
			pexpect(type == EVENT_SA_REPLACE ||
				type == EVENT_v1_SA_REPLACE_IF_USED);
			struct connection *c = st->st_connection;
			const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";

			so_serial_t newer_sa = get_newer_sa_from_connection(st);
			if (newer_sa != SOS_NOBODY) {
				/* not very interesting: no need to replace */
				dbg("not replacing stale %s SA %lu; #%lu will do",
				    satype, st->st_serialno, newer_sa);
			} else if (type == EVENT_v1_SA_REPLACE_IF_USED &&
				   !monobefore(mononow(), monotime_add(st->st_outbound_time, c->sa_rekey_margin))) {
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
				dbg("not replacing stale %s SA: inactive for %jds",
				    satype, deltasecs(monotimediff(mononow(), st->st_outbound_time)));
			} else {
				dbg("replacing stale %s SA",
				    IS_IKE_SA(st) ? "ISAKMP" : "IPsec");
				/*
				 * XXX: this call gets double billed -
				 * both to the state being deleted and
				 * to the new state being created.
				 */
				ipsecdoi_replace(st, 1);
			}

			event_delete(EVENT_v2_LIVENESS, st);
			event_delete(EVENT_DPD, st);
			event_schedule(EVENT_SA_EXPIRE, st->st_replace_margin, st);
			break;
		default:
			bad_case(st->st_ike_version);
		}
		break;

	case EVENT_SA_EXPIRE:
	{
		struct connection *c = st->st_connection;
		const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";
		so_serial_t newer_sa = get_newer_sa_from_connection(st);

		if (newer_sa != SOS_NOBODY) {
			/* not very interesting: already superseded */
			dbg("%s SA expired (superseded by #%lu)",
			    satype, newer_sa);
		} else if (!IS_IKE_SA_ESTABLISHED(st)) {
			/* not very interesting: failed IKE attempt */
			dbg("un-established partial CHILD SA timeout (%s)",
			    type == EVENT_SA_EXPIRE ? "SA expired" : "Responder timeout");
			pstat_sa_failed(st, REASON_EXCHANGE_TIMEOUT);
		} else {
			libreswan_log("%s %s (%s)", satype,
				      type == EVENT_SA_EXPIRE ? "SA expired" : "Responder timeout",
				      (c->policy & POLICY_DONT_REKEY) ?
				      "--dontrekey" : "LATEST!");
		}

		/* Delete this state object.  It must be in the hash table. */
		switch (st->st_ike_version) {
		case IKEv2:
			if (IS_IKE_SA(st)) {
				/* IKEv2 parent, delete children too */
				delete_ike_family(pexpect_ike_sa(st),
						  PROBABLY_SEND_DELETE);
				/* note: no md->st to clear */
			} else {
				struct ike_sa *ike = ike_sa(st, HERE);
				if (ike == NULL) {
					/*
					 * XXX: SNAFU with IKE SA
					 * replacing itself (but not
					 * deleting its children?)
					 * simultaneous to a CHILD SA
					 * failing to establish and
					 * attempting to delete /
					 * replace itself?
					 *
					 * Because these things are
					 * not serialized it is hard
					 * to say.
					 */
					loglog(RC_LOG_SERIOUS, "CHILD SA #%lu lost its IKE SA",
					       st->st_serialno);
					delete_state(st);
					st = NULL;
				} else {
					/* note: no md->st to clear */
					passert(st != &ike->sa);
					schedule_next_child_delete(st, ike);
					st = NULL;
				}
			}
			break;
		case IKEv1:
			delete_state(st);
			/* note: no md->st to clear */
			/* st = NULL; */
			break;
		default:
			bad_case(st->st_ike_version);
		}
		break;
	}

	case EVENT_SO_DISCARD:
		/*
		 * The state failed to complete within a reasonable
		 * time, or the state failed but was left to live for
		 * a while so re-transmits could work.  Either way,
		 * time to delete it.
		 */
		passert(st != NULL);
		deltatime_t timeout = (st->st_ike_version == IKEv2 ? MAXIMUM_RESPONDER_WAIT_DELAY :
				       st->st_connection->r_timeout);
		deltatime_buf dtb;
		libreswan_log("deleting incomplete state after %s seconds",
			      str_deltatime(timeout, &dtb));
		/*
		 * If no other reason has been given then this is a
		 * timeout.
		 */
		pstat_sa_failed(st, REASON_EXCHANGE_TIMEOUT);
		/*
		 * XXX: this is scary overkill - delete_state() likes
		 * to resurect things and/or send messages.  What's
		 * needed is a lower-level discard_state() that just
		 * does its job.
		 */
		delete_state(st);
		break;

	case EVENT_v2_REDIRECT:
		initiate_redirect(st);
		break;

	case EVENT_DPD:
		dpd_event(st);
		break;

	case EVENT_DPD_TIMEOUT:
		dpd_timeout(st);
		break;

	case EVENT_CRYPTO_TIMEOUT:
		dbg("event crypto_failed on state #%lu, aborting",
		    st->st_serialno);
		pstat_sa_failed(st, REASON_CRYPTO_TIMEOUT);
		delete_state(st);
		/* note: no md->st to clear */
		break;

#ifdef XAUTH_HAVE_PAM
	case EVENT_PAM_TIMEOUT:
		dbg("PAM thread timeout on state #%lu", st->st_serialno);
		xauth_pam_abort(st);
		/*
		 * Things get cleaned up when the PAM process exits.
		 *
		 * Should this schedule an event for the case when the
		 * child process (which is SIGKILLed) doesn't exit!?!
		 */
		break;
#endif

	default:
		bad_case(type);
	}

	statetime_stop(&start, "%s() %s", __func__, event_name);
	pop_cur_state(old_state);
}

/*
 * Delete all of the lifetime events (if any).
 *
 * Most lifetime events (things that kill the state) try to share a
 * single .st_event.  However, there has been and likely will be
 * exceptions (for instance the retransmit timer), and the code below
 * is written to deal with it.
 *
 * XXX:
 *
 * The decision to have all the loosely lifetime related timers
 * (retransmit, rekey, replace, ...) share a single .st_event field is
 * ...  unfortunate.  The code has to constantly juggle the field
 * deciding which event is next.  Far easier to set and forget each
 * independently.  This is why the retransmit timer has been split
 * off.
 */
void delete_event(struct state *st)
{
	struct liveness {
		const char *name;
		struct pluto_event **event;
	} events[] = {
		{ "st_event", &st->st_event, },
	};
	for (unsigned e = 0; e < elemsof(events); e++) {
		struct liveness *l = &events[e];
		if (*(l->event) == NULL) {
			dbg("state #%lu has no .%s to delete", st->st_serialno,
			    l->name);
		} else {
			dbg("state #%lu deleting .%s %s",
			    st->st_serialno, l->name,
			    enum_show(&timer_event_names,
				      (*l->event)->ev_type));
			delete_pluto_event(l->event);
		}
	}
}

/*
 * This routine schedules a state event.
 */
void event_schedule(enum event_type type, deltatime_t delay, struct state *st)
{
	passert(st != NULL);
	/*
	 * Scheduling a month into the future is most likely a bug.
	 * pexpect() causes us to flag this in our test cases
	 */
	pexpect(deltasecs(delay) < secs_per_day * 31);

	const char *en = enum_name(&timer_event_names, type);

	struct pluto_event **evp = state_event(st, type);
	if (evp == NULL) {
		LOG_PEXPECT("#%lu has no .st_*event field for %s",
			    st->st_serialno,
			    enum_name(&timer_event_names, type));
		return;
	}
	if (*evp != NULL) {
		/* help debugging by stumbling on */
		LOG_PEXPECT("#%lu already has a scheduled %s; forcing replacement",
			    st->st_serialno,
			    enum_name(&timer_event_names, type));
		delete_pluto_event(evp);
	}

	struct pluto_event *ev = alloc_thing(struct pluto_event, en);
	dbg("%s: newref %s-pe@%p", __func__, en, ev);
	ev->ev_type = type;
	ev->ev_name = en;
	ev->ev_state = st;
	ev->ev_time = monotime_add(mononow(), delay);
	*evp = ev;

	deltatime_buf buf;
	dbg("inserting event %s, timeout in %s seconds for #%lu",
	    en, str_deltatime(delay, &buf),
	    ev->ev_state->st_serialno);

	fire_timer_photon_torpedo(&ev->ev, timer_event_cb, ev, delay);
}

/*
 * Delete a state backlinked event (if any); leave *evp == NULL.
 */
void event_delete(enum event_type type, struct state *st)
{
	struct pluto_event **evp = state_event(st, type);
	if (evp == NULL) {
		LOG_PEXPECT("#%lu has no .st_event field for %s",
			    st->st_serialno, enum_name(&timer_event_names, type));
		return;
	}
	if (*evp != NULL) {
		dbg("#%lu requesting %s-pe@%p be deleted",
		    st->st_serialno, enum_name(&timer_event_names, (*evp)->ev_type), *evp);
		pexpect(st == (*evp)->ev_state);
		delete_pluto_event(evp);
		pexpect((*evp) == NULL);
	};
}

void event_force(enum event_type type, struct state *st)
{
	event_delete(type, st);
	deltatime_t delay = deltatime(0);
	event_schedule(type, delay, st);
}

void call_state_event_inline(struct logger *logger, struct state *st,
			     enum event_type event)
{
	/* sanity checks */
	struct pluto_event **evp = state_event(st, event);
	if (evp == NULL) {
		log_message(RC_COMMENT, logger, "%s is not a valid event",
			    enum_name(&timer_event_names, event));
		return;
	}
	if (*evp == NULL) {
		log_message(RC_COMMENT, logger, "no handler for %s",
			    enum_name(&timer_event_names, event));
		return;
	}
	if ((*evp)->ev_type != event) {
		log_message(RC_COMMENT, logger, "handler for %s is actually %s",
			    enum_name(&timer_event_names, event),
			    enum_name(&timer_event_names, (*evp)->ev_type));
		return;
	}
	/*
	 * XXX: can this kill off the old event when it is still
	 * pending?
	 */
	log_message(RC_COMMENT, logger, "calling %s",
		    enum_name(&timer_event_names, event));
	timer_event_cb(0/*sock*/, 0/*event*/, *evp);
}
