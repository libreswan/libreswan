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
 * Copyright (C) 2017-2021 Andrew Cagney
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
#include "ikev2_redirect.h"
#include "pending.h" /* for flush_pending_by_connection */
#include "ikev1_xauth.h"
#ifdef USE_PAM_AUTH
#include "pam_auth.h"
#endif
#include "kernel.h"		/* for kernel_ops */
#include "nat_traversal.h"
#include "pluto_sd.h"
#include "ikev1_retransmit.h"
#include "ikev2_retransmit.h"
#include "pluto_stats.h"
#include "iface.h"
#include "ikev2_liveness.h"
#include "ikev2_mobike.h"
#include "ikev2_delete.h"		/* for submit_v2_delete_exchange() */
#include "ikev1_replace.h"
#include "ikev2_replace.h"
#include "terminate.h"

static void dispatch_event(struct state *st, enum event_type event_type,
			   deltatime_t event_delay, struct logger *logger,
			   bool detach_whack);

static int state_event_cmp(const void *lp, const void *rp)
{
	const struct state_event *const *le = lp;
	const struct state_event *const *re = rp;
	monotime_t l = (*le)->ev_time;
	monotime_t r = (*re)->ev_time;
	int sign = monotime_sub_sign(l, r);
	monotime_buf lb, rb;
	dbg("%s - %s = %d", str_monotime(l, &lb), str_monotime(r, &rb), sign);
	return sign;
}

void state_event_sort(const struct state_event **events, unsigned nr_events)
{
	qsort(events, nr_events, sizeof(*events), state_event_cmp);
}


struct state_event **state_event_slot(struct state *st, enum event_type type)
{
	/*
	 * Return a pointer to the event in the state object.
	 *
	 * XXX: why not just have an array and index it by KIND?
	 *
	 * Because events come in groups.  For instance, for IKEv2,
	 * only one of REPLACE / EXPIRE are ever scheduled.
	 *
	 * XXX: but most don't.
	 */
	switch (type) {

	case EVENT_RETRANSMIT:
		return &st->st_retransmit_event;

	case EVENT_v1_SEND_XAUTH:
		return &st->st_v1_send_xauth_event;
	case EVENT_v1_DPD:
	case EVENT_v1_DPD_TIMEOUT:
		return &st->st_v1_dpd_event;

	case EVENT_CRYPTO_TIMEOUT:
	case EVENT_v1_DISCARD:
	case EVENT_v1_EXPIRE:
	case EVENT_v1_PAM_TIMEOUT:
	case EVENT_v1_REPLACE:
		/*
		 * Many of these don't make sense - however that's
		 * what happens when (the replaced) default: is used.
		 */
		return &st->st_event;

	case EVENT_v2_LIVENESS:
		return &st->st_v2_liveness_event;
	case EVENT_v2_ADDR_CHANGE:
		return &st->st_v2_addr_change_event;
	case EVENT_v2_REKEY:
		return &st->st_v2_refresh_event;
	case EVENT_v2_REPLACE:
	case EVENT_v2_EXPIRE:
		return &st->st_v2_lifetime_event;
	case EVENT_v2_DISCARD:
		return &st->st_event;

	case EVENT_RETAIN:
	case EVENT_NULL:
		return NULL;
	}
	bad_case(type);
}

void delete_state_event(struct state_event **evp, where_t where)
{
	struct state_event *e = (*evp);
	if (e == NULL) {
		return;
	}

	passert(e->ev_state != NULL);

	dbg("#%lu deleting %s",
	    e->ev_state->st_serialno,
	    enum_name(&event_type_names, e->ev_type));

	/* first the event */
	destroy_timeout(&e->timeout);
	/* then the structure */
	dbg_free("state-event", e, where);
	pfree(e);
	*evp = NULL;

}

/*
 * This file has the event handling routines. Events are
 * kept as a linked list of event structures. These structures
 * have information like event type, expiration time and a pointer
 * to event specific data (for example, to a state structure).
 */

static void timer_event_cb(void *arg, const struct timer_event *event)
{
	/*
	 * Get rid of the old timer event before calling the timer
	 * event processor.
	 */
	struct state *st;
	enum event_type event_type;
	const char *event_name;
	deltatime_t event_delay;

	{
		struct state_event *ev = arg;
		passert(ev != NULL);
		event_type = ev->ev_type;
		event_name = enum_name(&event_type_names, event_type);
		event_delay = ev->ev_delay;
		st = ev->ev_state;	/* note: *st might be changed; XXX: why? */
		passert(st != NULL);
		passert(event_name != NULL);

		ldbg(event->logger, "%s: processing %s-event@%p for %s SA "PRI_SO" in state %s",
		     __func__, event_name, ev,
		     IS_IKE_SA(st) ? "IKE" : "CHILD",
		     pri_so(st->st_serialno), st->st_state->short_name);

		struct state_event **evp = state_event_slot(st, event_type);
		if (evp == NULL) {
			llog_pexpect(st->logger, HERE,
				     ".st_event field is NULL for %s",
				     event_name);
			return;
		}

		if (*evp != ev) {
			llog_pexpect(st->logger, HERE,
				     ".st_event is %p but should be %s-pe@%p",
				     *evp, event_name, ev);
			return;
		}

		/* everything useful has been extracted */
		delete_state_event(evp, HERE);
		arg = ev = *evp = NULL; /* all gone */
	}

	statetime_t start = statetime_backdate(st, &event->inception);
	dispatch_event(st, event_type, event_delay, event->logger,
		       /*detach_whack*/false);
	statetime_stop(&start, "%s() %s", __func__, event_name);
}

static void dispatch_event(struct state *st, enum event_type event_type,
			   deltatime_t event_delay, struct logger *logger,
			   bool detach_whack)
{
	const monotime_t now = mononow();
	/*
	 * Check that st is as expected for the event type.
	 *
	 * For an event type associated with a state, remove the
	 * backpointer from the appropriate slot of the state object.
	 *
	 * We'll eventually either schedule a new event, or delete the
	 * state.
	 */
	switch (event_type) {

	case EVENT_v2_ADDR_CHANGE:
		ldbg(st->logger, "#%lu IKEv2 local address change", st->st_serialno);
		ikev2_addr_change(st);
		break;

	case EVENT_RETRANSMIT:
		ldbg(st->logger, "IKEv%d retransmit event", st->st_ike_version);
		switch (st->st_ike_version) {
		case IKEv2:
			event_v2_retransmit(st, now);
			break;
#ifdef USE_IKEv1
		case IKEv1:
			event_v1_retransmit(st, now);
			break;
#endif
		default:
			bad_case(st->st_ike_version);
		}
		break;

#ifdef USE_IKEv1
	case EVENT_v1_SEND_XAUTH:
		ldbg(st->logger, "XAUTH: event EVENT_v1_SEND_XAUTH #%lu %s",
		     st->st_serialno, st->st_state->name);
		xauth_send_request(st);
		break;
#endif

	case EVENT_v2_LIVENESS:
		liveness_check(st);
		break;

	case EVENT_v2_REKEY:
		pexpect(st->st_ike_version == IKEv2);
		event_v2_rekey(st, detach_whack);
		break;

#ifdef USE_IKEv1
	case EVENT_v1_REPLACE:
		event_v1_replace(st, now);
		break;
#endif

	case EVENT_v2_REPLACE:
		event_v2_replace(st, now);
		break;

	case EVENT_v1_EXPIRE:
	{
		struct connection *c = st->st_connection;
		const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";
		so_serial_t newer_sa = get_newer_sa_from_connection(st);

		if (newer_sa != SOS_NOBODY) {
			/* not very interesting: already superseded */
			ldbg(st->logger, "%s SA expired (superseded by #%lu)",
			     satype, newer_sa);
		} else if (!IS_IKE_SA_ESTABLISHED(st) &&
			   !IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
			/* not very interesting: failed IKE attempt */
			ldbg(st->logger, "un-established partial Child SA timeout (SA expired)");
			pstat_sa_failed(st, REASON_EXCHANGE_TIMEOUT);
		} else {
			llog(RC_LOG, st->logger,
			     "%s SA expired (%s)", satype,
			     (c->config->rekey ? "LATEST!" : "--dontrekey"));
		}

		state_attach(st, logger);
		connection_delete_v1_state(&st, HERE);
		break;
	}

	case EVENT_v2_EXPIRE:
	{
		struct connection *c = st->st_connection;
		const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";
		so_serial_t newer_sa = get_newer_sa_from_connection(st);

		if (newer_sa != SOS_NOBODY) {
			/* not very interesting: already superseded */
			ldbg(st->logger, "%s SA expired (superseded by #%lu)",
			     satype, newer_sa);
		} else if (!IS_IKE_SA_ESTABLISHED(st) &&
			   !IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
			/* not very interesting: failed IKE attempt */
			ldbg(st->logger, "un-established partial Child SA timeout (SA expired)");
			pstat_sa_failed(st, REASON_EXCHANGE_TIMEOUT);
		} else {
			llog(RC_LOG, st->logger,
			     "%s SA expired (%s)", satype,
			     (c->config->rekey ? "LATEST!" : "--dontrekey"));
		}

		struct ike_sa *ike = ike_sa(st, HERE);
		if (ike == NULL) {
			/*
			 * XXX: SNAFU with IKE SA replacing
			 * itself (but not deleting its
			 * children?)  simultaneous to a CHILD
			 * SA failing to establish and
			 * attempting to delete / replace
			 * itself?
			 *
			 * ST must be a Child SA (if it were
			 * an IKE SA then ike_sa() would have
			 * found itself).
			 *
			 * Because these things are
			 * not serialized it is hard
			 * to say.
			 */
			struct child_sa *child = pexpect_child_sa(st);
			state_attach(&child->sa, logger);
			llog_pexpect(child->sa.logger, HERE,
				     "Child SA lost its IKE SA #%lu",
				     child->sa.st_clonedfrom);
			connection_delete_child(&child, HERE);
			st = NULL;
		} else if (IS_IKE_SA_ESTABLISHED(st)) {
			/* IKEv2 parent, delete children too */
			ldbg(st->logger, "IKEv2 SA expired, delete whole family");
			send_n_log_delete_ike_family_now(&ike, ike->sa.logger, HERE);
			/* note: no md->st to clear */
			st = NULL;
		} else if (IS_IKE_SA(st)) {
			/* IKEv2 parent, delete children too */
			ldbg(st->logger, "IKEv2 SA expired, delete whole family");
			passert(&ike->sa == st);
			send_n_log_delete_ike_family_now(&ike, ike->sa.logger, HERE);
			/* note: no md->st to clear */
			st = NULL;
		} else if (IS_IKE_SA_ESTABLISHED(&ike->sa)) {
			/* note: no md->st to clear */
			submit_v2_delete_exchange(ike, pexpect_child_sa(st));
			st = NULL;
		} else {
			struct child_sa *child = pexpect_child_sa(st);
			state_attach(&child->sa, logger);
			connection_delete_child(&child, HERE);
			st = NULL;
		}
		break;
	}

	case EVENT_v1_DISCARD:
		/*
		 * The state failed to complete within a reasonable
		 * time, or the state failed but was left to live for
		 * a while so re-transmits could work, or the state is
		 * being garbage collected.  Either way, time to
		 * delete it.
		 */
		state_attach(st, logger);
		if (deltatime_cmp(event_delay, >, deltatime_zero)) {
			/* Don't bother logging 0 delay */
			deltatime_buf dtb;
			llog(RC_LOG, st->logger,
			     "deleting incomplete state after %s seconds",
			     str_deltatime(event_delay, &dtb));
		} else {
			deltatime_buf dtb;
			ldbg(st->logger, 
			     "deleting incomplete state after %s seconds",
			     str_deltatime(event_delay, &dtb));
		}

		/*
		 * If no other reason has been given then this is a
		 * timeout.
		 */
		pstat_sa_failed(st, REASON_EXCHANGE_TIMEOUT);
		/*
		 * XXX: this is scary overkill - delete_state() likes
		 * to resurrect things and/or send messages.  What's
		 * needed is a lower-level discard_state() that just
		 * does its job.
		 *
		 * XXX: for IKEv2, it looks like delete_state() will
		 * stop spontaneously sending messages (and hopefully
		 * spontaneously deleting IKE families).
		 */
		connection_delete_v1_state(&st, HERE);
		break;

	case EVENT_v2_DISCARD:
		/*
		 * The state failed to complete within a reasonable
		 * time, or the state failed but was left to live for
		 * a while so re-transmits could work, or the state is
		 * being garbage collected.  Either way, time to
		 * delete it.
		 */
		state_attach(st, logger);
		if (deltatime_cmp(event_delay, >, deltatime_zero)) {
			/* Don't bother logging 0 delay */
			deltatime_buf dtb;
			llog(RC_LOG, st->logger,
			     "deleting incomplete state after %s seconds",
			     str_deltatime(event_delay, &dtb));
		} else {
			deltatime_buf dtb;
			ldbg(st->logger, 
			     "deleting incomplete state after %s seconds",
			     str_deltatime(event_delay, &dtb));
		}
		/*
		 * Just assume this is a timeout.
		 */
		pstat_sa_failed(st, REASON_EXCHANGE_TIMEOUT);
		/*
		 * An IKEv2 IKE SA must delete all offspring.
		 */
		if (IS_IKE_SA(st)) {
			struct ike_sa *ike = pexpect_ike_sa(st);
			connection_delete_ike_family(&ike, HERE);
		} else {
			struct child_sa *child = pexpect_child_sa(st);
			connection_delete_child(&child, HERE);
		}
		st = NULL;
		break;

#ifdef USE_IKEv1
	case EVENT_v1_DPD:
		event_v1_dpd(st);
		break;

	case EVENT_v1_DPD_TIMEOUT:
		event_v1_dpd_timeout(st);
		break;

#ifdef USE_PAM_AUTH
	case EVENT_v1_PAM_TIMEOUT:
		ldbg(st->logger, "PAM thread timeout on state #%lu", st->st_serialno);
		pam_auth_abort(st, "timeout");
		/*
		 * Things get cleaned up when the PAM process exits.
		 *
		 * Should this schedule an event for the case when the
		 * child process (which is SIGKILLed) doesn't exit!?!
		 */
		break;
#endif
#endif
	case EVENT_CRYPTO_TIMEOUT:
		state_attach(st, logger);
		ldbg(st->logger, "event crypto_failed on state #%lu, aborting",
		     st->st_serialno);
		pstat_sa_failed(st, REASON_CRYPTO_TIMEOUT);
		if (IS_PARENT_SA(st)) {
			struct ike_sa *ike = pexpect_ike_sa(st);
			connection_delete_ike_family(&ike, HERE);
		} else {
			struct child_sa *child = pexpect_child_sa(st);
			connection_delete_child(&child, HERE);
		}
		/* note: no md->st to clear */
		break;


	default:
		bad_case(event_type);
	}
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
	delete_state_event(&st->st_event, HERE);
}

/*
 * This routine schedules a state event.
 */
void event_schedule_where(enum event_type type, deltatime_t delay, struct state *st, where_t where)
{
	passert(st != NULL);
	/*
	 * Scheduling a month into the future is most likely a bug.
	 * pexpect() causes us to flag this in our test cases
	 */
	pexpect(deltasecs(delay) < secs_per_day * 31);

	const char *event_name = enum_name(&event_type_names, type);

	struct state_event **evp = state_event_slot(st, type);
	if (evp == NULL) {
		llog_pexpect(st->logger, where,
			     "#%lu has no .st_*event field for %s",
			     st->st_serialno, event_name);
		return;
	}

	if (*evp != NULL) {
		/* help debugging by stumbling on */
		llog_pexpect(st->logger, where,
			     "#%lu already has %s scheduled; forcing %s",
			     st->st_serialno,
			     enum_name(&event_type_names, (*evp)->ev_type),
			     event_name);
		delete_state_event(evp, where);
	}

	struct state_event *ev = alloc_thing(struct state_event, event_name);
	ev->ev_type = type;
	ev->ev_state = st;
	ev->ev_epoch = mononow();
	ev->ev_delay = delay;
	ev->ev_time = monotime_add(ev->ev_epoch, delay);
	*evp = ev;

	deltatime_buf buf;
	ldbg(st->logger, "%s: newref %s-pe@%p timeout in %s seconds for #%lu",
	     __func__, event_name, ev, str_deltatime(delay, &buf),
	     ev->ev_state->st_serialno);

	schedule_timeout(event_name, &ev->timeout, delay, timer_event_cb, ev);
}

/*
 * Delete a state backlinked event (if any); leave *evp == NULL.
 */
void event_delete_where(enum event_type type, struct state *st, where_t where)
{
	struct state_event **evp = state_event_slot(st, type);
	if (evp == NULL) {
		llog_pexpect(st->logger, where,
			     "#%lu has no .st_event field for %s",
			     st->st_serialno, enum_name(&event_type_names, type));
		return;
	}
	if (*evp != NULL) {
		ldbg(st->logger, "#%lu requesting %s-event@%p be deleted "PRI_WHERE,
		     st->st_serialno, enum_name(&event_type_names, (*evp)->ev_type),
		     *evp, pri_where(where));
		pexpect(st == (*evp)->ev_state);
		delete_state_event(evp, where);
		pexpect((*evp) == NULL);
	};
}

void event_force(enum event_type type, struct state *st)
{
	event_delete(type, st);
	deltatime_t delay = deltatime(0);
	event_schedule(type, delay, st);
}

void whack_impair_call_state_event_handler(struct logger *logger, struct state *st,
					   enum event_type event_type, bool detach_whack)
{
	const char *event_name = enum_name_short(&event_type_names, event_type);
	if (event_name == NULL) {
		llog(RC_COMMENT, logger, "%d is not a valid event", event_type);
		return;
	}

	/* sanity checks */
	struct state_event **evp = state_event_slot(st, event_type);
	if (evp == NULL) {
		llog(RC_COMMENT, logger, "IMPAIR: %s is not a valid event", event_name);
		return;
	}

	/*
	 * Like timer_event_cb(), delete the old event before calling
	 * the event handler.
	 */
	deltatime_t event_delay = deltatime(1);
	if (*evp == NULL) {
		llog(RC_COMMENT, logger,
		     "IMPAIR: no existing %s event to delete", event_name);
	} else if ((*evp)->ev_type != event_type) {
		llog(RC_COMMENT, logger,
		     "IMPAIR: deleting existing %s event occupying the slot shared with %s",
		     enum_name(&event_type_names, (*evp)->ev_type),
		     event_name);
		delete_state_event(evp, HERE);
	} else {
		llog(RC_COMMENT, logger,
		     "IMPAIR: deleting existing %s event",
		     event_name);
		event_delay = (*evp)->ev_delay;
		delete_state_event(evp, HERE);
	}

	llog(RC_COMMENT, logger, "IMPAIR: calling %s event handler", event_name);
	dispatch_event(st, event_type, event_delay, logger, detach_whack);
}
