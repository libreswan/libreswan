/*
 * timer event handling
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

/*
 * This file has the event handling routines. Events are
 * kept as a linked list of event structures. These structures
 * have information like event type, expiration time and a pointer
 * to event specific data (for example, to a state structure).
 */

static bool parent_vanished(struct state *st)
{
	struct connection *c = st->st_connection;
	struct state *pst = state_with_serialno(st->st_clonedfrom);

	if (pst != NULL) {
		if (c != pst->st_connection) {
			char cib1[CONN_INST_BUF];
			char cib2[CONN_INST_BUF];

			fmt_conn_instance(c, cib1);
			fmt_conn_instance(pst->st_connection, cib2);

			DBG(DBG_CONTROLMORE,
				DBG_log("\"%s\"%s #%lu parent connection of this state is diffeent \"%s\"%s #%lu",
					c->name, cib1, st->st_serialno,
					pst->st_connection->name, cib2,
					pst->st_serialno));
		}
		return FALSE;
	}

	loglog(RC_LOG_SERIOUS, "liveness_check error, no IKEv2 parent state #%lu to take %s",
			st->st_clonedfrom,
			enum_name(&dpd_action_names, c->dpd_action));

	return TRUE;
}

/* note: this mutates *st by calling get_sa_info */
static void liveness_check(struct state *st)
{
	passert(st->st_ike_version == IKEv2);

	struct state *pst = NULL;
	deltatime_t last_msg_age;

	struct connection *c = st->st_connection;

	set_cur_state(st);

	/* this should be called on a child sa */
	if (IS_CHILD_SA(st)) {
		if (parent_vanished(st)) {
			liveness_action(c, st->st_ike_version);
			return;
		} else {
			pst = state_with_serialno(st->st_clonedfrom);
		}
	} else {
		pexpect(pst == NULL); /* no more dpd in IKE state */
		pst = st;
	}

	pexpect_st_local_endpoint(st);
	address_buf this_buf;
	const char *this_ip = ipstr(&st->st_interface->local_endpoint, &this_buf);
	address_buf that_buf;
	const char *that_ip = ipstr(&st->st_remoteaddr, &that_buf);

	/*
	 * If we are a lingering (replaced) IPsec SA, don't do liveness
	 */
	if (pst->st_connection->newest_ipsec_sa != st->st_serialno) {
		DBG(DBG_DPD,
		   DBG_log("liveness: no need to send or schedule DPD for replaced IPsec SA"));
		return;
	}

	/*
	 * don't bother sending the check and reset
	 * liveness stats if there has been incoming traffic
	 */
	if (get_sa_info(st, TRUE, &last_msg_age) &&
		deltaless(last_msg_age, c->dpd_timeout)) {
		pst->st_pend_liveness = FALSE;
		pst->st_last_liveness = monotime_epoch;
	} else {
		monotime_t tm = mononow();
		monotime_t last_liveness = pst->st_last_liveness;

		/* ensure that the very first liveness_check works out */
		if (is_monotime_epoch(last_liveness)) {
			pst->st_last_liveness = last_liveness = tm;
			LSWDBGP(DBG_DPD, buf) {
				lswlogf(buf, "#%lu liveness initial timestamp set ",
					st->st_serialno);
				lswlog_monotime(buf, tm);
			}
		}

		LSWDBGP(DBG_DPD, buf) {
			lswlogf(buf, "#%lu liveness_check - last_liveness: ",
				st->st_serialno);
			lswlog_monotime(buf, last_liveness);
			lswlogf(buf, ", now: ");
			lswlog_monotime(buf, tm);
			lswlogf(buf, " parent #%lu", pst->st_serialno);
		}

		deltatime_t timeout = deltatime_max(c->dpd_timeout,
						    deltatime_mulu(c->dpd_delay, 3));

		if (pst->st_pend_liveness &&
		    deltatime_cmp(monotimediff(tm, last_liveness), timeout) >= 0) {
			LSWLOG(buf) {
				lswlogf(buf, "liveness_check - peer %s has not responded in %jd seconds, with a timeout of ",
					log_ip ? that_ip : "<ip address>",
					deltasecs(monotimediff(tm, last_liveness)));
				lswlog_deltatime(buf, timeout);
				lswlogf(buf, ", taking %s",
					enum_name(&dpd_action_names, c->dpd_action));
			}
			liveness_action(c, st->st_ike_version);
			return;
		} else {
			stf_status ret = ikev2_send_livenss_probe(st);

			DBG(DBG_DPD,
				DBG_log("#%lu liveness_check - peer %s is missing - giving them some time to come back",
					st->st_serialno, that_ip));

			if (ret != STF_OK) {
				DBG(DBG_DPD,
					DBG_log("#%lu failed to send liveness informational from %s to %s using parent  #%lu",
						st->st_serialno,
						this_ip,
						that_ip,
						pst->st_serialno));
				return; /* this prevents any new scheduling ??? */
			}
		}
	}

	DBG(DBG_DPD, DBG_log("#%lu liveness_check - peer %s is ok schedule new",
				st->st_serialno, that_ip));
	deltatime_t delay = deltatime_max(c->dpd_delay, deltatime(MIN_LIVENESS));
	event_schedule(EVENT_v2_LIVENESS, delay, st);
}

/*
 * Delete a state backlinked event (if any); leave *evp == NULL.
 */
void delete_state_event(struct state *st, struct pluto_event **evp)
{
	struct pluto_event *ev = *evp;
	if (ev != NULL) {
		DBG(DBG_DPD | DBG_CONTROL,
		    DBG_log("state #%lu requesting %s-pe@%p be deleted",
			    st->st_serialno, enum_name(&timer_event_names, ev->ev_type), ev));
		pexpect(st == ev->ev_state);
		delete_pluto_event(evp);
	};
}

static event_callback_routine timer_event_cb;
static void timer_event_cb(evutil_socket_t unused_fd UNUSED,
			   const short unused_event UNUSED,
			   void *arg)
{
	threadtime_t inception = threadtime_start();

	struct pluto_event *ev = arg;
	DBG(DBG_LIFECYCLE,
	    DBG_log("%s: processing event@%p", __func__, ev));
	enum event_type type = ev->ev_type;
	const char *event_name = enum_short_name(&timer_event_names, type);
	struct state *st = ev->ev_state;	/* note: *st might be changed */
	passert(st != NULL);

	dbg("handling event %s for %s state #%lu",
	    enum_show(&timer_event_names, type),
	    (st->st_clonedfrom == SOS_NOBODY) ? "parent" : "child",
	    st->st_serialno);

	pexpect_reset_globals();
	so_serial_t old_state = push_cur_state(st);
	pexpect(old_state == SOS_NOBODY); /* since globals are reset */
	statetime_t start = statetime_backdate(st, &inception);

#if 0
	/*
	 * XXX: this line, which is a merger of the above two lines,
	 * leaks into the expected test output causing failures.
	 */
	dbg("%s: processing %s-event@%p for %s SA #%lu in state %s",
	    __func__, event_name, ev,
	    IS_IKE_SA(st) ? "IKE" : "CHILD",
	    st->st_serialno, st->st_state->short_name);
#endif

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
		DBG(DBG_RETRANSMITS, DBG_log("#%lu IKEv2 local address change",
					st->st_serialno));
		passert(st->st_addr_change_event == ev);
		st->st_addr_change_event = NULL;
		ikev2_addr_change(st);
		break;

	case EVENT_v2_RELEASE_WHACK:
		DBG(DBG_CONTROL, DBG_log("%s releasing whack for #%lu %s (sock="PRI_FD")",
					enum_show(&timer_event_names, type),
					st->st_serialno,
					st->st_state->name,
					 PRI_fd(st->st_whack_sock)));
		passert(st->st_rel_whack_event == ev);
		st->st_rel_whack_event = NULL;
		release_pending_whacks(st, "release whack");
		break;

	case EVENT_RETRANSMIT:
		passert(st->st_event == ev);
		st->st_event = NULL;
		switch (st->st_ike_version) {
		case IKEv2:
			DBG(DBG_RETRANSMITS, DBG_log("IKEv2 retransmit event"));
			retransmit_v2_msg(st);
			break;
		case IKEv1:
			DBG(DBG_RETRANSMITS, DBG_log("IKEv1 retransmit event"));
			retransmit_v1_msg(st);
			break;
		default:
			bad_case(st->st_ike_version);
		}
		break;

	case EVENT_v1_SEND_XAUTH:
		passert(st->st_send_xauth_event == ev);
		st->st_send_xauth_event = NULL;
		dbg("XAUTH: event EVENT_v1_SEND_XAUTH #%lu %s",
		    st->st_serialno, st->st_state->name);
		xauth_send_request(st);
		break;

	case EVENT_v2_INITIATE_CHILD:
		passert(st->st_event == ev);
		st->st_event = NULL;
		ikev2_child_outI(st);
		break;

	case EVENT_v2_LIVENESS:
		passert(st->st_liveness_event == ev);
		st->st_liveness_event = NULL;
		liveness_check(st);
		break;

	case EVENT_SA_REKEY:
		passert(st->st_event == ev);
		st->st_event = NULL;
		pexpect(st->st_ike_version == IKEv2);
		v2_event_sa_rekey(st);
		break;

	case EVENT_SA_REPLACE:
	case EVENT_v1_SA_REPLACE_IF_USED:
		passert(st->st_event == ev);
		st->st_event = NULL;
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

			delete_liveness_event(st);
			delete_dpd_event(st);
			event_schedule(EVENT_SA_EXPIRE, st->st_replace_margin, st);
			break;
		default:
			bad_case(st->st_ike_version);
		}
		break;

	case EVENT_SA_EXPIRE:
	{
		passert(st->st_event == ev);
		st->st_event = NULL;
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
				delete_my_family(st, FALSE);
				/* note: no md->st to clear */
			} else {
				struct ike_sa *ike = ike_sa(st);
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
					delete_state(st);
					st = NULL;
					v2_expire_unused_ike_sa(ike);
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
		passert(st->st_event == ev);
		st->st_event = NULL;
		/*
		 * The state failed to complete within a reasonable
		 * time, or the state failed but was left to live for
		 * a while so re-transmits could work.  Either way,
		 * time to delete it.
		 */
		passert(st != NULL);
		deltatime_t timeout = (st->st_ike_version == IKEv2) ? deltatime(MAXIMUM_RESPONDER_WAIT) : st->st_connection->r_timeout;

		libreswan_log("deleting incomplete state after "PRI_DELTATIME" seconds",
			      pri_deltatime(timeout));
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
		passert(st->st_event == ev);
		st->st_event = NULL;
		initiate_redirect(st);
		break;

	case EVENT_DPD:
		passert(st->st_dpd_event == ev);
		st->st_dpd_event = NULL;
		dpd_event(st);
		break;

	case EVENT_DPD_TIMEOUT:
		passert(st->st_dpd_event == ev);
		st->st_dpd_event = NULL;
		dpd_timeout(st);
		break;

	case EVENT_CRYPTO_TIMEOUT:
		DBG(DBG_LIFECYCLE,
			DBG_log("event crypto_failed on state #%lu, aborting",
				st->st_serialno));
		passert(st->st_event == ev);
		st->st_event = NULL;
		pstat_sa_failed(st, REASON_CRYPTO_TIMEOUT);
		delete_state(st);
		/* note: no md->st to clear */
		break;

#ifdef XAUTH_HAVE_PAM
	case EVENT_PAM_TIMEOUT:
		DBG(DBG_LIFECYCLE,
				DBG_log("PAM thread timeout on state #%lu",
					st->st_serialno));
		passert(st->st_event == ev);
		st->st_event = NULL;
		xauth_pam_abort(st);
		/*
		 * Things get cleaned up when the PAM process exits.
		 *
		 * Should this schedule an event for the case when the
		 * child process (which is SIGKILLed) doesn't exit!?!
		 */
		break;
#endif

	case EVENT_REINIT_SECRET:
	case EVENT_SHUNT_SCAN:
	case EVENT_PENDING_DDNS:
	case EVENT_PENDING_PHASE2:
	case EVENT_SD_WATCHDOG:
	case EVENT_NAT_T_KEEPALIVE:
	case EVENT_CHECK_CRLS:
	case EVENT_REVIVE_CONNS:
	default:
		bad_case(type);
	}

	delete_pluto_event(&ev);
	statetime_stop(&start, "%s() %s", __func__, event_name);
	pop_cur_state(old_state);
}

/*
 * Delete an event (if any); leave st->st_event == NULL.
 */
void delete_event(struct state *st)
{
	if (st->st_event != NULL) {
		dbg("state #%lu requesting %s to be deleted",
		    st->st_serialno, enum_show(&timer_event_names,
					       st->st_event->ev_type));

		if (st->st_event->ev_type == EVENT_RETRANSMIT)
			clear_retransmits(st);

		delete_pluto_event(&st->st_event);
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
	struct pluto_event *ev = alloc_thing(struct pluto_event, en);
	DBG(DBG_LIFECYCLE, DBG_log("%s: new %s-pe@%p", __func__, en, ev));

	ev->ev_type = type;
	ev->ev_name = en;
	ev->ev_state = st;

	ev->ev_time = monotimesum(mononow(), delay);

	/*
	 * Put a pointer to the event in the state object, so we can
	 * find and delete the event if we need to (for example, if we
	 * receive a reply).  (There are actually six classes of event
	 * associated with a state.)
	 */
	switch (type) {
	case EVENT_v2_ADDR_CHANGE:
		passert(st->st_addr_change_event == NULL);
		st->st_addr_change_event = ev;
		break;

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
	deltatime_buf buf;
	dbg("inserting event %s, timeout in %s seconds for #%lu",
	    en, str_deltatime(delay, &buf),
	    ev->ev_state->st_serialno);

	fire_timer_photon_torpedo(&ev->ev, timer_event_cb, ev, delay);
}

void event_schedule_s(enum event_type type, time_t delay_sec, struct state *st)
{
	deltatime_t delay = deltatime(delay_sec);
	event_schedule(type, delay, st);
}

void event_force(enum event_type type, struct state *st)
{
	delete_event(st);
	deltatime_t delay = deltatime(0);
	event_schedule(type, delay, st);
}
