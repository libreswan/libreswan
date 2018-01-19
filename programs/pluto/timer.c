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
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev1_dpd.h"
#include "ikev2.h"
#include "pending.h" /* for flush_pending_by_connection */
#include "ikev1_xauth.h"
#include "xauth.h"
#include "kernel.h" /* for scan_shunts() */
#include "kernel_pfkey.h" /* for pfkey_scan_shunts */
#include "retransmit.h"
#include "nat_traversal.h"
#include "ip_address.h"

#include "pluto_sd.h"

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
	struct connection *c = st->st_connection;
	unsigned long try = st->st_try;
	unsigned long try_limit = c->sa_keying_tries;

	set_cur_state(st);

	/* Paul: this line can say attempt 3 of 2 because the cleanup happens when over the maximum */
	DBG(DBG_CONTROL|DBG_RETRANSMITS, {
		ipstr_buf b;
		char cib[CONN_INST_BUF];
		DBG_log("handling event EVENT_v1_RETRANSMIT for %s \"%s\"%s #%lu keying attempt %lu of %lu; retransmit %lu",
			ipstr(&c->spd.that.host_addr, &b),
			c->name, fmt_conn_instance(c, cib),
			st->st_serialno, try, try_limit,
			retransmit_count(st) + 1);
	});

	switch (retransmit(st)) {
	case RETRANSMIT_YES:
		resend_ike_v1_msg(st, "EVENT_v1_RETRANSMIT");
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMITS_TIMED_OUT:
		break;
	}

	/*
	 * check if we've tried rekeying enough times.  st->st_try ==
	 * 0 means that this should be the only try (possibly from
	 * IMPAIR).  c->sa_keying_tries == 0 means that there is no
	 * limit.
	 */

	if (IMPAIR(RETRANSMITS) && try > 0) {
		/*
		 * IKEv1 never retries to IKEv2; but IKEv2 can retry
		 * to IKEv1
		 */
		libreswan_log("IMPAIR RETRANSMITS: suppressing re-key");
		/* disable re-key code */
		try = 0;
	}

	if (try != 0 && (try <= try_limit || try_limit == 0)) {
		/*
		 * A lot like EVENT_SA_REPLACE, but over again.  Since
		 * we know that st cannot be in use, we can delete it
		 * right away.
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

	set_cur_state(st);  /* ipsecdoi_replace would reset cur_state, set it again */
	delete_state(st);
	/* note: no md->st to clear */
}

static void retransmit_v2_msg(struct state *st)
{
	struct connection *c;
	unsigned long try;
	unsigned long try_limit;
	struct state *pst = IS_CHILD_SA(st) ? state_with_serialno(st->st_clonedfrom) : st;

	passert(st != NULL);
	passert(IS_PARENT_SA(pst));

	set_cur_state(st);
	c = st->st_connection;
	try_limit = c->sa_keying_tries;
	try = st->st_try + 1;

	/* Paul: this line can stay attempt 3 of 2 because the cleanup happens when over the maximum */
	DBG(DBG_CONTROL|DBG_RETRANSMITS, {
		ipstr_buf b;
		char cib[CONN_INST_BUF];
		DBG_log("handling event EVENT_v2_RETRANSMIT for %s \"%s\"%s #%lu attempt %lu of %lu",
			ipstr(&c->spd.that.host_addr, &b),
			c->name, fmt_conn_instance(c, cib),
			st->st_serialno, try, try_limit);
		DBG_log("and parent for %s \"%s\"%s #%lu keying attempt %lu of %lu; retransmit %lu",
			ipstr(&c->spd.that.host_addr, &b),
			c->name, fmt_conn_instance(c, cib),
			pst->st_serialno,
			pst->st_try, try_limit,
			retransmit_count(pst) + 1);
		});

	if (need_this_intiator(st)) {
		delete_state(st);
		return;
	}

	switch (retransmit(st)) {
	case RETRANSMIT_YES:
		send_ike_msg(pst, "EVENT_v2_RETRANSMIT");
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMITS_TIMED_OUT:
		break;
	}

	/*
	 * Current state is dead and will be deleted at the end of the
	 * function.
	 */

	/*
	 * check if we've tried rekeying enough times.  st->st_try ==
	 * 0 means that this should be the only try (possibly from
	 * IMPAIR).  c->sa_keying_tries == 0 means that there is no
	 * limit.
	 */

	if (IMPAIR(RETRANSMITS) && try > 0) {
		/*
		 * XXX: Even though TRY is always non-zero; check it.
		 * At some point TRY, and the code falling back to
		 * IKEv1 will go away and this is a bread-crumb for
		 * what needs to be changed.
		 */
		libreswan_log("IMPAIR RETRANSMITS: suppressing re-key");
		/* disable re-key code */
		try = 0;
	}

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
		DBG(DBG_CONTROL|DBG_RETRANSMITS,
		    DBG_log("maximum number of keyingtries reached - deleting state"));
	}


	if (pst != st) {
		set_cur_state(pst);  /* now we are on pst */
		if (pst->st_state == STATE_PARENT_I2) {
			delete_state(pst);
		} else {
			release_fragments(st);
			freeanychunk(st->st_tpacket);
		}
	}

	set_cur_state(st);  /* ipsecdoi_replace would reset cur_state, set it again */

	/*
	 * XXX There should not have been a child sa unless this was a timeout of
	 * our CREATE_CHILD_SA request. But our code has moved from parent to child
	 */

	delete_state(st);

	/* note: no md->st to clear */
}

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
	struct state *pst = NULL;
	deltatime_t last_msg_age;

	struct connection *c = st->st_connection;

	passert(st->st_ikev2);

	set_cur_state(st);

	/* this should be called on a child sa */
	if (IS_CHILD_SA(st)) {
		if (parent_vanished(st)) {
			liveness_action(c, st->st_ikev2);
			return;
		} else {
			pst = state_with_serialno(st->st_clonedfrom);
		}
	} else {
		pexpect(pst == NULL); /* no more dpd in IKE state */
		pst = st;
	}

	char this_ip[ADDRTOT_BUF];
	char that_ip[ADDRTOT_BUF];

	addrtot(&st->st_localaddr, 0, this_ip, sizeof(this_ip));
	addrtot(&st->st_remoteaddr, 0, that_ip, sizeof(that_ip));

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
			liveness_action(c, st->st_ikev2);
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
					 "last used %jds ago < %jd ",
					 deltasecs(last_used_age),
					 deltasecs(c->sa_rekey_margin));
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
		DBG_log("not replacing unused IPSEC SA #%lu: last used %jds ago > %jd let it and the parent #%lu expire",
			st->st_serialno,
			deltasecs(last_used_age),
			deltasecs(c->sa_rekey_margin),
			pst->st_serialno));

	delete_event(pst);
	event_schedule_s(EVENT_SA_EXPIRE, 0, pst);
}

/*
 * Delete a state backlinked event.
 */
void delete_state_event(struct state *st, struct pluto_event **evp)
{
        struct pluto_event *ev = *evp;
	DBG(DBG_DPD | DBG_CONTROL,
	    const char *en = ev ? enum_name(&timer_event_names, ev->ev_type) : "N/A";
	    DBG_log("state #%lu requesting %s-pe@%p be deleted",
		    st->st_serialno, en, ev));
	pexpect(*evp == NULL || st == (*evp)->ev_state);
	delete_pluto_event(evp);
}

static event_callback_routine timer_event_cb;
static void timer_event_cb(evutil_socket_t fd UNUSED, const short event UNUSED, void *arg)
{
	struct pluto_event *ev = arg;
	DBG(DBG_LIFECYCLE,
	    DBG_log("%s: processing event@%p", __func__, ev));

	enum event_type type = ev->ev_type;
	struct state *const st = ev->ev_state;	/* note: *st might be changed */
	bool state_event = (st != NULL);

	DBG(DBG_CONTROL,
	    char statenum[64] = "";
	    if (st != NULL) {
		    snprintf(statenum, sizeof(statenum), " for %s state #%lu",
			     (st->st_clonedfrom == SOS_NOBODY) ? "parent" : "child",
			     st->st_serialno);
	    }
	    DBG_log("handling event %s%s",
		    enum_show(&timer_event_names, type), statenum));

	pexpect_reset_globals();

	if (state_event)
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
	case EVENT_SD_WATCHDOG:
	case EVENT_NAT_T_KEEPALIVE:
		passert(st == NULL);
		break;

	case EVENT_v1_SEND_XAUTH:
		passert(st != NULL && st->st_send_xauth_event == ev);
		DBG(DBG_CONTROLMORE|DBG_XAUTH,
		    DBG_log("XAUTH: event EVENT_v1_SEND_XAUTH #%lu %s",
			    st->st_serialno, st->st_state_name));
		st->st_send_xauth_event = NULL;
		break;

	case EVENT_v2_SEND_NEXT_IKE:
	case EVENT_v2_INITIATE_CHILD:
	case EVENT_v1_RETRANSMIT:
	case EVENT_v2_RETRANSMIT:
	case EVENT_SA_REPLACE:
	case EVENT_SA_REPLACE_IF_USED:
	case EVENT_v2_SA_REPLACE_IF_USED:
	case EVENT_v2_SA_REPLACE_IF_USED_IKE:
	case EVENT_v2_RESPONDER_TIMEOUT:
	case EVENT_SA_EXPIRE:
	case EVENT_SO_DISCARD:
	case EVENT_CRYPTO_TIMEOUT:
	case EVENT_PAM_TIMEOUT:
		passert(st != NULL && st->st_event == ev);
		st->st_event = NULL;
		break;

	case EVENT_v2_ADDR_CHANGE:
		passert(st != NULL && st->st_addr_change_event == ev);
		st->st_addr_change_event = NULL;
		break;

	case EVENT_v2_RELEASE_WHACK:
		passert(st != NULL && st->st_rel_whack_event == ev);
		DBG(DBG_CONTROL,
			DBG_log("event EVENT_v2_RELEASE_WHACK st_rel_whack_event=NULL #%lu %s",
				st->st_serialno, st->st_state_name));
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
	case EVENT_v2_ADDR_CHANGE:
		DBG(DBG_RETRANSMITS, DBG_log("#%lu IKEv2 local address change",
					st->st_serialno));
		ikev2_addr_change(st);
		break;
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
					st->st_state_name,
					st->st_whack_sock));
		release_pending_whacks(st, "release whack");
		break;

	case EVENT_v1_RETRANSMIT:
		DBG(DBG_RETRANSMITS, DBG_log("IKEv1 retransmit event"));
		retransmit_v1_msg(st);
		break;

	case EVENT_v1_SEND_XAUTH:
		xauth_send_request(st);
		break;

	case EVENT_v2_RETRANSMIT:
		DBG(DBG_RETRANSMITS, DBG_log("IKEv2 retransmit event"));
		retransmit_v2_msg(st);
		break;

	case EVENT_v2_SEND_NEXT_IKE:
		ikev2_child_send_next(st);
		break;

	case EVENT_v2_INITIATE_CHILD:
		ikev2_child_outI(st);
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
			DBG(DBG_LIFECYCLE,
				DBG_log("%s picked newest_isakmp_sa #%lu",
					enum_name(&timer_event_names, type),
					newest));
		} else {
			newest = c->newest_ipsec_sa;
			DBG(DBG_LIFECYCLE,
				DBG_log("%s picked newest_ipsec_sa #%lu",
					enum_name(&timer_event_names, type),
					newest));
		}

		if (newest != SOS_NOBODY && newest > st->st_serialno) {
			/* not very interesting: no need to replace */
			DBG(DBG_LIFECYCLE,
				DBG_log("not replacing stale %s SA: #%lu will do",
					IS_IKE_SA(st) ? "ISAKMP" : "IPsec",
					newest));
		} else if (type == EVENT_v2_SA_REPLACE_IF_USED &&
				get_sa_info(st, TRUE, &last_used_age) &&
				deltaless(c->sa_rekey_margin, last_used_age)) {
			ikev2_expire_parent(st, last_used_age);
			break;
		} else if (type == EVENT_v2_SA_REPLACE_IF_USED_IKE) {
				struct state *cst = state_with_serialno(c->newest_ipsec_sa);
				if (cst == NULL)
					break;
				DBG(DBG_LIFECYCLE, DBG_log("#%lu check last used on newest IPsec SA #%lu",
							st->st_serialno, cst->st_serialno));
				if (get_sa_info(cst, TRUE, &last_used_age) &&
					deltaless(c->sa_rekey_margin, last_used_age))
				{
					delete_liveness_event(cst);
					delete_event(cst);
					event_schedule_s(EVENT_SA_EXPIRE, 0, cst);
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
					"not replacing stale %s SA: inactive for %jds",
					IS_IKE_SA(st) ? "ISAKMP" : "IPsec",
					deltasecs(monotimediff(mononow(),
							       st->st_outbound_time))));
		} else {
			ikev2_log_v2_sa_expired(st, type);
			ipsecdoi_replace(st, LEMPTY, LEMPTY, 1);
		}


		delete_liveness_event(st);
		delete_dpd_event(st);
		event_schedule(EVENT_SA_EXPIRE, st->st_margin, st);
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
		/* Delete this state object.  It must be in the hash table. */
		if (st->st_ikev2 && IS_IKE_SA(st)) {
			/* IKEv2 parent, delete children too */
			delete_my_family(st, FALSE);
			/* note: no md->st to clear */
		} else {
			struct state *pst = state_with_serialno(st->st_clonedfrom);
			delete_state(st);
			/* note: no md->st to clear */

			ikev2_expire_unused_parent(pst);
		}
		break;
	}

	case EVENT_SO_DISCARD:
	{
		passert(st != NULL);
		struct connection *c = st->st_connection;
		/*
		 * If there is a screw-up because code forgot to
		 * update the default event, this log message will be
		 * wrong.  See hack in insert_state().
		 */
		libreswan_log("deleting incomplete state after %jd.%03jd seconds",
			      deltasecs(c->r_timeout),
			      deltamillisecs(c->r_timeout) % 1000);
		delete_state(st);
		break;
	}

	case EVENT_DPD:
		dpd_event(st);
		break;

	case EVENT_DPD_TIMEOUT:
		dpd_timeout(st);
		break;

	case EVENT_CRYPTO_TIMEOUT:
		DBG(DBG_LIFECYCLE,
			DBG_log("event crypto_failed on state #%lu, aborting",
				st->st_serialno));
		delete_state(st);
		/* note: no md->st to clear */
		break;

#ifdef XAUTH_HAVE_PAM
	case EVENT_PAM_TIMEOUT:
		DBG(DBG_LIFECYCLE,
				DBG_log("PAM thread timeout on state #%lu",
					st->st_serialno));
		/*
		 * This immediately invokes the callback passing in
		 * ST.
		 */
		xauth_pam_abort(st, TRUE);
		/*
		 * Removed this call, presumably it was needed because
		 * the call back didn't fire until later?
		 *
		 * event_schedule(EVENT_SA_EXPIRE, MAXIMUM_RESPONDER_WAIT, st);
		 */
		/* note: no md->st to clear */
		break;
#endif

	default:
		bad_case(type);
	}

	delete_pluto_event(&ev);
	if (state_event)
		reset_cur_state();
}

/*
 * Delete an event.
 */
void delete_event(struct state *st)
{
	/* ??? isn't this a bug?  Should we not passert? */
	if (st->st_event == NULL) {
		DBG(DBG_CONTROLMORE,
				DBG_log("state #%lu requesting to delete non existing event",
					st->st_serialno));
		return;
	}
	if (DBGP(DBG_CONTROL) ||
	    (DBGP(DBG_RETRANSMITS) && (st->st_event->ev_type == EVENT_v1_RETRANSMIT ||
				       st->st_event->ev_type == EVENT_v2_RETRANSMIT))) {
		DBG_log("state #%lu requesting %s to be deleted",
			st->st_serialno,
			enum_show(&timer_event_names,
				  st->st_event->ev_type));
	}
	if (st->st_event->ev_type == EVENT_v1_RETRANSMIT ||
	    st->st_event->ev_type == EVENT_v2_RETRANSMIT) {
		clear_retransmits(st);
	}
	delete_pluto_event(&st->st_event);
}

/*
 * This routine places an event in the event list.
 * Delay should really be a deltatime_t but this is easier
 */
void event_schedule(enum event_type type, deltatime_t delay, struct state *st)
{
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

	/* ??? ev_time lacks required precision */
	ev->ev_time = monotimesum(mononow(), delay);
	link_pluto_event_list(ev); /* add to global ist to track */

	/*
	 * If the event is associated with a state, put a backpointer to the
	 * event in the state object, so we can find and delete the event
	 * if we need to (for example, if we receive a reply).
	 * (There are actually three classes of event associated
	 * with a state.)
	 */
	if (st != NULL) {
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
	}

	if (DBGP(DBG_CONTROL) || DBGP(DBG_LIFECYCLE) ||
	    (DBGP(DBG_RETRANSMITS) && (ev->ev_type == EVENT_v1_RETRANSMIT ||
				       ev->ev_type == EVENT_v2_RETRANSMIT))) {
			if (st == NULL) {
				DBG_log("inserting event %s, timeout in %jd.%03jd seconds",
					en,
					deltasecs(delay),
					(deltamillisecs(delay) % 1000));
			} else {
				DBG_log("inserting event %s, timeout in %jd.%03jd seconds for #%lu",
					en,
					deltasecs(delay),
					(deltamillisecs(delay) % 1000),
					ev->ev_state->st_serialno);
			}
	}

	timer_private_pluto_event_new(&ev->ev,
				      NULL_FD, EV_TIMEOUT,
				      timer_event_cb, ev, delay);
}

void event_schedule_s(enum event_type type, time_t delay_sec, struct state *st)
{
	deltatime_t delay = deltatime(delay_sec);
	event_schedule(type, delay, st);
}
