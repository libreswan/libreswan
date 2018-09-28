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
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "defs.h"
#include "state.h"
#include "retry.h"
#include "log.h"
#include "ip_address.h"
#include "connections.h"
#include "ikev1_send.h"
#include "ikev2_send.h"
#include "demux.h"	/* for state_transition_fn used by ipsec_doi.h */
#include "ipsec_doi.h"
#include "ikev2.h"	/* for need_this_intiator() */

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
void retransmit_v1_msg(struct state *st)
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
		resend_recorded_v1_ike_msg(st, "EVENT_v1_RETRANSMIT");
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMITS_TIMED_OUT:
		break;
	case DELETE_ON_RETRANSMIT:
		/* disable re-key code */
		try = 0;
		break;
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
			if (fd_p(st->st_whack_sock)) {
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
		ipsecdoi_replace(st, try);
	}

	set_cur_state(st);  /* ipsecdoi_replace would reset cur_state, set it again */
	delete_state(st);
	/* note: no md->st to clear */
}

void retransmit_v2_msg(struct state *st)
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
		send_recorded_v2_ike_msg(pst, "EVENT_v2_RETRANSMIT");
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMITS_TIMED_OUT:
		break;
	case DELETE_ON_RETRANSMIT:
		/* disable re-key code */
		try = 0;
		break;
	}

	/*
	 * Current state is dead and will be deleted at the end of the
	 * function.
	 */

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

		if (fd_p(st->st_whack_sock)) {
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
		ipsecdoi_replace(st, try);
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

bool ikev2_schedule_retry(struct state *st)
{
	struct connection *c = st->st_connection;
	unsigned long try = st->st_try;
	unsigned long try_limit = c->sa_keying_tries;
	if (try_limit > 0 && try >= try_limit) {
		DBGF(DBG_CONTROL|DBG_RETRANSMITS,
		     "maximum number of retries reached - deleting state");
		return false;
	}
	LSWLOG_RC(RC_COMMENT, buf) {
		lswlogf(buf, "scheduling retry attempt %ld of ", try);
		if (try_limit == 0) {
			lswlogs(buf, "an unlimited number");
		} else {
			lswlogf(buf, "at most %ld", try_limit);
		}
		if (fd_p(st->st_whack_sock)) {
			lswlogs(buf, ", but releasing whack");
		}
	}

	/*
	 * release_pending_whacks() will release ST (and ST's parent
	 * if it exists and has the same whack).  For instance, when
	 * the AUTH exchange somehow digs a hole where the child sa
	 * gets a timeout.
	 *
	 * XXX: The child SA 'diging a hole' is likely a bug.
	 */
	release_pending_whacks(st, "scheduling a retry");

	/*
	 * XXX: Should the parent or child get re-scheduled?  Does it
	 * flip to the parent when the child's timer expires?
	 */
	suppress_retransmits(st);
	return true;
}
