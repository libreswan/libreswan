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

#include "defs.h"
#include "state.h"
#include "ikev2_retry.h"
#include "passert.h"
#include "connections.h"
#include "log.h"
#include "pluto_stats.h"
#include "ikev2_send.h"
#include "pending.h"
#include "ipsec_doi.h"

void retransmit_v2_msg(struct state *st)
{
	passert(st != NULL);
	struct ike_sa *ike = ike_sa(st, HERE);
	if (ike == NULL) {
		dbg("no ike sa so going away");
		delete_state(st);
	}

	struct connection *c = st->st_connection;
	unsigned long try_limit = c->sa_keying_tries;
	unsigned long try = st->st_try + 1;

	/*
	 * Paul: this line can stay attempt 3 of 2 because the cleanup
	 * happens when over the maximum
	 */
	if (DBGP(DBG_BASE)) {
		ipstr_buf b;
		connection_buf cib;
		DBG_log("handling event EVENT_RETRANSMIT for %s "PRI_CONNECTION" #%lu attempt %lu of %lu",
			ipstr(&c->spd.that.host_addr, &b),
			pri_connection(c, &cib),
			st->st_serialno, try, try_limit);
		DBG_log("and parent for %s "PRI_CONNECTION" #%lu keying attempt %lu of %lu; retransmit %lu",
			ipstr(&c->spd.that.host_addr, &b),
			pri_connection(c, &cib),
			ike->sa.st_serialno,
			ike->sa.st_try, try_limit,
			retransmit_count(&ike->sa) + 1);
	}

	/*
	 * if this connection has a newer Child SA than this state
	 * this negotiation is not relevant any more.  would this
	 * cover if there are multiple CREATE_CHILD_SA pending on this
	 * IKE negotiation ???
	 *
	 * XXX: Suspect this is to handle a race where the other end
	 * brings up the connection first?  For that case, shouldn't
	 * this state have been deleted?
	 *
	 *  NOTE: a larger serialno does not mean superseded. crossed
	 * streams could mean the lower serial established later and is
	 * the "newest". Should > be replaced with !=   ?
	 */
	if (st->st_establishing_sa == IKE_SA &&
	    c->newest_isakmp_sa > st->st_serialno) {
		log_state(RC_LOG, st,
			  "suppressing retransmit because IKE SA was superseded #%lu try=%lu; drop this negotiation",
			  c->newest_isakmp_sa, st->st_try);
		pstat_sa_failed(st, REASON_SUPERSEDED_BY_NEW_SA);
		delete_state(st);
		return;
	} else if (st->st_establishing_sa == IPSEC_SA &&
		   c->newest_ipsec_sa > st->st_serialno) {
		log_state(RC_LOG, st,
			  "suppressing retransmit because CHILD SA was superseded by #%lu try=%lu; drop this negotiation",
			  c->newest_ipsec_sa, st->st_try);
		pstat_sa_failed(st, REASON_SUPERSEDED_BY_NEW_SA);
		delete_state(st);
		return;
	}

	switch (retransmit(st)) {
	case RETRANSMIT_YES:
		send_recorded_v2_message(ike, "EVENT_RETRANSMIT",
					 MESSAGE_REQUEST);
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMITS_TIMED_OUT:
		break;
	case DELETE_ON_RETRANSMIT:
		/* disable revival code */
		try = 0;
		break;
	}

	/*
	 * The entire family is dead dead head
	 */
	if (IS_IKE_SA_ESTABLISHED(&ike->sa)) {
		/*
		 * Since the IKE SA is established, mimic the
		 * (probably wrong) behaviour of the old liveness code
		 * path - it needs to revive all the connections under
		 * the IKE SA and not just this one child(?).
		 */
		/* already logged */
		liveness_action(st);
		/* presumably liveness_action() deletes the state? */
		return;
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

		if (fd_p(st->st_logger->object_whackfd)) {
			/*
			 * Release whack because the observer will
			 * get bored.
			 */
			log_state(RC_COMMENT, st, "%s, but releasing whack",
				story);
			release_pending_whacks(st, story);
		} else if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			/* no whack: just log to syslog */
			log_state(RC_LOG, st, "%s", story);
		}

		ipsecdoi_replace(st, try);
	} else {
		dbg("maximum number of keyingtries reached - deleting state");
	}

	if (&ike->sa != st) {
		if (ike->sa.st_state->kind == STATE_PARENT_I2) {
			pstat_sa_failed(&ike->sa, REASON_TOO_MANY_RETRANSMITS);
			delete_state(&ike->sa);
		} else {
			free_v2_message_queues(st);
		}
	}


	/*
	 * XXX There should not have been a child sa unless this was a timeout of
	 * our CREATE_CHILD_SA request. But our code has moved from parent to child
	 */

	pstat_sa_failed(st, REASON_TOO_MANY_RETRANSMITS);
	delete_state(st);

	/* note: no md->st to clear */
}

bool ikev2_schedule_retry(struct state *st)
{
	struct connection *c = st->st_connection;
	unsigned long try = st->st_try;
	unsigned long try_limit = c->sa_keying_tries;
	if (try_limit > 0 && try >= try_limit) {
		dbg("maximum number of retries reached - deleting state");
		return false;
	}
	LLOG_JAMBUF(RC_COMMENT, st->st_logger, buf) {
		jam(buf, "scheduling retry attempt %ld of ", try);
		if (try_limit == 0) {
			jam_string(buf, "an unlimited number");
		} else {
			jam(buf, "at most %ld", try_limit);
		}
		if (fd_p(st->st_logger->object_whackfd)) {
			jam_string(buf, ", but releasing whack");
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
