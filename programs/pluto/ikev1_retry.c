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
#include "ikev1_retry.h"
#include "connections.h"
#include "log.h"
#include "ikev1_send.h"
#include "pending.h"
#include "ipsec_doi.h"
#include "pluto_stats.h"

#ifdef USE_IKEv1
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
	/*
	 * XXX: CURRENT_TRY will be 0 on the initial responder (which
	 * isn't currently trying to establish a connection).
	 */
	unsigned long current_try = st->st_try;
	unsigned long try_limit = c->sa_keying_tries;

	/* Paul: this line can say attempt 3 of 2 because the cleanup happens when over the maximum */
	address_buf b;
	connection_buf cib;
	dbg("handling event EVENT_RETRANSMIT for %s "PRI_CONNECTION" #%lu keying attempt %lu of %lu; retransmit %lu",
	    str_address(&c->spd.that.host_addr, &b),
	    pri_connection(c, &cib),
	    st->st_serialno, current_try, try_limit,
	    retransmit_count(st) + 1);

	switch (retransmit(st)) {
	case RETRANSMIT_YES:
		resend_recorded_v1_ike_msg(st, "EVENT_RETRANSMIT");
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMITS_TIMED_OUT:
		break;
	case DELETE_ON_RETRANSMIT:
		/* disable re-key code */
		current_try = 0;
		break;
	}

	if (current_try != 0 && (current_try < try_limit || try_limit == 0)) {
		/*
		 * A lot like EVENT_SA_REPLACE, but over again.  Since
		 * we know that st cannot be in use, we can delete it
		 * right away.
		 */
		char story[80]; /* arbitrary limit */

		unsigned long next_try = current_try + 1;
		snprintf(story, sizeof(story), try_limit == 0 ?
			 "starting keying attempt %ld of an unlimited number" :
			 "starting keying attempt %ld of at most %ld",
			 next_try, try_limit);

		/* ??? DBG and real-world code mixed */
		if (!DBGP(DBG_WHACKWATCH)) {
			if (fd_p(st->st_logger->object_whackfd)) {
				/*
				 * Release whack because the observer
				 * will get bored.
				 */
				log_state(RC_COMMENT, st,
				       "%s, but releasing whack",
				       story);
				release_pending_whacks(st, story);
			} else if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				/* no whack: just log */
				log_state(RC_LOG, st, "%s", story);
			}
		} else if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			log_state(RC_COMMENT, st, "%s", story);
		}

		ipsecdoi_replace(st, next_try);
	}

	pstat_sa_failed(st, REASON_TOO_MANY_RETRANSMITS);

	/* placed here because IKEv1 doesn't do a proper state change to STF_FAIL/STF_FATAL */
	linux_audit_conn(st, IS_IKE_SA(st) ? LAK_PARENT_FAIL : LAK_CHILD_FAIL);

	delete_state(st);
	/* note: no md->st to clear */
}
#endif
