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
#include "kernel.h"

static void liveness_clear_connection(struct connection *c, const char *v)
{
	/*
	 * For CK_INSTANCE, delete_states_by_connection() will clear
	 * Note that delete_states_by_connection changes c->kind but we need
	 * to remember what it was to know if we still need to unroute after delete
	 */
	if (c->kind == CK_INSTANCE) {
		delete_states_by_connection(c, /*relations?*/true);
	} else {
		flush_pending_by_connection(c); /* remove any partial negotiations that are failing */
		delete_states_by_connection(c, /*relations?*/true);
		dbg("%s: unrouting connection %s action - clearing",
		    enum_name(&connection_kind_names, c->kind), v);
		unroute_connection(c); /* --unroute */
	}
}

static void retry_action(struct ike_sa *ike_tbd)
{
	/*
	 * XXX: Danger! These connection calls, notably
	 * restart_connections_by_peer(), can end up deleting IKE_TBD.
	 *
	 * So that the logger is valid after IKE_TBD's been deleted,
	 * create a clone of IKE_TBD's logger and kill the IKE_TBD
	 * pointer.
	 */
	struct logger *logger = clone_logger(ike_tbd->sa.st_logger, HERE);
	struct connection *c = ike_tbd->sa.st_connection;
	const char *liveness_name = enum_name(&ike_version_liveness_names, ike_tbd->sa.st_ike_version);
	passert(liveness_name != NULL);
	ike_tbd = NULL; /* kill IKE_TBD; can no longer be trusted */

	switch (c->dpd_action) {
	case DPD_ACTION_CLEAR:
		llog(RC_LOG, logger,
		     "%s action - clearing connection kind %s",
		     liveness_name, enum_name(&connection_kind_names, c->kind));
		liveness_clear_connection(c, liveness_name);
		break;

	case DPD_ACTION_RESTART:
		llog(RC_LOG, logger,
		     "%s action - restarting all connections that share this peer",
		     liveness_name);
		restart_connections_by_peer(c, logger);
		break;

	case DPD_ACTION_HOLD:
		llog(RC_LOG, logger,
		     "%s action - putting connection into hold",
		     liveness_name);
		if (c->kind == CK_INSTANCE) {
			dbg("%s warning dpdaction=hold on instance futile - will be deleted", liveness_name);
		}
		delete_states_by_connection(c, /*relations?*/true);
		break;

	default:
		bad_case(c->dpd_action);
	}
	free_logger(&logger, HERE);
}

/*
 * XXX: it is the IKE SA that is responsible for all retransmits.
 */

void retransmit_v2_msg(struct state *ike_sa)
{
	passert(ike_sa != NULL);
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return;
	}

	/*
	 * XXX: this is the IKE SA's retry limit; a second child
	 * trying to establish may have a different policy.
	 */
	struct connection *c = ike->sa.st_connection;
	unsigned long try_limit = c->sa_keying_tries;
	unsigned long try = ike->sa.st_try + 1;

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
			ike->sa.st_serialno, try, try_limit);
		DBG_log("and parent for %s "PRI_CONNECTION" #%lu keying attempt %lu of %lu; retransmit %lu",
			ipstr(&c->spd.that.host_addr, &b),
			pri_connection(c, &cib),
			ike->sa.st_serialno,
			ike->sa.st_try, try_limit,
			retransmit_count(&ike->sa) + 1);
	}

	/* if this connection has a newer Child SA than this state
	 * this negotiation is not relevant any more.  would this
	 * cover if there are multiple CREATE_CHILD_SA pending on this
	 * IKE negotiation ???
	 *
	 * XXX: Suspect this is to handle a race where the other end
	 * brings up the connection first?  For that case, shouldn't
	 * this state have been deleted?
	 *
	 * NOTE: a larger serialno does not mean superseded. crossed
	 * streams could mean the lower serial established later and
	 * is the "newest". Should > be replaced with != ?
	 */

	if (!IS_IKE_SA_ESTABLISHED(&ike->sa) && c->newest_ike_sa > ike->sa.st_serialno) {
		log_state(RC_LOG, &ike->sa,
			  "suppressing retransmit because IKE SA was superseded #%lu try=%lu; drop this negotiation",
			  c->newest_ike_sa, ike->sa.st_try);
		pstat_sa_failed(&ike->sa, REASON_SUPERSEDED_BY_NEW_SA);
		delete_ike_family(ike, DONT_SEND_DELETE);
		return;
	}

	switch (retransmit(&ike->sa)) {
	case RETRANSMIT_YES:
		send_recorded_v2_message(ike, "EVENT_RETRANSMIT",
					 MESSAGE_REQUEST);
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMITS_TIMED_OUT:
		break;
	case DELETE_ON_RETRANSMIT:
		delete_ike_family(ike, DONT_SEND_DELETE);
		return;
	}

	/*
	 * The entire family is dead dead head.
	 */
	if (IS_IKE_SA_ESTABLISHED(&ike->sa)) {
		/*
		 * Since the IKE SA is established, mimic the
		 * (probably wrong) behaviour of the old liveness code
		 * path - it needs to revive all the connections under
		 * the IKE SA and not just this one child(?).
		 */
		/* already logged */
		retry_action(ike);
		/* presumably retry_action() deletes the state? */
		return;
	}

	/*
	 * XXX: This is looking at the failed to establish IKE SA.
	 * The retry is probably valid.  However, would it be easier
	 * to just let the replace code handle this?
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

		if (fd_p(ike->sa.st_logger->object_whackfd)) {
			/*
			 * Release whack because the observer will
			 * get bored.
			 */
			log_state(RC_COMMENT, &ike->sa,
				  "%s, but releasing whack",
				  story);
			release_pending_whacks(&ike->sa, story);
		} else if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			/* no whack: just log to syslog */
			log_state(RC_LOG, &ike->sa, "%s", story);
		}

		ipsecdoi_replace(&ike->sa, try);
	} else {
		dbg("maximum number of keyingtries reached - deleting state");
	}

	/*
	 * XXX: There might be a larval child.  Just use the biggest
	 * stick available.
	 */

	pstat_sa_failed(&ike->sa, REASON_TOO_MANY_RETRANSMITS);
	/* can't send delete as message window is full */
	delete_ike_family(ike, DONT_SEND_DELETE);

	/* note: no md->st to clear */
}
