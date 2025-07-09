/* IKEv2 replace, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2010-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2011 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2014-2022 Andrew Cagney
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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
#include "ipsec_doi.h"
#include "log.h"
#include "ikev2.h"
#include "ikev2_replace.h"
#include "timer.h"
#include "connections.h"
#include "ikev2_ike_sa_init.h"
#include "initiate.h"
#include "ikev2_create_child_sa.h"
#include "kernel.h"		/* for was_eroute_idle() */

/*
 * For opportunistic IPsec, we want to delete idle connections, so we
 * are not gaining an infinite amount of unused IPsec SAs.
 *
 * NOTE: Soon we will accept an idletime= configuration option that
 * replaces this check.
 *
 * Only replace the SA when it's been in use (checking for in-use is a
 * separate operation).
 */

static bool expire_ike_because_child_not_used(struct state *st)
{
	if (!(IS_IKE_SA_ESTABLISHED(st) ||
	      IS_CHILD_SA_ESTABLISHED(st))) {
		/* for instance, too many retransmits trigger replace */
		return false;
	}

	struct connection *c = st->st_connection;

	if (!is_opportunistic(c)) {
		/* killing idle IPsec SA's is only for opportunistic SA's */
		return false;
	}

	if (nr_child_leases(c->remote) > 0) {
		llog_pexpect(st->logger, HERE,
			     "#%lu has lease; should not be trying to replace",
			     st->st_serialno);
		return true;
	}

	/* see of (most recent) child is busy */
	struct child_sa *child;
	struct ike_sa *ike;
	if (IS_IKE_SA(st)) {
		ike = pexpect_ike_sa(st);
		child = child_sa_by_serialno(c->established_child_sa);
		if (child == NULL) {
			llog_pexpect(st->logger, HERE,
				     "can't check usage as IKE SA #%lu has no newest child",
				     ike->sa.st_serialno);
			return true;
		}
	} else {
		child = pexpect_child_sa(st);
		ike = ike_sa(st, HERE);
	}

	dbg(PRI_SO" check last used on newest CHILD SA "PRI_SO,
	    ike->sa.st_serialno, child->sa.st_serialno);

	/* not sure why idleness is set to rekey margin? */
	if (was_eroute_idle(child, c->config->sa_rekey_margin)) {
		/* we observed no traffic, let IPSEC SA and IKE SA expire */
		dbg("expiring IKE SA "PRI_SO" as CHILD SA "PRI_SO" has been idle for more than %jds",
		    ike->sa.st_serialno,
		    child->sa.st_serialno,
		    deltasecs(c->config->sa_rekey_margin));
		return true;
	}
	return false;
}

static bool v2_state_is_expired(struct state *st, const char *verb)
{
	struct ike_sa *ike = ike_sa(st, HERE);
	if (ike == NULL) {
		/*
		 * An IKE SA must return itself so NULL implies a
		 * parentless child.
		 *
		 * Even it is decided that Child SAs can linger after
		 * the IKE SA has gone they shouldn't be getting
		 * rekeys!
		 */
		llog_pexpect(st->logger, HERE,
			     "not %s Child SA #%lu; as IKE SA #%lu has diasppeared",
			     verb, st->st_serialno, st->st_clonedfrom);
		event_force(EVENT_v2_EXPIRE, st);
		return true;
	}

	if (expire_ike_because_child_not_used(st)) {
		struct ike_sa *ike = ike_sa(st, HERE);
		event_force(EVENT_v2_EXPIRE, &ike->sa);
		return true;
	}

	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (newer_sa != SOS_NOBODY) {
		/*
		 * A newer SA implies that this SA has already been
		 * successfully replaced (it's only set when the newer
		 * SA establishes).
		 *
		 * Two ways this can happen:
		 *
		 * + the SA should have been expired at the same time
		 * as the new SA was established; but wasn't
		 *
		 * + this and the peer established the same SA in
		 * parallel, aka crossing the streams; the two SAs are
		 * allowed to linger until one is clearly obsolete;
		 * see github/699
		 *
		 * either way expire the SA now
		 */
		const char *satype = IS_IKE_SA(st) ? "IKE" : "Child";
#if 0
		llog_pexpect(st->logger, HERE,
			     "not %s stale %s SA #%lu; as already got a newer #%lu",
			     verb, satype, st->st_serialno, newer_sa);
#else
		llog(RC_LOG, st->logger,
		     "not %s stale %s SA "PRI_SO"; as already got a newer #%lu",
		     verb, satype, pri_so(st->st_serialno), newer_sa);
#endif
		event_force(EVENT_v2_EXPIRE, st);
		return true;
	}

	return false;
}

/* Replace SA with a fresh one that is similar
 *
 * Shares some logic with ipsecdoi_initiate, but not the same!
 * - we must not reuse the ISAKMP SA if we are trying to replace it!
 * - if trying to replace IPSEC SA, use ipsecdoi_initiate to build
 *   ISAKMP SA if needed.
 * - duplicate whack fd, if live.
 * Does not delete the old state -- someone else will do that.
 */

void ikev2_replace(struct state *st, bool detach_whack)
{
	/*
	 * start billing the new state.  The old state also gets
	 * billed for this function call, oops.
	 */
	threadtime_t inception = threadtime_start();

	if (IS_IKE_SA(st)) {
		/*
		 * Should this call capture_child_rekey_policy(st) or
		 * child_sa_policy(c) to capture the Child SA's
		 * policy?
		 *
		 * Probably not.
		 *
		 * When the IKE (ISAKMP) SA initiator code sees
		 * policy=LEMPTY it skips scheduling the connection as
		 * a Child SA to be initiated once the IKE SA
		 * establishes.  Instead the revival code will
		 * schedule the connection as a child.
		 */
		struct connection *c = st->st_connection;
		const struct child_policy policy = {0};
		if (IS_IKE_SA_ESTABLISHED(st)) {
			llog(RC_LOG, st->logger, "initiate reauthentication of IKE SA");
		}
		initiate_v2_IKE_SA_INIT_request(c, st, &policy, &inception,
						HUNK_AS_SHUNK(c->child.sec_label),
						detach_whack);

	} else {

		/*
		 * Start from policy in (ipsec) state, not connection.
		 * This ensures that rekeying doesn't downgrade
		 * security.  I admit that this doesn't capture
		 * everything.
		 */
		const struct child_policy policy = capture_child_rekey_policy(st);
		initiate(st->st_connection, &policy, st->st_serialno, &inception,
			 null_shunk, detach_whack, st->logger,
			 INITIATED_BY_REPLACE, HERE);
	}
}

void event_v2_replace(struct state *st, bool detach_whack)
{
	if (v2_state_is_expired(st, "replace")) {
		return;
	}

	ldbg(st->logger, "replacing stale %s", state_sa_name(st));

	ikev2_replace(st, detach_whack);

	/*
	 * XXX: this kills the existing state, which means the
	 * 'replace' is never smooth.
	 */
	event_force(EVENT_v2_EXPIRE, st);
}

void event_v2_rekey(struct state *st, bool detach_whack)
{
	if (v2_state_is_expired(st, "rekey")) {
		return;
	}

	struct ike_sa *ike = ike_sa(st, HERE);
	if (PBAD(st->logger, ike == NULL)) {
		return;
	}

	struct child_sa *larval_sa;
	if (IS_IKE_SA(st)) {
		larval_sa = submit_v2_CREATE_CHILD_SA_rekey_ike(ike, detach_whack);
	} else {
		larval_sa = submit_v2_CREATE_CHILD_SA_rekey_child(ike, pexpect_child_sa(st),
								  detach_whack);
	}

	llog(RC_LOG, larval_sa->sa.logger,
	     "initiating rekey to replace %s "PRI_SO" using IKE SA "PRI_SO,
	     state_sa_name(st),
	     pri_so(st->st_serialno),
	     pri_so(ike->sa.st_serialno));
}
