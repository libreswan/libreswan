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
#include "ikev2_parent.h"

/* Replace SA with a fresh one that is similar
 *
 * Shares some logic with ipsecdoi_initiate, but not the same!
 * - we must not reuse the ISAKMP SA if we are trying to replace it!
 * - if trying to replace IPSEC SA, use ipsecdoi_initiate to build
 *   ISAKMP SA if needed.
 * - duplicate whack fd, if live.
 * Does not delete the old state -- someone else will do that.
 */

void ikev2_replace(struct state *st)
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
		lset_t policy = LEMPTY;
		if (IS_IKE_SA_ESTABLISHED(st)) {
			log_state(RC_LOG, st, "initiate reauthentication of IKE SA");
		}
		initiate_v2_IKE_SA_INIT_request(c, st, policy, &inception,
						HUNK_AS_SHUNK(c->child.sec_label),
						/*background?*/false);

	} else {

		/*
		 * Start from policy in (ipsec) state, not connection.
		 * This ensures that rekeying doesn't downgrade
		 * security.  I admit that this doesn't capture
		 * everything.
		 */
		lset_t policy = capture_child_rekey_policy(st);

		initiate(st->st_connection, policy, st->st_serialno, &inception,
			 null_shunk, /*background?*/false, st->logger,
			 INITIATED_BY_REPLACE, HERE);
	}
}

void event_v2_replace(struct state *st, monotime_t now UNUSED)
{
	if (v2_state_is_expired(st, "replace")) {
		return;
	}

	const char *satype = IS_IKE_SA(st) ? "IKE" : "Child";
	ldbg(st->logger, "replacing stale %s SA", satype);

	ikev2_replace(st);
	event_force(EVENT_v2_EXPIRE, st);
}
