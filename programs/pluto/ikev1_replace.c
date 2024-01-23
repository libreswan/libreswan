/* timer event handling
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2010-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2018 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2011 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2014-2021 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
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
#include "connections.h"
#include "ikev1_replace.h"
#include "log.h"
#include "ipsec_doi.h"
#include "timer.h"		/* for event_*() */
#include "ikev1.h"
#include "initiate.h"

/* Replace SA with a fresh one that is similar
 *
 * Shares some logic with ipsecdoi_initiate, but not the same!
 * - we must not reuse the ISAKMP SA if we are trying to replace it!
 * - if trying to replace IPSEC SA, use ipsecdoi_initiate to build
 *   ISAKMP SA if needed.
 * - duplicate whack fd, if live.
 * Does not delete the old state -- someone else will do that.
 */

void ikev1_replace(struct state *st)
{
	/*
	 * start billing the new state.  The old state also gets
	 * billed for this function call, oops.
	 */
	threadtime_t inception = threadtime_start();

	if (IS_IKE_SA(st)) {
		/* start from policy in connection */

		struct connection *c = st->st_connection;

		/* should this call capture_child_rekey_policy(st); */
		lset_t policy = LEMPTY;
		struct ike_sa *predecessor = pexpect_ike_sa(st);
		if (c->config->aggressive) {
			aggr_outI1(c, predecessor, policy, &inception, /*background?*/false);
		} else {
			main_outI1(c, predecessor, policy, &inception, /*background?*/false);
		}

	} else {

		/*
		 * Start from policy in (ipsec) state, not connection.
		 * This ensures that rekeying doesn't downgrade
		 * security.  I admit that this doesn't capture
		 * everything.
		 */
		lset_t policy = capture_child_rekey_policy(st);
		passert(HAS_IPSEC_POLICY(policy));
		initiate(st->st_connection, policy, st->st_serialno, &inception,
			 null_shunk, /*background?*/false, st->logger,
			 INITIATED_BY_REPLACE, HERE);
	}
}

void event_v1_replace(struct state *st, monotime_t now)
{
	const char *satype = IS_IKE_SA(st) ? "ISAKMP" : "IPsec";
	struct connection *c = st->st_connection;

	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (newer_sa != SOS_NOBODY) {
		/* not very interesting: no need to replace */
		ldbg(st->logger,
		     "not replacing stale %s SA %lu; #%lu will do",
		     satype, st->st_serialno, newer_sa);
	} else if (!c->config->rekey &&
		   monotime_cmp(now, >=, monotime_add(st->st_outbound_time,
						      c->config->sa_rekey_margin))) {
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
		ldbg(st->logger,
		     "not replacing stale %s SA: inactive for %jds",
		     satype, deltasecs(monotimediff(now, st->st_outbound_time)));
	} else {
		ldbg(st->logger, "replacing stale %s SA", satype);
		/*
		 * XXX: this call gets double billed -
		 * both to the state being deleted and
		 * to the new state being created.
		 */
		ikev1_replace(st);
	}

	event_delete(EVENT_v1_DPD, st);
	event_schedule(EVENT_v1_EXPIRE, st->st_replace_margin, st);
}
