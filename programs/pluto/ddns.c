/* DDNS, for libreswan
 *
 * Copyright (C) 1998-2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2009-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2007-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Panagiotis Tamtamis <tamtamis@gmail.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include "ddns.h"
#include "defs.h"
#include "connections.h"
#include "state.h"
#include "log.h"
#include "timer.h"
#include "initiate.h"
#include "orient.h"
#include "show.h"

/* time before retrying DDNS host lookup for phase 1 */
#define PENDING_DDNS_INTERVAL secs_per_minute

/*
 * Call me periodically to check to see if any DDNS tunnel can come up.
 * The order matters, we try to do the cheapest checks first.
 */

static void connection_check_ddns1(struct connection *c, struct verbose verbose)
{
	/* This is the cheapest check, so do it first */
	if (never_negotiate(c)) {
		vdbg("skipping connection %s, is never_negotiate",
		     c->name);
		return;
	}

	/* find the end needing DNS */
	if (c->remote->config->host.host.type != KH_IPHOSTNAME) {
		vdbg("skipping connection %s, has no KP_IPHOSTNAME",
		     c->name);
		return;
	}

	if (PBAD(c->logger, c->remote->config->host.host.name == NULL)) {
		return;
	}

	/*
	 * We do not update a resolved address once resolved.  That might
	 * be considered a bug.  Can we count on liveness if the target
	 * changed IP?  The connection might need to get its host_addr
	 * updated.  Do we do that when terminating the conn?
	 */
	if (address_is_specified(c->remote->host.addr)) {
		vdbg("skipping connection %s, already has address",
		     c->name);
		return;
	}

	if (!is_permanent(c)) {
		vdbg("skipping connection %s, is not permanent",
		     c->name);
		return;
	}

	/* should have been handled by above */
	if (pbad(id_has_wildcards(&c->remote->host.id))) {
		vdbg("skipping connection %s, remote has wildcard ID",
		     c->name);
		return;
	}

	/*
	 * Do not touch what is not broken.
	 *
	 * XXX: Can this happen?  Above has rejected any connection
	 * with a valid .remote .host .addr, and having that is a
	 * requirement for establishing a connection?
	 */
	struct ike_sa *established_ike = ike_sa_by_serialno(c->established_ike_sa);
	if (established_ike != NULL) {
		/* also require viable? */
		PEXPECT(established_ike->sa.logger, (IS_IKE_SA_ESTABLISHED(&established_ike->sa) ||
						     IS_V1_ISAKMP_SA_ESTABLISHED(&established_ike->sa)));
		vdbg("skipping connection %s, is established as "PRI_SO,
		     c->name, pri_so(established_ike->sa.st_serialno));
		return;
	}

	vdbg("updating connection IP addresses");
	verbose.level++;

	/* XXX: blocking call on dedicated thread */

	if (!resolve_connection_hosts_from_configs(c, verbose)) {
		return;
	}

	/*
	 * Pull any existing routing based on current SPDs.  Remember,
	 * per above, the connection isn't established.
	 *
	 * Note: disorient() also deletes any SPDs, orient() will put
	 * them back.
	 */
	vdbg("unrouting");
	connection_unroute(c, HERE);

	if (oriented(c)) {
		vdbg("disorienting");
		disorient(c);
	} else {
		vdbg("already disoriented");
	}

	/*
	 * Caller holds reference.
	 */
	vdbg("orienting?");
	vassert(!oriented(c));	/* see above */
	if (!orient(c, verbose.logger)) {
		vdbg("connection was updated, but did not orient");
		return;
	}

	if (c->policy.route) {
		vdbg("connection was updated, restoring route");
		connection_route(c, HERE);
	}

	if (c->policy.up) {
		vdbg("connection was updated, (re-)initiating");
		initiate_connection(c, /*remote-host-name*/NULL,
				    /*background*/true,
				    verbose.logger);
	}
}

static void connection_check_ddns(struct logger *logger)
{
	threadtime_t start = threadtime_start();

	struct connection_filter cf = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&cf)) {
		/* addref, delref is probably over kill */
		struct connection *c = connection_addref(cf.c, logger);
		connection_attach(c, logger);
		struct verbose verbose = VERBOSE(DEBUG_STREAM, c->logger, "pending ddns");
		connection_check_ddns1(c, verbose);
		connection_detach(c, logger);
		connection_delref(&c, logger);
	}

	threadtime_stop(&start, SOS_NOBODY, "in %s for hostname lookup", __func__);
}

void whack_ddns(const struct whack_message *wm UNUSED, struct show *s)
{
	struct logger *logger = show_logger(s);
	llog(RC_LOG, logger, "updating pending dns lookups");
	connection_check_ddns(logger);
}

void init_ddns(void)
{
	enable_periodic_timer(EVENT_PENDING_DDNS, connection_check_ddns,
			      deltatime(PENDING_DDNS_INTERVAL));
}
