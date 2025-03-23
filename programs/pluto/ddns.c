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

static void connection_check_ddns1(struct connection *c, struct logger *logger)
{
	const char *e;

	/* this is the cheapest check, so do it first */
	if (c->config->dnshostname == NULL) {
		pdbg(c->logger, "pending ddns: skipping connection, has no .dnshostname");
		return;
	}

	/* should we let the caller get away with this? */
	if (never_negotiate(c)) {
		pdbg(c->logger, "pending ddns: skipping connection, is never_negotiate");
		return;
	}

	/*
	 * We do not update a resolved address once resolved.  That might
	 * be considered a bug.  Can we count on liveness if the target
	 * changed IP?  The connection might need to get its host_addr
	 * updated.  Do we do that when terminating the conn?
	 */
	if (address_is_specified(c->remote->host.addr)) {
		pdbg(c->logger, "pending ddns: skipping connection, already has address");
		return;
	}

	if (!is_permanent(c)) {
		pdbg(c->logger, "pending ddns: skipping connection, is not permanent");
		return;
	}

	/* should have been handled by above */
	if (pbad(id_has_wildcards(&c->remote->host.id))) {
		pdbg(c->logger, "pending ddns: skipping connection, remote has wildcard ID");
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
		pdbg(c->logger, "pending ddns: skipping connection, is established as "PRI_SO,
		     pri_so(established_ike->sa.st_serialno));
		return;
	}

	/* XXX: blocking call */

	ip_address new_remote_addr;
	e = ttoaddress_dns(shunk1(c->config->dnshostname), NULL/*UNSPEC*/, &new_remote_addr);
	if (e != NULL) {
		pdbg(c->logger, "pending ddns: skipping connection, lookup of \"%s\" failed: %s",
		     c->config->dnshostname, e);
		return;
	}

	if (!address_is_specified(new_remote_addr)) {
		pdbg(c->logger, "pending ddns: skipping connection, still no address for \"%s\"",
		     c->config->dnshostname);
		return;
	}

	/*
	 * Since above rejected a specified .remote .host .addr, this
	 * check currently cannot succeed.  If in the future we do,
	 * don't do weird things.
	 */
	if (sameaddr(&new_remote_addr, &c->remote->host.addr)) {
		llog_pexpect(c->logger, HERE, "pending ddns: skipping connection, unset address unchanged");
		return;
	}

	/* I think this is OK now we check everything above. */

	address_buf old, new;
	pdbg(c->logger,
	     "pending ddns: updating connection IP address by '%s' from %s to %s",
	     c->config->dnshostname,
	     str_address_sensitive(&c->remote->host.addr, &old),
	     str_address_sensitive(&new_remote_addr, &new));

	pexpect(!address_is_specified(c->remote->host.addr)); /* per above */

	/*
	 * Pull any existing routing based on current SPDs.  Remember,
	 * per above, the connection isn't established.
	 *
	 * Note: disorient() also deletes any SPDs, orient() will put
	 * them back.
	 */
	pdbg(c->logger, "  unrouting");
	connection_unroute(c, HERE);

	if (oriented(c)) {
		pdbg(c->logger, "  disorienting");
		disorient(c);
	} else {
		pdbg(c->logger, "  already disoriented");
	}

	/* propagate remote address */
	pdbg(c->logger, "  updating hosts");
	update_hosts_from_end_host_addr(c, c->remote->config->index, new_remote_addr, HERE); /* from DNS */

	if (c->remote->child.config->selectors.len > 0) {
		pdbg(c->logger, "  %s.child already has hard-wired selectors; skipping",
		     c->remote->config->leftright);
	} else if (c->remote->child.has_client) {
		pexpect(is_opportunistic(c));
		pdbg(c->logger, "  %s.child.has_client yet no selectors; skipping magic",
		     c->remote->config->leftright);
	} else {
		/*
		 * Default the end's child selector (client)
		 * to a subnet containing only the end's host
		 * address.
		 */
		struct child_end *child = &c->remote->child;
		ip_selector remote =
			selector_from_address_protoport(new_remote_addr, child->config->protoport);
		selector_buf new;
		pdbg(logger, "  updated %s.selector to %s",
		    c->remote->config->leftright,
		    str_selector(&remote, &new));
		append_end_selector(c->remote, selector_info(remote), remote,
				    c->logger, HERE);
	}

	/*
	 * Caller holds reference.
	 */
	pdbg(c->logger, "  orienting?");
	PASSERT(logger, !oriented(c));	/* see above */
	if (!orient(c, logger)) {
		pdbg(c->logger, "pending ddns: connection was updated, but did not orient");
		return;
	}

	if (c->policy.route) {
		ldbg(c->logger, "pending ddns: connection was updated, restoring route");
		connection_route(c, HERE);
	}

	if (c->policy.up) {
		ldbg(c->logger,
		     "pending ddns: connection was updated, (re-)initiating");
		initiate_connection(c, /*remote-host-name*/NULL,
				    /*background*/true,
				    logger);
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
		connection_check_ddns1(c, logger);
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
