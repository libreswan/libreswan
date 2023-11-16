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
#include "host_pair.h"

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
		connection_buf cb;
		ldbg(c->logger,
		     "pending ddns: connection "PRI_CONNECTION" has no .dnshostname",
		     pri_connection(c, &cb));
		return;
	}

	/* should we let the caller get away with this? */
	if (never_negotiate(c)) {
		connection_buf cb;
		ldbg(c->logger,
		     "pending ddns: connection "PRI_CONNECTION" is never_negotiate",
		     pri_connection(c, &cb));
		return;
	}

	/*
	 * We do not update a resolved address once resolved.  That might
	 * be considered a bug.  Can we count on liveness if the target
	 * changed IP?  The connection might need to get its host_addr
	 * updated.  Do we do that when terminating the conn?
	 */
	if (address_is_specified(c->remote->host.addr)) {
		connection_buf cib;
		ldbg(c->logger,
		     "pending ddns: connection "PRI_CONNECTION" has address",
		     pri_connection(c, &cib));
		return;
	}

	if (c->remote->config->child.protoport.has_port_wildcard ||
	    (c->config->never_negotiate_shunt == SHUNT_UNSET &&
	     id_has_wildcards(&c->remote->host.id))) {
		connection_buf cib;
		ldbg(c->logger,
		     "pending ddns: connection "PRI_CONNECTION" with wildcard not started",
		     pri_connection(c, &cib));
		return;
	}

	/* XXX: blocking call */
	ip_address new_remote_addr;
	e = ttoaddress_dns(shunk1(c->config->dnshostname), NULL/*UNSPEC*/, &new_remote_addr);
	if (e != NULL) {
		connection_buf cib;
		ldbg(c->logger,
		     "pending ddns: connection "PRI_CONNECTION" lookup of \"%s\" failed: %s",
		     pri_connection(c, &cib), c->config->dnshostname, e);
		return;
	}

	if (!address_is_specified(new_remote_addr)) {
		connection_buf cib;
		ldbg(c->logger,
		     "pending ddns: connection "PRI_CONNECTION" still no address for \"%s\"",
		     pri_connection(c, &cib), c->config->dnshostname);
		return;
	}

	/* do not touch what is not broken */
	struct ike_sa *established_ike = ike_sa_by_serialno(c->established_ike_sa);
	if (established_ike != NULL) {
		/* also require viable? */
		PEXPECT(established_ike->sa.logger, (IS_IKE_SA_ESTABLISHED(&established_ike->sa) ||
						     IS_V1_ISAKMP_SA_ESTABLISHED(&established_ike->sa)));
		pdbg(c->logger,
		     "pending ddns: connection is established");
		return;
	}

	/*
	 * This cannot currently be reached.  If in the future we do,
	 * don't do weird things
	 */
	if (sameaddr(&new_remote_addr, &c->remote->host.addr)) {
		connection_buf cib;
		ldbg(c->logger,
		     "pending ddns: connection "PRI_CONNECTION" address is unchanged",
		     pri_connection(c, &cib));
		return;
	}

	/* I think this is OK now we check everything above. */

	address_buf old, new;
	connection_buf cb;
	ldbg(c->logger,
	     "pending ddns: connection "PRI_CONNECTION" IP address updated by '%s' from %s to %s",
	     pri_connection(c, &cb),
	     c->config->dnshostname,
	     str_address_sensitive(&c->remote->host.addr, &old),
	     str_address_sensitive(&new_remote_addr, &new));
	pexpect(!address_is_specified(c->remote->host.addr)); /* per above */

	/* propogate remote address */
	ldbg(c->logger, "  updating hosts");
	update_hosts_from_end_host_addr(c, c->remote->config->index, new_remote_addr, HERE); /* from DNS */
	ldbg(c->logger, "  discarding SPDs");
	discard_connection_spds(c);

	if (c->remote->child.config->selectors.len > 0) {
		ldbg(c->logger, "  %s.child already has hard-wired selectors; skipping",
		     c->remote->config->leftright);
	} else if (c->remote->child.has_client) {
		pexpect(is_opportunistic(c));
		ldbg(c->logger, "  %s.child.has_client yet no selectors; skipping magic",
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
		ldbg(logger,
		     "  updated %s.selector to %s",
		    c->remote->config->leftright,
		    str_selector(&remote, &new));
		append_end_selector(c->remote, selector_info(remote), remote,
				    c->logger, HERE);
	}

	ldbg(c->logger, "  adding SPDs");
	add_connection_spds(c, address_info(c->local->host.addr));

	/*
	 * reduce the work we do by updating all connections waiting for this
	 * lookup
	 */
	ldbg(c->logger, "  updating host pairs");
	update_host_pairs(c);

	if (!c->policy.up) {
		connection_buf cib;
		ldbg(c->logger,
		     "pending ddns: connection "PRI_CONNECTION" was updated, but does not want to be up",
		     pri_connection(c, &cib));
		return;
	}

	connection_buf cib;
	ldbg(c->logger,
	     "pending ddns: re-initiating connection "PRI_CONNECTION"",
	     pri_connection(c, &cib));
	initiate_connection(c, /*remote-host-name*/NULL,
			    /*background*/true,
			    logger);
}

void connection_check_ddns(struct logger *logger)
{
	threadtime_t start = threadtime_start();

	struct connection_filter cf = { .where = HERE, };
	while (next_connection_new2old(&cf)) {
		struct connection *c = cf.c;
		connection_check_ddns1(c, logger);
	}

	ldbg(logger, "DDNS: checking orientations");
	check_orientations(logger);

	threadtime_stop(&start, SOS_NOBODY, "in %s for hostname lookup", __func__);
}

void init_ddns(void)
{
	enable_periodic_timer(EVENT_PENDING_DDNS, connection_check_ddns,
			      deltatime(PENDING_DDNS_INTERVAL));
}
