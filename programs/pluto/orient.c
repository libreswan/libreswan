/* information about connections between hosts and clients
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

#include "lswlog.h"		/* for bad_case() */
#include "log.h"
#include "connections.h"
#include "iface.h"
#include "server.h"		/* for listening; */
#include "orient.h"

static bool orient_1(struct connection *c, struct logger *logger);

bool oriented(const struct connection *c)
{
	if (!pexpect(c != NULL)) {
		return false;
	}

	return (c->interface != NULL);
}

static void swap_ends(struct connection *c, const char *reason)
{
	ldbg(c->logger, "  swapping local=%s remote=%s; %s",
	     c->local->config->leftright, c->remote->config->leftright,
	     reason);
	struct connection_end *local = c->local;
	c->local = c->remote;
	c->remote = local;

	for (struct spd_route *sr = c->spd; sr != NULL; sr = sr->spd_next) {
		struct spd_end *local = sr->local;
		sr->local = sr->remote;
		sr->remote = local;
	}

	/* rehash end dependent hashes */
	rehash_db_connection_that_id(c);
	for (struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {
		rehash_db_spd_route_remote_client(spd);
	}
}

static bool orient_new_iface_endpoint(struct connection *c, struct host_end *end)
{
	if (end->config->ikeport == 0) {
		return false;
	}
	if (address_is_unset(&end->addr)) {
		return false;
	}
	struct iface_dev *dev = find_iface_dev_by_address(&end->addr);
	if (dev == NULL) {
		return false;
	}
	/*
	 * A custom IKEPORT should not float away to port 4500.
	 * Assume a custom port always has the prefix (like 4500 and
	 * not 500).  Perhaps it doesn't belong in iface?
	 *
	 * Log against the connection that is causing the interface's
	 * port to be opened.
	 *
	 * XXX: what happens if a second connection is also interested
	 * in the interface?
	 *
	 * XXX: what about IPv4 vs IPv6, host_addr would have pinned
	 * that down?
	 */
	const bool esp_encapsulation_enabled = true;
	const bool float_nat_initiator = false;

	struct iface_endpoint *ifp = NULL;
	switch (c->iketcp) {
	case IKE_TCP_NO:
		if (pluto_listen_udp) {
			ifp = bind_iface_endpoint(dev, &udp_iface_io,
						  ip_hport(end->config->ikeport),
						  esp_encapsulation_enabled,
						  float_nat_initiator,
						  c->logger);
			if (ifp == NULL) {
				ldbg(c->logger, "could not create new UDP interface");
				return false;
			}
		}
		break;

	case IKE_TCP_ONLY:
		if (pluto_listen_tcp) {
			ifp = bind_iface_endpoint(dev, &iketcp_iface_io,
						  ip_hport(end->config->ikeport),
						  esp_encapsulation_enabled,
						  float_nat_initiator,
						  c->logger);
			if (ifp == NULL) {
				ldbg(c->logger, "could not create new TCP interface");
				return false;
			}
		}
		break;

	case IKE_TCP_FALLBACK:
		return false;

	default:
		bad_case(c->iketcp);
	}

	pexpect(c->interface == NULL);	/* no leak */
	if (ifp != NULL) {
		c->interface = iface_endpoint_addref(ifp); /* from bind */
		if (listening) {
			listen_on_iface_endpoint(ifp, c->logger);
		}
	}
	return true;
}

static bool end_matches_iface_endpoint(const struct host_end *this,
				       const struct host_end *that,
				       const struct iface_endpoint *ifp)
{
	ip_address this_host_addr = this->addr;
	if (!address_is_specified(this_host_addr)) {
		/* %any, unknown, or unset */
		return false;
	}

	/*
	 * which port?
	 */
	ip_port this_host_port = end_host_port(this, that);
	ip_endpoint this_host_endpoint =
		endpoint_from_address_protocol_port(this_host_addr,
						    ifp->io->protocol,
						    this_host_port);
	return endpoint_eq_endpoint(this_host_endpoint, ifp->local_endpoint);
}

static void LDBG_orient_end(struct logger *logger, const char *thisthat, struct host_end *this, struct host_end *that)
{
	address_buf ab;
	enum_buf enb;
	LDBG_log(logger, "  %s(%s) host type=%s address=%s port="PRI_HPORT" ikeport=%d encap=%s",
		 this->config->leftright, thisthat,
		 str_enum_short(&keyword_host_names, this->config->type, &enb),
		 str_address(&this->addr, &ab),
		 pri_hport(end_host_port(this, that)),
		 this->config->ikeport,
		 bool_str(this->encap));
}

bool orient(struct connection *c, struct logger *logger)
{
	if (oriented(c)) {
		ldbg(c->logger, "already oriented");
		return true;
	}

	if (!orient_1(c, logger)) {
		return false;
	}

	/* success; update everything */
	passert(oriented(c));
	set_policy_prio(c); /* update */

	return true;
}

bool orient_1(struct connection *c, struct logger *logger)
{
	if (DBGP(DBG_BASE)) {
		connection_buf cb;
		LDBG_log(c->logger, "orienting "PRI_CONNECTION, pri_connection(c, &cb));
		LDBG_orient_end(c->logger, "this", &c->local->host, &c->remote->host);
		LDBG_orient_end(c->logger, "that", &c->remote->host, &c->local->host);
	}
	passert(c->interface == NULL); /* aka not oriented */

	/*
	 * Save match; don't update the connection until all the
	 * interfaces have been checked.  More than one could match,
	 * oops!
	 */
	bool matching_swaps_end = false;
	struct iface_endpoint *matching_ifp = NULL;

	for (struct iface_endpoint *ifp = interfaces; ifp != NULL; ifp = ifp->next) {

		/* XXX: check connection allows p->protocol? */
		bool this = end_matches_iface_endpoint(&c->local->host, &c->remote->host, ifp);
		bool that = end_matches_iface_endpoint(&c->remote->host, &c->local->host, ifp);

		if (this && that) {
			/* too many choices */
			connection_buf cib;
			llog(RC_LOG_SERIOUS, logger,
			     "both sides of "PRI_CONNECTION" are our interface %s!",
			     pri_connection(c, &cib),
			     ifp->ip_dev->id_rname);
			terminate_connections_by_name(c->name, /*quiet?*/false, logger);
			return false;
		}

		if (!this && !that) {
			endpoint_buf eb;
			ldbg(c->logger, "  interface endpoint %s does not match %s(THIS) or %s(THAT)",
			     str_endpoint(&ifp->local_endpoint, &eb),
			     c->local->config->leftright, c->remote->config->leftright);
			continue;
		}

		pexpect(this != that); /* only one */

		if (matching_ifp != NULL) {
			/*
			 * Oops there's already a MATCHING_IFP.  Try
			 * to be helpful with the log line.
			 */
			if (matching_ifp->ip_dev == ifp->ip_dev) {
				connection_buf cib;
				llog(RC_LOG_SERIOUS, logger,
				     "both sides of "PRI_CONNECTION" are our interface %s!",
				     pri_connection(c, &cib),
				     ifp->ip_dev->id_rname);
			} else {
				/*
				 * XXX: if an interface has two
				 * addresses vis <<ip addr add
				 * 192.1.2.23/24 dev eth1>> this log
				 * line doesn't differentiate.
				 */
				connection_buf cib;
				address_buf cb, ifpb;
				llog(RC_LOG_SERIOUS, logger,
				     "two interfaces match "PRI_CONNECTION" (%s %s, %s %s)",
				     pri_connection(c, &cib),
				     matching_ifp->ip_dev->id_rname,
				     str_address(&matching_ifp->ip_dev->id_address, &cb),
				     ifp->ip_dev->id_rname,
				     str_address(&ifp->ip_dev->id_address, &ifpb));
			}
			terminate_connections_by_name(c->name, /*quiet?*/false, logger);
			return false;
		}

		/* save match, and then continue search */
		matching_ifp = ifp;
		passert(this != that); /* only one */
		if (this) {
			endpoint_buf eb;
			ldbg(c->logger, "  interface endpoint %s matches %s(THIS); orienting",
			     str_endpoint(&ifp->local_endpoint, &eb),
			     c->local->config->leftright);
			matching_swaps_end = false;
		}
		if (that) {
			endpoint_buf eb;
			ldbg(c->logger, "  interface endpoint %s matches %s(THAT); orienting and swapping",
			     str_endpoint(&ifp->local_endpoint, &eb),
			     c->remote->config->leftright);
			matching_swaps_end = true;
		}
	}

	if (matching_ifp != NULL) {
		pexpect(c->interface == NULL); /* wasn't updated */
		c->interface = iface_endpoint_addref(matching_ifp);
		if (matching_swaps_end) {
			swap_ends(c, "existing interface");
		}
		return true;
	}

	/*
	 * No existing interface worked, create a new one?
	 */

	if (orient_new_iface_endpoint(c, &c->local->host)) {
		return true;
	}

	if (orient_new_iface_endpoint(c, &c->remote->host)) {
		swap_ends(c, "new interface");
		return true;
	}

	return false;
}
