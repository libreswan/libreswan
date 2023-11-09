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
#include "terminate.h"
#include "host_pair.h"

static enum left_right orient_1(struct connection **cp, struct logger *logger);

bool oriented(const struct connection *c)
{
	if (!pexpect(c != NULL)) {
		return false;
	}

	return (c->iface != NULL);
}

void disorient(struct connection *c)
{
	if (oriented(c)) {
		PEXPECT(c->logger, c->host_pair != NULL);
		delete_oriented_hp(c);
		PEXPECT(c->logger, c->host_pair == NULL);
		iface_delref(&c->iface);
		/* Since it is unoriented, it will be connected to the
		 * unoriented_connections list */
		PASSERT(c->logger, !oriented(c));
		connect_to_unoriented(c);
	}
}

static void add_iface_endpoint(bool listening,
			       struct connection *c,
			       const struct iface_io *io)
{
	ip_port local_port = ip_hport(c->local->config->host.ikeport);

	if (local_port.hport == 0) {
		address_buf ab;
		ldbg(c->logger, "  skipping %s %s; no custom %s port",
		     c->iface->real_device_name,
		     str_address(&c->iface->local_address, &ab),
		     io->protocol->name);
		return;
	}

	if (!listening) {
		address_buf ab;
		ldbg(c->logger, "  skipping %s %s "PRI_HPORT"; not listening to %s",
		     c->iface->real_device_name,
		     str_address(&c->iface->local_address, &ab),
		     pri_hport(local_port),
		     io->protocol->name);
		return;
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

	/*
	 * See if it already exists.
	 */

	ip_endpoint local_endpoint =
		endpoint_from_address_protocol_port(c->local->host.addr,
						    io->protocol,
						    local_port);

	struct iface_endpoint *ife = find_iface_endpoint_by_local_endpoint(local_endpoint); /* must delref */
	if (ife != NULL) {
		address_buf ab;
		ldbg(c->logger, "  skipping %s %s; already bound to %s port "PRI_HPORT,
		     c->iface->real_device_name,
		     str_address(&c->iface->local_address, &ab),
		     io->protocol->name,
		     pri_hport(local_port));
		iface_endpoint_delref(&ife);
		return;
	}

	struct iface_endpoint *ifp = bind_iface_endpoint(c->iface, io,
							 local_port,
							 esp_encapsulation_enabled,
							 float_nat_initiator,
							 c->logger);
	if (ifp == NULL) {
		address_buf ab;
		llog(RC_LOG_SERIOUS, c->logger,
		     "  skipping %s %s; bind of %s port "PRI_HPORT" failed",
		     c->iface->real_device_name,
		     str_address(&c->iface->local_address, &ab),
		     io->protocol->name,
		     pri_hport(local_port));
		return;
	}

	address_buf ab;
	ldbg(c->logger, "  %s %s; bound to %s port "PRI_HPORT,
	     c->iface->real_device_name,
	     str_address(&c->iface->local_address, &ab),
	     io->protocol->name,
	     pri_hport(local_port));

	if (listening) {
		listen_on_iface_endpoint(ifp, c->logger);
	}
}

/*
 * Bind to any missing interfaces.
 */

static void add_iface_endpoints(struct connection *c)
{
	add_iface_endpoint(pluto_listen_udp, c, &udp_iface_io);
	add_iface_endpoint(pluto_listen_tcp, c, &iketcp_iface_io);
}

static bool host_end_matches_iface(const struct connection *c, enum left_right end,
				   const struct iface *iface)
{
	const struct host_end *this = &c->end[end].host;

	ip_address this_host_addr = this->addr;
	if (!address_is_specified(this_host_addr)) {
		/* %any, unknown, or unset */
		return false;
	}

	return address_eq_address(this->addr, iface->local_address);
}

static void LDBG_orient_end(struct connection *c, enum left_right end)
{
	const struct host_end *this = &c->end[end].host;
	const struct host_end *that = &c->end[!end].host;
	address_buf ab;
	enum_buf enb;
	sparse_buf tcpb;
	LDBG_log(c->logger, "  %s host type=%s address=%s port="PRI_HPORT" ikeport=%d encap=%s tcp=%s",
		 this->config->leftright,
		 str_enum_short(&keyword_host_names, this->config->type, &enb),
		 str_address(&this->addr, &ab),
		 pri_hport(end_host_port(this, that)),
		 this->config->ikeport,
		 bool_str(this->encap),
		 str_sparse(tcp_option_names, c->local->config->host.iketcp, &tcpb));
}

bool orient(struct connection **cp, struct logger *logger)
{
	if (oriented((*cp))) {
		ldbg((*cp)->logger, "already oriented");
		return true;
	}

	enum left_right end = orient_1(cp, logger);
	if (end == END_ROOF) {
		return false;
	}

	if (PBAD(logger, (*cp) == NULL)) {
		return false;
	}

	struct connection_end *local = &(*cp)->end[end];
	struct connection_end *remote = &(*cp)->end[!end];

	ldbg((*cp)->logger, "  orienting %s=local %s=remote",
	     local->config->leftright, remote->config->leftright);

	(*cp)->local = local;
	(*cp)->remote = remote;

	FOR_EACH_ITEM(spd, &(*cp)->child.spds) {
		spd->local = &spd->end[end];
		spd->remote = &spd->end[!end];
	}

	/* rehash end dependent hashes */
	connection_db_rehash_that_id((*cp));
	FOR_EACH_ITEM(spd, &(*cp)->child.spds) {
		spd_route_db_rehash_remote_client(spd);
	}

	/*
	 * Add a listen for any missing interface endpoints.
	 */
	add_iface_endpoints((*cp));

	return true;
}

static void jam_iface(struct jambuf *buf, const struct iface *iface)
{
	jam_string(buf, iface->real_device_name);
	jam_string(buf, " ");
	jam_address(buf, &iface->local_address);
}

enum left_right orient_1(struct connection **cp, struct logger *logger)
{
	if (DBGP(DBG_BASE)) {
		connection_buf cb;
		LDBG_log((*cp)->logger, "orienting "PRI_CONNECTION, pri_connection((*cp), &cb));
		LDBG_orient_end((*cp), LEFT_END);
		LDBG_orient_end((*cp), RIGHT_END);
	}
	passert((*cp)->iface == NULL); /* aka not oriented */

	/*
	 * Save match; don't update the connection until all the
	 * interfaces have been checked.  More than one could match,
	 * oops!
	 */
	enum left_right matching_end = END_ROOF;/*invalid*/
	struct iface *matching_iface = NULL;

	for (struct iface *iface = next_iface(NULL); iface != NULL; iface = next_iface(iface)) {

		/* XXX: check connection allows p->protocol? */
		bool left = host_end_matches_iface((*cp), LEFT_END, iface);
		bool right = host_end_matches_iface((*cp), RIGHT_END, iface);

		if (!left && !right) {
			if (DBGP(DBG_BASE)) {
				LLOG_JAMBUF(DEBUG_STREAM, (*cp)->logger, buf) {
					jam_string(buf, "    interface ");
					jam_iface(buf, iface);
					jam_string(buf, " does not match left or right");
				}
			}
			continue;
		}

		if (left && right) {
			/* too many choices */
			connection_attach((*cp), logger);
			connection_attach((*cp), logger);
			LLOG_JAMBUF(RC_LOG_SERIOUS, (*cp)->logger, buf) {
				jam_string(buf, "connection matches both left ");
				jam_iface(buf, iface);
				jam_string(buf, " and right ");
				jam_iface(buf, iface);
			}
			terminate_and_down_connections(cp, logger, HERE);
			connection_detach((*cp), logger);
			return END_ROOF;
		}

		passert(left != right); /* only one */
		enum left_right end = (left ? LEFT_END :
				       right ? RIGHT_END :
				       END_ROOF);
		passert(end != END_ROOF);

		if (matching_iface != NULL) {
			/*
			 * Oops there's already a MATCHING_IFACE.  Try
			 * to be helpful with the log line.
			 *
			 * Presumably the LHS(say) matched the first
			 * interface and the RHS(say) is now matching
			 * the second.
			 *
			 * XXX: if an interface has two addresses vis
			 * <<ip addr add 192.1.2.23/24 dev eth1>> this
			 * log line doesn't differentiate.
			 */
			pexpect(end != matching_end);
			connection_attach((*cp), logger);
			LLOG_JAMBUF(RC_LOG_SERIOUS, (*cp)->logger, buf) {
				jam_string(buf, "connection matches both ");
				/*previous-match*/
				jam_string(buf, (*cp)->end[matching_end].config->leftright);
				jam_string(buf, " ");
				jam_iface(buf, matching_iface);
				jam_string(buf, " and ");
				/* new match */
				jam_string(buf, (*cp)->end[end].config->leftright);
				jam_string(buf, " ");
				jam_iface(buf, iface);
			}
			terminate_and_down_connections(cp, logger, HERE);
			connection_detach((*cp), logger);

			return END_ROOF;
		}

		/* save match, and then continue search */
		if (DBGP(DBG_BASE)) {
			LLOG_JAMBUF(DEBUG_STREAM, (*cp)->logger, buf) {
				jam_string(buf, "    interface ");
				jam_iface(buf, iface);
				jam_string(buf, " matches '");
				jam_string(buf, (*cp)->end[end].config->leftright);
				jam_string(buf, "'; orienting");
			}
		}
		matching_iface = iface;
		matching_end = end;
	}

	if (matching_iface == NULL) {
		return END_ROOF;
	}

	/*
	 * Attach the interface (still not properly oriented).
	 */
	PASSERT((*cp)->logger, matching_end != END_ROOF);
	PEXPECT((*cp)->logger, (*cp)->iface == NULL); /* wasn't updated */
	(*cp)->iface = iface_addref(matching_iface);

	return matching_end;

}
