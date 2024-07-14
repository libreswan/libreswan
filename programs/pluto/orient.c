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
#include "sparse_names.h"
#include "initiate.h"

static void terminate_and_disorient_connection(struct connection *c,
					       where_t where)
{
	/* Strip bits so connection shuts down.  */
	bool up = del_policy(c, policy.up);
	bool keep = del_policy(c, policy.keep);
	terminate_connection(c, where);
	disorient(c);
	/* Restore bits so next orient recovers.  */
	set_policy(c, policy.up, up);
	set_policy(c, policy.up, keep);
}

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
		iface_device_delref(&c->iface);
		PASSERT(c->logger, !oriented(c));
		/*
		 * Move to a special disoriented hash.
		 */
		connection_db_rehash_host_pair(c);
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

	struct iface_endpoint *ifp = bind_iface_endpoint(c->iface, io,
							 local_port,
							 ESP_ENCAPSULATION_ENABLED,
							 INITIATOR_PORT_FIXED,
							 c->logger);
	if (ifp == NULL) {
		address_buf ab;
		llog(RC_LOG, c->logger,
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
				   const struct iface_device *iface)
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
		 str_sparse(&tcp_option_names, c->local->config->host.iketcp, &tcpb));
}

static void jam_iface(struct jambuf *buf, const struct iface_device *iface)
{
	jam_string(buf, iface->real_device_name);
	jam_string(buf, " ");
	jam_address(buf, &iface->local_address);
}

bool orient(struct connection *c, struct logger *logger)
{
	if (DBGP(DBG_BASE)) {
		connection_buf cb;
		LDBG_log(c->logger, "orienting "PRI_CONNECTION, pri_connection(c, &cb));
		LDBG_orient_end(c, LEFT_END);
		LDBG_orient_end(c, RIGHT_END);
	}

	struct iface_device *old_iface = c->iface; /* for sanity checking below */

	/*
	 * Save match; don't update the connection until all the
	 * interfaces have been checked.  More than one could match,
	 * oops!
	 */

	bool need_offload = ((c->config->nic_offload == NIC_OFFLOAD_PACKET) ||
				(c->config->nic_offload == NIC_OFFLOAD_CRYPTO));

	enum left_right matching_end = END_ROOF;/*invalid*/
	struct iface_device *matching_iface = NULL;

	for (struct iface_device *iface = next_iface_device(NULL);
	     iface != NULL; iface = next_iface_device(iface)) {

		/* XXX: check connection allows p->protocol? */
		bool left = host_end_matches_iface(c, LEFT_END, iface);
		bool right = host_end_matches_iface(c, RIGHT_END, iface);

		if (!left && !right) {
			if (DBGP(DBG_BASE)) {
				LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
					jam_string(buf, "    interface ");
					jam_iface(buf, iface);
					jam_string(buf, " does not match left or right");
				}
			}
			continue;
		}

		if (left && right) {
			/* too many choices */
			connection_attach(c, logger);
			LLOG_JAMBUF(RC_LOG, c->logger, buf) {
				jam_string(buf, "connection matches both left ");
				jam_iface(buf, iface);
				jam_string(buf, " and right ");
				jam_iface(buf, iface);
			}
			terminate_and_disorient_connection(c, HERE);
			connection_detach(c, logger);
			return false;
		}

		passert(left != right); /* only one */
		enum left_right end = (left ? LEFT_END :
				       right ? RIGHT_END :
				       END_ROOF);
		passert(end != END_ROOF);

		if (need_offload && !iface->nic_offload) {
			llog(RC_LOG, c->logger,
			     "interface search skipped interface %s as it does not have nic-offload support",
			     iface->real_device_name);
			continue;
		}

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
			connection_attach(c, logger);
			LLOG_JAMBUF(RC_LOG, c->logger, buf) {
				jam_string(buf, "connection matches both ");
				/*previous-match*/
				jam_string(buf, c->end[matching_end].config->leftright);
				jam_string(buf, " ");
				jam_iface(buf, matching_iface);
				jam_string(buf, " and ");
				/* new match */
				jam_string(buf, c->end[end].config->leftright);
				jam_string(buf, " ");
				jam_iface(buf, iface);
			}
			terminate_and_disorient_connection(c, HERE);
			connection_detach(c, logger);
			return false;
		}

		/* save match, and then continue search */
		if (DBGP(DBG_BASE)) {
			LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
				jam_string(buf, "    interface ");
				jam_iface(buf, iface);
				jam_string(buf, " matches '");
				jam_string(buf, c->end[end].config->leftright);
				jam_string(buf, "'; orienting");
			}
		}
		matching_iface = iface;
		matching_end = end;
	}

	PEXPECT(c->logger, c->iface == old_iface); /* wasn't updated */

	if (matching_iface == NULL) {
		if (old_iface != NULL) {
			/* when there's no interface, there's nothing
			 * to terminate */
			connection_attach(c, logger);
			terminate_and_disorient_connection(c, HERE);
			connection_detach(c, logger);
		}
		return false;
	}

	if (matching_iface == c->iface) {
		/* well that was pointless */
		return true;
	}

	/*
	 * Switch interfaces (still not properly oriented).
	 */
	PASSERT(c->logger, matching_end != END_ROOF);
	disorient(c);
	c->iface = iface_addref(matching_iface);

	struct connection_end *local = &c->end[matching_end];
	struct connection_end *remote = &c->end[!matching_end];

	ldbg(c->logger, "  orienting %s=local %s=remote",
	     local->config->leftright, remote->config->leftright);

	c->local = local;
	c->remote = remote;

	FOR_EACH_ITEM(spd, &c->child.spds) {
		spd->local = &spd->end[matching_end];
		spd->remote = &spd->end[!matching_end];
	}

	/* rehash end dependent hashes */
	connection_db_rehash_that_id(c);
	FOR_EACH_ITEM(spd, &c->child.spds) {
		spd_db_rehash_remote_client(spd);
	}

	/* the ends may have flipped */
	connection_db_rehash_host_pair(c);

	/*
	 * Add a listen for any missing interface endpoints.
	 */
	add_iface_endpoints(c);

	/*
	 * If the connection was previously unoriented, route things
	 * when needed.
	 */
	if (old_iface == NULL/*i.e., unoriented*/) {
		PEXPECT(c->logger, c->routing.state == RT_UNROUTED);
		if (c->policy.route) {
			connection_route(c, HERE);
		}
		if (c->policy.up) {
			initiate_connection(c, /*REMOTE_HOST*/NULL, /*background*/true, logger);
		}
	}

	return true;
}

/*
 * Adjust orientations of connections to reflect newly added
 * interfaces.
 */

void check_orientations(struct logger *logger)
{
	/*
	 * Try to orient unoriented connections by re-building the
	 * unoriented connections list.
	 *
	 * The list is emptied, then as each connection fails to
	 * orient it goes back on the list.
	 */
	struct connection_filter cq = {
		.search = {
			.order = OLD2NEW,
			.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&cq)) {
		struct connection *c = cq.c;
		/* just try */
		bool was_oriented = oriented(c);
		bool is_oriented = orient(c, logger);
		/* log when it becomes oriented */
		if (!was_oriented && is_oriented) {
			connection_attach(c, logger);
			LLOG_JAMBUF(RC_LOG, c->logger, buf) {
				jam_orientation(buf, c, /*orientation_details*/true);
			}
			connection_detach(c, logger);
		}
	}
}

static void jam_host_addr(struct jambuf *buf, struct connection_end *end)
{
	jam_string(buf, end->host.config->leftright);
	jam_string(buf, "=");
	if (end->host.config->addr_name != NULL) {
		jam_string(buf, end->host.config->addr_name);
	} else {
		jam_address(buf, &end->host.addr);
	}
}

void jam_orientation(struct jambuf *buf,
		     struct connection *c,
		     bool oriented_details)
{
	/*
	 * Did the connection orient?
	 *
	 * When listening, a connection should orient so log
	 * failure, but when pluto isn't even listening
	 * connections can't orient so say nothing.
	 *
	 * Should successful orientation also be logged?
	 */
	if (oriented(c)) {
		if (oriented_details) {
			jam_string(buf, "oriented ");
		}
	} else if (listening) {
		jam_string(buf, "unoriented ");
	}

	/*
	 * What is the connection?  IKEv1, IKEv2, or never-negotiate?
	 *
	 * Use slightly different names compared to
	 * pluto_constants.c.
	 */
	static const char *const policy_shunt_names[SHUNT_POLICY_ROOF] = {
		[SHUNT_UNSET] = "[should not happen]",
		[SHUNT_TRAP] = "trap[should not happen]",
		[SHUNT_NONE] = "none",
		[SHUNT_PASS] = "passthrough",
		[SHUNT_DROP] = "drop",
		[SHUNT_REJECT] = "reject",
	};
	const char *what =
		(never_negotiate(c) ? policy_shunt_names[c->config->never_negotiate_shunt] :
		 c->config->ike_info->version_name);
	jam_string(buf, what);
	jam_string(buf, " connection");

	/*
	 * Provide an overview of the conection's orientation;
	 * or hints at where the problem is when it failed.
	 */
	if (oriented(c)) {
		if (oriented_details) {
			jam_string(buf, " (local: ");
			jam_host_addr(buf, c->local);
			jam_string(buf, " ");
			jam_string(buf, " remote: ");
			jam_host_addr(buf, c->remote);
			jam_string(buf, ")");
		}
	} else if (listening) {
		/*
		 * When listening, a connection should orient
		 * during load yet this one didn't!  Try to
		 * provide some helpful details.
		 */
		jam_string(buf, " (neither ");
		jam_host_addr(buf, &c->end[LEFT_END]);
		jam_string(buf, " nor ");
		jam_host_addr(buf, &c->end[RIGHT_END]);
		jam_string(buf, " match an interface)");
	}
}

