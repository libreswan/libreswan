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

	return (c->interface != NULL);
}

void disorient(struct connection *c)
{
	if (oriented(c)) {
		PEXPECT(c->logger, c->host_pair != NULL);
		delete_oriented_hp(c);
		PEXPECT(c->logger, c->host_pair == NULL);
		iface_endpoint_delref(&c->interface);
		/* Since it is unoriented, it will be connected to the
		 * unoriented_connections list */
		PASSERT(c->logger, !oriented(c));
		connect_to_host_pair(c);
	}
}

static struct iface_endpoint *new_iface_endpoint(bool listening,
						 struct iface *dev,
						 const struct iface_io *io,
						 const struct host_end_config *end,
						 struct logger *logger)
{
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

	if (!listening) {
		ldbg(logger, "  skipping %s interface; not listening to %s",
		     end->leftright, io->protocol->name);
		return NULL;
	}

	struct iface_endpoint *ifp = bind_iface_endpoint(dev, io,
							 ip_hport(end->ikeport),
							 esp_encapsulation_enabled,
							 float_nat_initiator,
							 logger);
	if (ifp == NULL) {
		llog(RC_LOG_SERIOUS, logger,
		     "skipping %s interface; %s bind failed",
		     end->leftright, io->protocol->name);
		return NULL;
	}

	ldbg(logger, "%s interface; %s created",
	     end->leftright, io->protocol->name);

	if (listening) {
		listen_on_iface_endpoint(ifp, logger);
	}

	return ifp;
}

static bool add_new_iface_endpoints(struct connection *c, struct host_end *end)
{
	if (end->config->ikeport == 0) {
		ldbg(c->logger, "  skipping %s interface; no ikeport", end->config->leftright);
		return false;
	}
	if (!end->addr.is_set) {
		ldbg(c->logger, "  skipping %s interface; no address", end->config->leftright);
		return false;
	}

	struct iface *iface = find_iface_by_address(&end->addr); /* must delref */
	if (iface == NULL) {
		address_buf ab;
		ldbg(c->logger, "  skipping %s interface; no device matches %s",
		     end->config->leftright, str_address(&end->addr, &ab));
		return false;
	}

	/*
	 * Create both interfaces; but bind to only one.
	 */

	struct iface_endpoint *udp = new_iface_endpoint(pluto_listen_udp,
							iface, &udp_iface_io,
							end->config, c->logger);

	struct iface_endpoint *tcp = new_iface_endpoint(pluto_listen_tcp,
							iface, &iketcp_iface_io,
							end->config, c->logger);

	iface_delref(&iface); /* all done */

	struct iface_endpoint *ifp = (udp != NULL ? udp :
				      tcp != NULL ? tcp :
				      NULL);
	if (ifp == NULL) {
		llog(RC_LOG_SERIOUS, c->logger, "no %s interface bound to port %d",
		     end->config->leftright, end->config->ikeport);
		return false;
	}

	pexpect(c->interface == NULL);	/* no leak */
	c->interface = iface_endpoint_addref(ifp); /* from bind */

	ldbg(c->logger, "  adding %s interface",
	     end->config->leftright);

	return true;
}

static bool host_end_matches_iface_endpoint(const struct connection *c, enum left_right end,
					    const struct iface_endpoint *ifp)
{
	const struct host_end *this = &c->end[end].host;
	const struct host_end *that = &c->end[!end].host;

	ip_address this_host_addr = this->addr;
	if (!address_is_specified(this_host_addr)) {
		/* %any, unknown, or unset */
		return false;
	}

	/*
	 * which port?
	 */
	ip_port this_host_port = end_host_port(this, that);
	const struct ip_protocol *this_host_protocol;
	switch (c->local->config->host.iketcp) {
	case IKE_TCP_NO:
	case IKE_TCP_FALLBACK:
		this_host_protocol = &ip_protocol_udp;
		break;
	case IKE_TCP_ONLY:
		this_host_protocol = &ip_protocol_tcp;
		break;
	default:
		bad_sparse(c->logger, tcp_option_names, c->local->config->host.iketcp);
	}
	ip_endpoint this_host_endpoint =
		endpoint_from_address_protocol_port(this_host_addr,
						    this_host_protocol,
						    this_host_port);
	return endpoint_eq_endpoint(this_host_endpoint, ifp->local_endpoint);
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
	return true;
}

static void jam_if(struct jambuf *buf, const struct iface_endpoint *ifp)
{
	jam_string(buf, ifp->ip_dev->real_device_name);
	jam_string(buf, " ");
	if (ifp->io->protocol->prefix != NULL) {
		jam_string_human(buf, ifp->io->protocol->prefix);
	} else {
		jam_string_human(buf, ifp->io->protocol->name);
	}
	jam_string(buf, ":");
	jam_endpoint(buf, &ifp->local_endpoint);
}

enum left_right orient_1(struct connection **cp, struct logger *logger)
{
	if (DBGP(DBG_BASE)) {
		connection_buf cb;
		LDBG_log((*cp)->logger, "orienting "PRI_CONNECTION, pri_connection((*cp), &cb));
		LDBG_orient_end((*cp), LEFT_END);
		LDBG_orient_end((*cp), RIGHT_END);
	}
	passert((*cp)->interface == NULL); /* aka not oriented */

	/*
	 * Save match; don't update the connection until all the
	 * interfaces have been checked.  More than one could match,
	 * oops!
	 */
	enum left_right matching_end = END_ROOF;/*invalid*/
	struct iface_endpoint *matching_ifp = NULL;

	for (struct iface_endpoint *ifp = interfaces; ifp != NULL; ifp = ifp->next) {

		/* XXX: check connection allows p->protocol? */
		bool left = host_end_matches_iface_endpoint((*cp), LEFT_END, ifp);
		bool right = host_end_matches_iface_endpoint((*cp), RIGHT_END, ifp);

		if (!left && !right) {
			endpoint_buf eb;
			ldbg((*cp)->logger, "    interface %s %s:%s does not match left or right",
			     ifp->ip_dev->real_device_name,
			     ifp->io->protocol->name,
			     str_endpoint(&ifp->local_endpoint, &eb));
			continue;
		}

		if (left && right) {
			/* too many choices */
			connection_attach((*cp), logger);
			connection_attach((*cp), logger);
			LLOG_JAMBUF(RC_LOG_SERIOUS, (*cp)->logger, buf) {
				jam_string(buf, "connection matches both left ");
				jam_if(buf, ifp);
				jam_string(buf, " and right ");
				jam_if(buf, ifp);
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

		if (matching_ifp != NULL) {
			/*
			 * Oops there's already a MATCHING_IFP.  Try
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
				jam_if(buf, matching_ifp);
				jam_string(buf, " and ");
				/* new match */
				jam_string(buf, (*cp)->end[end].config->leftright);
				jam_string(buf, " ");
				jam_if(buf, ifp);
			}
			terminate_and_down_connections(cp, logger, HERE);
			connection_detach((*cp), logger);

			return END_ROOF;
		}

		/* save match, and then continue search */
		matching_ifp = ifp;
		endpoint_buf eb;
		ldbg((*cp)->logger, "  interface %s endpoint %s matches '%s'; orienting",
		     ifp->ip_dev->real_device_name,
		     str_endpoint(&ifp->local_endpoint, &eb),
		     (*cp)->end[end].config->leftright);
		matching_end = end;
	}

	if (matching_ifp != NULL) {
		passert(matching_end != END_ROOF);
		pexpect((*cp)->interface == NULL); /* wasn't updated */
		(*cp)->interface = iface_endpoint_addref(matching_ifp);
		return matching_end;
	}

	/*
	 * No existing interface worked, try to create new ones.
	 */
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		passert((*cp)->interface == NULL); /* wasn't updated */
		if (add_new_iface_endpoints((*cp), &(*cp)->end[end].host)) {
			passert((*cp)->interface != NULL); /* was updated */
			return end;
		}
	}

	return END_ROOF;
}
