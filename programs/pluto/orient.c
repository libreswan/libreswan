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

/*
 * Swap ends and try again.
 * It is a little tricky to see that this loop will stop.
 * Only continue if the far side matches.
 * If both sides match, there is an error-out.
 */
static void swap_ends(struct connection *c)
{
	struct spd_route *sr = &c->spd;
	struct end this = sr->this;

	sr->this = sr->that;
	sr->that = this;

	const struct config_end *local = c->local;
	c->local = c->remote;
	c->remote = local;

	/*
	 * In case of asymmetric auth c->policy contains left.authby.
	 * This magic will help responder to find connection during INIT.
	 */
	if (sr->this.authby != sr->that.authby)
	{
		c->policy &= ~POLICY_ID_AUTH_MASK;
		switch (sr->this.authby) {
		case AUTHBY_PSK:
			c->policy |= POLICY_PSK;
			break;
		case AUTHBY_RSASIG:
			c->policy |= POLICY_RSASIG;
			break;
		case AUTHBY_ECDSA:
			c->policy |= POLICY_ECDSA;
			break;
		case AUTHBY_NULL:
			c->policy |= POLICY_AUTH_NULL;
			break;
		case AUTHBY_NEVER:
			/* nothing to add */
			break;
		default:
			bad_case(sr->this.authby);
		}
	}
	/* re-compute the base policy priority using the swapped left/right */
	set_policy_prio(c);
}

static bool orient_new_iface_endpoint(struct connection *c, struct fd *whackfd, bool this)
{
	struct end *end = (this ? &c->spd.this : &c->spd.that);
	if (end->config->host.ikeport == 0) {
		return false;
	}
	if (address_is_unset(&end->host_addr)) {
		return false;
	}
	struct iface_dev *dev = find_iface_dev_by_address(&end->host_addr);
	if (dev == NULL) {
		return false;
	}
	/*
	 * assume UDP for now
	 *
	 * A custom IKEPORT should not float away to port 4500.  For
	 * now leave ADD_IKE_ENCAPSULATION_PREFIX clear so it can talk
	 * to port 500.  Perhaps it doesn't belong in iface?
	 *
	 * XXX: should this log globally or against the connection?
	 */
	struct logger logger[1] = { GLOBAL_LOGGER(whackfd), };
	struct iface_endpoint *ifp = bind_iface_endpoint(dev, &udp_iface_io,
							 ip_hport(end->config->host.ikeport),
							 true/*esp_encapsulation_enabled*/,
							 false/*float_nat_initiator*/,
							 logger);
	if (ifp == NULL) {
		dbg("could not create new interface");
		return false;
	}
	/* already logged */
	c->interface = ifp;
	if (!this) {
		dbg("swapping to that; new interface");
		swap_ends(c);
	}
	if (listening) {
		listen_on_iface_endpoint(ifp, logger);
	}
	return true;
}

static bool end_matches_iface_endpoint(const struct end *end,
				       const struct end *other_end,
				       const struct iface_endpoint *ifp)
{
	ip_address host_addr = end->host_addr;
	if (!address_is_specified(host_addr)) {
		/* %any, unknown, or unset */
		return false;
	}

	/*
	 * which port?
	 */
	ip_port port = end_host_port(end, other_end);
	ip_endpoint host_end = endpoint_from_address_protocol_port(host_addr,
								   ifp->protocol,
								   port);
	return endpoint_eq_endpoint(host_end, ifp->local_endpoint);
}

bool orient(struct connection *c)
{
	struct fd *whackfd = whack_log_fd; /* placeholder */
	if (oriented(*c)) {
		dbg("already oriented");
		return true;
	}

	connection_buf cb;
	dbg("orienting "PRI_CONNECTION, pri_connection(c, &cb));
	address_buf ab;
	dbg("  %s(THIS) host-address=%s host-port="PRI_HPORT" ikeport=%d encap=%s",
	    c->spd.this.leftright, str_address(&c->spd.this.host_addr, &ab),
	    pri_hport(end_host_port(&c->spd.this, &c->spd.that)),
	    c->local->host.ikeport, bool_str(c->spd.this.host_encap));
	dbg("  %s(THAT) host-address=%s host-port="PRI_HPORT" ikeport=%d encap=%s",
	    c->spd.that.leftright, str_address(&c->spd.that.host_addr, &ab),
	    pri_hport(end_host_port(&c->spd.that, &c->spd.this)),
	    c->remote->host.ikeport, bool_str(c->spd.that.host_encap));
	set_policy_prio(c); /* for updates */
	bool swap = false;
	for (const struct iface_endpoint *ifp = interfaces; ifp != NULL; ifp = ifp->next) {

		/* XXX: check connection allows p->protocol? */
		bool this = end_matches_iface_endpoint(&c->spd.this, &c->spd.that, ifp);
		bool that = end_matches_iface_endpoint(&c->spd.that, &c->spd.this, ifp);

		if (this && that) {
			/* too many choices */
			connection_buf cib;
			log_global(RC_LOG_SERIOUS, whackfd,
				   "both sides of "PRI_CONNECTION" are our interface %s!",
				   pri_connection(c, &cib),
				   ifp->ip_dev->id_rname);
			terminate_connection(c->name, false, whackfd);
			c->interface = NULL; /* withdraw orientation */
			return false;
		}

		if (!this && !that) {
			endpoint_buf eb;
			dbg("  interface endpoint %s does not match %s(THIS) or %s(THAT)",
			    str_endpoint(&ifp->local_endpoint, &eb),
			    c->spd.this.leftright, c->spd.that.leftright);
			continue;
		}
		pexpect(this != that); /* only one */

		if (oriented(*c)) {
			/* oops, second match */
			if (c->interface->ip_dev == ifp->ip_dev) {
				connection_buf cib;
				log_global(RC_LOG_SERIOUS, whackfd,
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
				log_global(RC_LOG_SERIOUS, whackfd,
					   "two interfaces match \"%s\"%s (%s %s, %s %s)",
					   pri_connection(c, &cib),
					   c->interface->ip_dev->id_rname,
					   str_address(&c->interface->ip_dev->id_address, &cb),
					   ifp->ip_dev->id_rname,
					   str_address(&ifp->ip_dev->id_address, &ifpb));
			}
			terminate_connection(c->name, false, whackfd);
			c->interface = NULL; /* withdraw orientation */
			return false;
		}

		/* orient then continue search */
		passert(this != that); /* only one */
		if (this) {
			endpoint_buf eb;
			dbg("  interface endpoint %s matches %s(THIS); orienting",
			    str_endpoint(&ifp->local_endpoint, &eb),
			    c->spd.this.leftright);
			swap = false;
		}
		if (that) {
			endpoint_buf eb;
			dbg("  interface endpoint %s matches %s(THAT); orienting and swapping",
			    str_endpoint(&ifp->local_endpoint, &eb),
			    c->spd.that.leftright);
			swap = true;
		}
		c->interface = ifp;
		passert(oriented(*c));
	}
	if (oriented(*c)) {
		if (swap) {
			dbg("  swapping ends so that %s(THAT) is oriented as (THIS)",
			    c->spd.that.leftright);
			swap_ends(c);
		}
		return true;
	}

	/* No existing interface worked, should a new one be created? */

	if (orient_new_iface_endpoint(c, whackfd, true)) {
		return true;
	}
	if (orient_new_iface_endpoint(c, whackfd, false)) {
		return true;
	}
	return false;
}
