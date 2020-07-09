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

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "secrets.h"

#include "defs.h"
#include "connections.h"        /* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "keys.h"
#include "whack.h"
#include "spdb.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "nat_traversal.h"
#include "ip_address.h"
#include "initiate.h"
#include "virtual.h"	/* needs connections.h */
#include "iface.h"
#include "hostpair.h"

/*
 * swap ends and try again.
 * It is a little tricky to see that this loop will stop.
 * Only continue if the far side matches.
 * If both sides match, there is an error-out.
 */
static void swap_ends(struct connection *c)
{
	struct spd_route *sr = &c->spd;
	struct end t = sr->this;

	sr->this = sr->that;
	sr->that = t;

	/*
	 * in case of asymmetric auth c->policy contains left.authby
	 * This magic will help responder to find connction during INIT
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
}

static bool orient_new_iface_port(struct connection *c, struct fd *whackfd, bool this)
{
	struct end *end = (this ? &c->spd.this : &c->spd.that);
	if (end->raw.host.ikeport == 0) {
		return false;
	}
	if (!address_is_set(&end->host_addr)) {
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
	 */
	struct iface_port *ifp = bind_iface_port(dev, &udp_iface_io,
						 ip_hport(end->raw.host.ikeport),
						 true/*esp_encapsulation_enabled*/,
						 false/*float_nat_initiator*/);
	if (ifp == NULL) {
		dbg("could not create new interface");
		return false;
	}
	endpoint_buf b;
	log_global(RC_LOG, whackfd, "adding interface %s %s",
		   ifp->ip_dev->id_rname,
		   str_endpoint(&ifp->local_endpoint, &b));
	c->interface = ifp;
	if (!this) {
		dbg("swapping to that; new interface");
		swap_ends(c);
	}
	if (listening) {
		struct logger logger = CONNECTION_LOGGER(c, whackfd);
		listen_on_iface_port(ifp, &logger);
	}
	return true;
}

static bool end_matches_port(const struct end *end, const struct end *other,
			     const struct iface_port *ifp)
{
	/*
	 * XXX: something stomps on .host_addr turning it into an
	 * endpoint - .ipproto gets set; hack around it
	 */
	ip_address host_addr = strip_endpoint(&end->host_addr, HERE);
	/*
	 * First choice is the IKEPORT.  Second choice, when the other
	 * end is using IKEPORT, is to use the PLUTO_NAT_PORT -
	 * IKEPORT assumes esp encapsulation which means sending the
	 * ESP=0 prefix and that doesn't work with PLUTO_PORT.
	 */
	ip_port port = ip_hport(end->raw.host.ikeport ? end->raw.host.ikeport :
				other->raw.host.ikeport ? NAT_IKE_UDP_PORT :
				IKE_UDP_PORT);
	ip_endpoint host_end = endpoint3(ifp->protocol, &host_addr, port);
	return endpoint_eq(host_end, ifp->local_endpoint);
}

bool orient(struct connection *c)
{
	struct fd *whackfd = whack_log_fd; /* placeholder */
	if (oriented(*c)) {
		dbg("already oriented");
		return true;
	}

	dbg("orienting %s", c->name);
	bool swap = false;
	for (const struct iface_port *ifp = interfaces; ifp != NULL; ifp = ifp->next) {

		/* XXX: check connection allows p->protocol? */
		bool this = end_matches_port(&c->spd.this, &c->spd.that, ifp);
		bool that = end_matches_port(&c->spd.that, &c->spd.this, ifp);

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
			dbg("%s doesn't match %s at all",
			    c->name, str_endpoint(&ifp->local_endpoint, &eb));
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
				 * line doesn't differnetiate.
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
		if (this) {
			dbg("oriented %s's this", c->name);
			swap = false;
		} else if (that) {
			dbg("oriented %s's that", c->name);
			swap = true;
		}
		c->interface = ifp;
		passert(oriented(*c));
	}
	if (oriented(*c)) {
		if (swap) {
			dbg("swapping ends so that that is this")
			swap_ends(c);
		}
		return true;
	}

	/*
	 * No existing interface worked, should a new one be created?
	 */
	if (orient_new_iface_port(c, whackfd, true)) {
		return true;
	}
	if (orient_new_iface_port(c, whackfd, false)) {
		return true;
	}
	return false;
}

struct initiate_stuff {
	bool background;
	const char *remote_host;
};

bool initiate_connection(struct connection *c, const char *remote_host,
			 struct fd *whackfd, bool background)
{
	threadtime_t inception  = threadtime_start();
	struct connection *old = push_cur_connection(c);

	/* If whack supplied a remote IP, fill it in if we can */
	if (remote_host != NULL && isanyaddr(&c->spd.that.host_addr)) {
		ip_address remote_ip;

		ttoaddr_num(remote_host, 0, AF_UNSPEC, &remote_ip);

		if (c->kind != CK_TEMPLATE) {
			log_connection(RC_NOPEERIP, whackfd, c,
				       "cannot instantiate non-template connection to a supplied remote IP address");
			pop_cur_connection(old);
			return 0;
		}

		struct connection *d = instantiate(c, &remote_ip, NULL);
		connection_buf cb;
		/*
		 * XXX: why not write to the log file?
		 */
		log_connection(RC_LOG|WHACK_STREAM, whackfd, c,
			       "instantiated connection "PRI_CONNECTION" with remote IP set to %s",
			       pri_connection(d, &cb), remote_host);
		/* flip cur_connection */
		c = d;
		pop_cur_connection(old);
		old = push_cur_connection(c);
		/* now proceed as normal */
	}

	if (!oriented(*c)) {
		ipstr_buf a;
		ipstr_buf b;
		log_connection(RC_ORIENT, whackfd, c,
			       "we cannot identify ourselves with either end of this connection.  %s or %s are not usable",
			       ipstr(&c->spd.this.host_addr, &a),
			       ipstr(&c->spd.that.host_addr, &b));
		pop_cur_connection(old);
		return 0;
	}

	if (NEVER_NEGOTIATE(c->policy)) {
		log_connection(RC_INITSHUNT, whackfd, c,
			       "cannot initiate an authby=never connection");
		pop_cur_connection(old);
		return 0;
	}

	if ((remote_host == NULL) && (c->kind != CK_PERMANENT) && !(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
		if (isanyaddr(&c->spd.that.host_addr)) {
			if (c->dnshostname != NULL) {
				log_connection(RC_NOPEERIP, whackfd, c,
					       "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s)",
					       enum_show(&connection_kind_names,
							 c->kind));
				dbg("connection '%s' +POLICY_UP", c->name);
				c->policy |= POLICY_UP;
				reset_cur_connection();
				return 1;
			} else {
				log_connection(RC_NOPEERIP, whackfd, c,
					       "cannot initiate connection without knowing peer IP address (kind=%s)",
					       enum_show(&connection_kind_names, c->kind));
			}
			pop_cur_connection(old);
			return 0;
		}

		if (!(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			log_connection(RC_WILDCARD, whackfd, c,
				       "cannot initiate connection with narrowing=no and (kind=%s)",
				       enum_show(&connection_kind_names, c->kind));
		} else {
			log_connection(RC_WILDCARD, whackfd, c,
				       "cannot initiate connection with ID wildcards (kind=%s)",
				       enum_show(&connection_kind_names, c->kind));
		}
		pop_cur_connection(old);
		return 0;
	}

	if (isanyaddr(&c->spd.that.host_addr) && (c->policy & POLICY_IKEV2_ALLOW_NARROWING) ) {
		if (c->dnshostname != NULL) {
			log_connection(RC_NOPEERIP, whackfd, c,
				       "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s, narrowing=%s)",
				       enum_show(&connection_kind_names, c->kind),
				       bool_str((c->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY));
			dbg("connection '%s' +POLICY_UP", c->name);
			c->policy |= POLICY_UP;
			pop_cur_connection(old);
			return 1;
		} else {
			log_connection(RC_NOPEERIP, whackfd, c,
				       "cannot initiate connection without knowing peer IP address (kind=%s narrowing=%s)",
				       enum_show(&connection_kind_names,
						 c->kind),
				       bool_str((c->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY));
			pop_cur_connection(old);
			return 0;
		}
	}

	if (LIN(POLICY_IKEV2_ALLOW | POLICY_IKEV2_ALLOW_NARROWING, c->policy) &&
	    c->kind == CK_TEMPLATE) {
		struct connection *d = instantiate(c, NULL, NULL);
#if 0
		/*
		 * LOGGING: why not log this (other than it messes
		 * with test output)?
		 */
		connection_buf cb;
		log_connection(RC_LOG, whackfd, c,
			       "instantiated connection "PRI_CONNECTION"",
			       pri_connection(d, &cb));
#endif
		/* flip cur_connection */
		c = d;
		pop_cur_connection(old);
		old = push_cur_connection(c);
	}

	/* We will only request an IPsec SA if policy isn't empty
	 * (ignoring Main Mode items).
	 * This is a fudge, but not yet important.
	 *
	 * XXX:  Is this still useful?
	 *
	 * In theory, by delaying the the kernel algorithm probe until
	 * here when the connection is being initiated, it is possible
	 * to detect kernel algorithms that have been loaded after
	 * pluto has started or are only loaded on-demand.
	 *
	 * In reality, the kernel algorithm DB is "static": PFKEY is
	 * only probed during startup(?); and XFRM, even if it does
	 * support probing, is using static entries.  See
	 * kernel_alg.c.
	 *
	 * Consequently:
	 *
	 * - when the connection's proposal suite is specified, the
	 * algorithm parser will check the algorithms against the
	 * kernel algorithm DB, so calling kernel_alg_makedb() to to
	 * perform an identical check is redundant
	 *
	 * - when default proposals are used (CHILD_PROPOSALS.P==NULL)
	 * (the parser can't see these) kernel_alg_makedb(NULL)
	 * returns a static table and skips all checks
	 *
	 * - finally, kernel_alg_makedb() is IKEv1 only
	 *
	 * A better fix would be to feed the proposal parser the
	 * default proposal suite.
	 *
	 * For moment leave call but make it IKEv1 only - for IKEv2
	 * all it does is give spdb.c some busy work (and log bogus
	 * stats).
	 *
	 * XXX: mumble something about c->ike_version
	 */
	if ((c->policy & POLICY_IKEV1_ALLOW) &&
	    (c->policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE))) {
		struct db_sa *phase2_sa =
			kernel_alg_makedb(c->policy, c->child_proposals, TRUE);
		if (c->child_proposals.p != NULL && phase2_sa == NULL) {
			log_connection(WHACK_STREAM | RC_LOG_SERIOUS, whackfd, c,
				       "cannot initiate: no acceptable kernel algorithms loaded");
			pop_cur_connection(old);
			return 0;
		}
		free_sa(&phase2_sa);
	}

	dbg("connection '%s' +POLICY_UP", c->name);
	c->policy |= POLICY_UP;
	ipsecdoi_initiate(background ? null_fd : whackfd,
			  c, c->policy, 1, SOS_NOBODY, &inception, NULL);
	pop_cur_connection(old);
	return 1;
}

static int initiate_a_connection(struct connection *c, struct fd *whackfd, void *arg)
{
	const struct initiate_stuff *is = arg;
	return initiate_connection(c, is->remote_host,
				   whackfd, is->background) ? 1 : 0;
}

void initiate_connections_by_name(const char *name, const char *remote_host,
				  struct fd *whackfd, bool background)
{
	passert(name != NULL);

	struct connection *c = conn_by_name(name, false/*!strict*/);
	if (c != NULL) {
		if (!initiate_connection(c, remote_host, whackfd, background))
			loglog_global(RC_FATAL, whackfd,
				      "failed to initiate %s",
				      c->name);
		return;
	}

	loglog_global(RC_COMMENT, whackfd, "initiating all conns with alias='%s'", name);
	struct initiate_stuff is = {
		.background = background,
		.remote_host = remote_host,
	};
	int count = foreach_connection_by_alias(name, whackfd, initiate_a_connection, &is);

	if (count == 0) {
		loglog_global(RC_UNKNOWN_NAME, whackfd,
			      "no connection named \"%s\"", name);
	}
}

static bool same_host(const char *a_dnshostname, const ip_address *a_host_addr,
		const char *b_dnshostname, const ip_address *b_host_addr)
{
	/* should this be dnshostname and host_addr ?? */

	return a_dnshostname == NULL ?
		b_dnshostname == NULL && sameaddr(a_host_addr, b_host_addr) :
		b_dnshostname != NULL && streq(a_dnshostname, b_dnshostname);
}

static bool same_in_some_sense(const struct connection *a,
			const struct connection *b)
{
	return same_host(a->dnshostname, &a->spd.that.host_addr,
			b->dnshostname, &b->spd.that.host_addr);
}

void restart_connections_by_peer(struct connection *const c)
{
	struct fd *whackfd = whack_log_fd; /* placeholder */
	/*
	 * If c is a CK_INSTANCE, it will be removed by terminate_connection.
	 * Any parts of c we need after that must be copied first.
	 */

	struct host_pair *hp = c->host_pair;
	enum connection_kind c_kind  = c->kind;
	struct connection *hp_next = hp->connections->hp_next;

	pexpect(hp != NULL);	/* ??? why would this happen? */
	if (hp == NULL)
		return;

	char *dnshostname = clone_str(c->dnshostname, "dnshostname for restart");

	ip_address host_addr = c->spd.that.host_addr;

	struct connection *d;

	for (d = hp->connections; d != NULL;) {
		struct connection *next = d->hp_next; /* copy before d is deleted, CK_INSTANCE */

		if (same_host(dnshostname, &host_addr,
				d->dnshostname, &d->spd.that.host_addr))
		{
			/* This might delete c if CK_INSTANCE */
			/* ??? is there a chance hp becomes dangling? */
			terminate_connection(d->name, false, whackfd);
		}
		d = next;
	}

	if (c_kind != CK_INSTANCE) {
		/* reference to c is OK because not CK_INSTANCE */
		update_host_pairs(c);
		/* host_pair/host_addr changes with dynamic dns */
		hp = c->host_pair;
		host_addr = c->spd.that.host_addr;
	}

	if (c_kind == CK_INSTANCE && hp_next == NULL) {
		/* in simple cases this is  a dangling hp */
		dbg("no connection to restart after termination");
	} else {
		for (d = hp->connections; d != NULL; d = d->hp_next) {
			if (same_host(dnshostname, &host_addr,
					d->dnshostname, &d->spd.that.host_addr))
				initiate_connections_by_name(d->name, NULL,
							     null_fd, true/*background*/);
		}
	}
	pfreeany(dnshostname);
}

/* (Possibly) Opportunistic Initiation:
 * Knowing clients (single IP addresses), try to build a tunnel.
 * This may involve discovering a gateway and instantiating an
 * Opportunistic connection.  Called when a packet is caught by
 * a %trap, or when whack --oppohere --oppothere is used.
 * It may turn out that an existing or non-opporunistic connection
 * can handle the traffic.
 *
 * Most of the code will be restarted if an ADNS request is made
 * to discover the gateway.  The only difference between the first
 * and second entry is whether gateways_from_dns is NULL or not.
 *	initiate_opportunistic: initial entrypoint
 *	continue_oppo: where we pickup when ADNS result arrives
 *	initiate_opportunistic_body: main body shared by above routines
 *	cannot_oppo: a helper function to log a diagnostic
 * This structure repeats a lot of code when the ADNS result arrives.
 * This seems like a waste, but anything learned the first time through
 * may no longer be true!
 *
 * After the first IKE message is sent, the regular state machinery
 * carries negotiation forward.
 */

struct find_oppo_bundle {
	const char *want;
	bool failure_ok;        /* if true, continue_oppo should not die on DNS failure */
	ip_address our_client;  /* not pointer! */
	ip_address peer_client;
	int transport_proto;
	bool held;
	policy_prio_t policy_prio;
	ipsec_spi_t negotiation_shunt; /* in host order! */
	ipsec_spi_t failure_shunt; /* in host order! */
	struct fd *whackfd;
	bool background;
};

static void cannot_oppo(struct find_oppo_bundle *b, err_t ughmsg)
{
	address_buf ocb_buf;
	const char *ocb = ipstr(&b->our_client, &ocb_buf);
	address_buf pcb_buf;
	const char *pcb = ipstr(&b->peer_client, &pcb_buf);

	enum stream logger_stream = (DBGP(DBG_BASE) ? ALL_STREAMS : WHACK_STREAM);
	log_global(logger_stream | RC_OPPOFAILURE, b->whackfd,
		   "cannot opportunistically initiate for %s to %s: %s",
		   ocb, pcb, ughmsg);

	if (b->held) {
		/* this was filled in for us based on packet trigger, not whack --oppo trigger */
		dbg("cannot_oppo() detected packet triggered shunt from bundle");

		/*
		 * Replace negotiationshunt (hold or pass) with failureshunt (hold or pass)
		 * If no failure_shunt specified, use SPI_PASS -- THIS MAY CHANGE.
		 */
		pexpect(b->failure_shunt != 0); /* PAUL: I don't think this can/should happen? */
		if (replace_bare_shunt(&b->our_client, &b->peer_client,
					  b->policy_prio,
					  b->negotiation_shunt,
					  b->failure_shunt,
					  b->transport_proto,
					  ughmsg)) {
			dbg("cannot_oppo() replaced negotiationshunt with bare failureshunt=%s",
			    enum_short_name(&spi_names, b->failure_shunt));
		} else {
			log_global(RC_LOG, b->whackfd, "cannot_oppo() failed to replace negotiationshunt with bare failureshunt");
		}
	}
}

static void initiate_ondemand_body(struct find_oppo_bundle *b,
				   struct xfrm_user_sec_ctx_ike *uctx)
{
	threadtime_t inception = threadtime_start();

	/*
	 * XXX: this function gets called either with a real trigger
	 * (which includes ports) or with:
	 *
	 *    ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23
	 *
	 * which does not.  So output matches tests the string below
	 * forces addr:port and not end (latter strips of 0 port).
	 */
	ip_address our_address = endpoint_address(&b->our_client);
	ip_address peer_address = endpoint_address(&b->peer_client);

	int our_port = endpoint_hport(&b->our_client);
	int peer_port = endpoint_hport(&b->peer_client);

	address_buf ourb;
	const char *our_addr = str_address(&our_address, &ourb);
	address_buf peerb;
	const char *peer_addr = str_address(&peer_address, &peerb);

	if (uctx != NULL) {
		dbg("received security label string: %.*s",
		    uctx->ctx.ctx_len,
		    uctx->sec_ctx_value);
	}

	char demandbuf[256];
	snprintf(demandbuf, sizeof(demandbuf),
		 "initiate on demand from %s:%d to %s:%d proto=%d because: %s",
		 our_addr, our_port, peer_addr, peer_port,
		 b->transport_proto, b->want);

	/* ??? DBG and real-world code mixed */
	bool loggedit = false;
	if (DBGP(DBG_BASE)) {
		libreswan_log("%s", demandbuf);
		loggedit = true;
	} else if (fd_p(b->whackfd)) {
		whack_log(RC_COMMENT, b->whackfd, "%s", demandbuf);
		loggedit = true;
	}

	/* What connection shall we use?
	 * First try for one that explicitly handles the clients.
	 */

	if (isanyaddr(&b->our_client) || isanyaddr(&b->peer_client)) {
		cannot_oppo(b, "impossible IP address");
		return;
	}

	if (sameaddr(&b->our_client, &b->peer_client)) {
		/* NETKEY gives us acquires for our own IP */
		/* this does not catch talking to ourselves on another ip */
		cannot_oppo(b, "acquire for our own IP address");
		return;
	}

	struct spd_route *sr;
	struct connection *c = find_connection_for_clients(&sr,
							   &b->our_client,
							   &b->peer_client,
							   b->transport_proto);
	if (c == NULL) {
		/* No connection explicitly handles the clients and there
		 * are no Opportunistic connections -- whine and give up.
		 * The failure policy cannot be gotten from a connection; we pick %pass.
		 */
		if (!loggedit) {
			log_global(RC_LOG, b->whackfd, "%s", demandbuf);
		}
		cannot_oppo(b, "no routed template covers this pair");
		return;
	}

	if ((c->policy & POLICY_OPPORTUNISTIC) && !orient(c)) {
		/* happens when dst is ourselves on a different IP */
		cannot_oppo(b, "connection to self on another IP?");
		return;
	}

	if (c->kind == CK_TEMPLATE && (c->policy & POLICY_OPPORTUNISTIC) == 0) {
		if (!loggedit) {
			log_global(RC_LOG, b->whackfd, "%s", demandbuf);
		}
		log_global(RC_NOPEERIP, b->whackfd,
			   "cannot initiate connection for packet %s:%d -> %s:%d proto=%d - template conn",
			   our_addr, our_port, peer_addr, peer_port,
			   b->transport_proto);
		return;
	}

	if (c->kind == CK_INSTANCE) {
		connection_buf cib;
		/* there is already an instance being negotiated */
#if 0
		log_global(RC_LOG, b->whackfd,
			   "rekeying existing instance "PRI_CONNECTION", due to acquire",
			   pri_connection(c, &cib));

		/*
		 * we used to return here, but rekeying is a better choice. If we
		 * got the acquire, it is because something turned stuff into a
		 * %trap, or something got deleted, perhaps due to an expiry.
		 */
#else
		/*
		 * XXX We got an acquire (NETKEY only?) for
		 * something we already have an instance for ??
		 * We cannot process as normal because the
		 * bare_shunts table and assign_holdpass()
		 * would get confused between this new entry
		 * and the existing one. So we return without
		 * doing anything
		 */
		log_global(RC_LOG, b->whackfd,
			   "ignoring found existing connection instance "PRI_CONNECTION" that covers kernel acquire with IKE state #%lu and IPsec state #%lu - due to duplicate acquire?",
			   pri_connection(c, &cib),
			   c->newest_isakmp_sa, c->newest_ipsec_sa);
		return;
#endif
	}

	if (c->kind != CK_TEMPLATE) {
		/* We've found a connection that can serve.
		 * Do we have to initiate it?
		 * Not if there is currently an IPSEC SA.
		 * This may be redundant if a non-opportunistic
		 * negotiation is already being attempted.
		 */

		/* If we are to proceed asynchronously, b->whackfd will be NULL_WHACKFD. */

		/* we have a connection, fill in the negotiation_shunt and failure_shunt */
		b->failure_shunt = shunt_policy_spi(c, FALSE);
		b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;

		/*
		 * otherwise, there is some kind of static conn that can handle
		 * this connection, so we initiate it.
		 * Only needed if we this was triggered by a packet, not by whack
		 */
		if (b->held) {
			if (assign_holdpass(c, sr, b->transport_proto, b->negotiation_shunt,
					   &b->our_client, &b->peer_client)) {
				dbg("initiate_ondemand_body() installed negotiation_shunt,");
			} else {
				log_global(RC_LOG, b->whackfd,
					   "initiate_ondemand_body() failed to install negotiation_shunt,");
			}
		}

		if (!loggedit) {
			log_global(RC_LOG, b->whackfd, "%s", demandbuf);
		}

		ipsecdoi_initiate(b->background ? null_fd : b->whackfd,
				  c, c->policy, 1,
				  SOS_NOBODY, &inception, uctx);
		address_buf b1;
		address_buf b2;
		dbg("initiate on demand using %s from %s to %s",
		    (c->policy & POLICY_AUTH_NULL) ? "AUTH_NULL" : "RSASIG",
		    str_address(&b->our_client, &b1),
		    str_address(&b->peer_client, &b2));
		return;
	}

	/* We are handling an opportunistic situation.
	 * This involves several DNS lookup steps that require suspension.
	 * NOTE: will be re-implemented
	 *
	 * old comment:
	 * The first chunk of code handles the result of the previous
	 * DNS query (if any).  It also selects the kind of the next step.
	 * The second chunk initiates the next DNS query (if any).
	 */

	connection_buf cib;
	dbg("creating new instance from "PRI_CONNECTION, pri_connection(c, &cib));

	if (sr->routing == RT_ROUTED_PROSPECTIVE && eclipsable(sr)) {
		dbg("route is eclipsed");
		sr->routing = RT_ROUTED_ECLIPSED;
		eclipse_count++;
	}

	pexpect(c->kind == CK_TEMPLATE);
	passert(c->policy & POLICY_OPPORTUNISTIC); /* can't initiate Road Warrior connections */

	/* we have a connection, fill in the negotiation_shunt and failure_shunt */
	b->failure_shunt = shunt_policy_spi(c, FALSE);
	b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;

	/*
	 * XFRM always has shunts with protoports, even when no *protoport= settings in conn
	 */
	if (b->negotiation_shunt != SPI_HOLD ||
	    (b->transport_proto != 0 ||
	     our_port != 0 ||
	     peer_port != 0)) {
		const char *const delmsg = "delete bare kernel shunt - was replaced with  negotiationshunt";
		const char *const addwidemsg = "oe-negotiating";
		ip_subnet this_client, that_client;
		int shunt_proto = b->transport_proto;

		happy(endtosubnet(&b->our_client, &this_client, HERE));
		happy(endtosubnet(&b->peer_client, &that_client, HERE));
		/* OLD: negotiationshunt must be wider than bare shunt, esp on NETKEY */
		/* if the connection we found has protoports, match those for the shunt */

		setportof(0, &this_client.addr); /* always catch all ephemeral to dest */
		setportof(0, &that_client.addr); /* default unless connection says otherwise */
		if (b->transport_proto != 0) {
			if (c->spd.that.protocol == 0) {
				dbg("shunt widened for protoports since conn does not limit protocols");
				shunt_proto = 0;
				our_port = 0;
				peer_port = 0;
			} else {
				if (peer_port != 0) {
					if (c->spd.that.port != 0) {
						if (c->spd.that.port != peer_port) {
							log_global(RC_LOG_SERIOUS, b->whackfd,
								   "Dragons! connection port %d mismatches shunt dest port %d",
								   c->spd.that.port, peer_port);
						} else {
							update_selector_hport(&that_client, peer_port);
							dbg("bare shunt destination port set to %d", peer_port);
						}
					} else {
						dbg("not really expecting a shunt for dport 0 ?");
					}
				}
			}
		} else {
			dbg("shunt not widened for oppo because no protoport received from the kernel for the shunt");
		}

		dbg("going to initiate opportunistic, first installing %s negotiationshunt",
		    enum_short_name(&spi_names, b->negotiation_shunt));

		// PAUL: should this use shunt_eroute() instead of API violation into raw_eroute()
		/* if we have protoport= set, narrow to it. zero out ephemeral port */
		if (shunt_proto != 0) {
			if (c->spd.this.port != 0)
				setportof(portof(&b->our_client), &this_client.addr);
			if (c->spd.that.port != 0)
				setportof(portof(&b->peer_client), &that_client.addr);
		}

		if (!raw_eroute(&b->our_client, &this_client,
				&b->peer_client, &that_client,
				htonl(SPI_HOLD), /* kernel induced */
				htonl(b->negotiation_shunt),
				&ip_protocol_internal, shunt_proto,
				ET_INT, null_proto_info,
				deltatime(SHUNT_PATIENCE),
				calculate_sa_prio(c, LIN(POLICY_OPPORTUNISTIC, c->policy) ? TRUE : FALSE),
				NULL, 0 /* xfrm-if-id */,
				ERO_ADD, addwidemsg,
				NULL)) {
			log_global(RC_LOG, b->whackfd, "adding bare wide passthrough negotiationshunt failed");
		} else {
			dbg("added bare (possibly wided) passthrough negotiationshunt succeeded (violating API)");
			add_bare_shunt(&this_client, &that_client, shunt_proto, SPI_HOLD, addwidemsg);
		}
		/* now delete the (obsoleted) narrow bare kernel shunt - we have a (possibly broadened) negotiationshunt replacement installed */
		if (!delete_bare_shunt(&b->our_client, &b->peer_client,
				       b->transport_proto,
				       SPI_HOLD /* kernel dictated */, delmsg)) {
			log_global(RC_LOG, b->whackfd, "Failed to: %s", delmsg);
		} else {
			dbg("success taking down narrow bare shunt");
		}
	}

	/* XXX: re-use C */
	c = build_outgoing_opportunistic_connection(&b->our_client,
						    &b->peer_client,
						    b->transport_proto);
	if (c == NULL) {
		/* We cannot seem to instantiate a suitable connection:
		 * complain clearly.
		 */
		ipstr_buf b1, b2;

		/* ??? CLANG 3.5 thinks ac might be NULL (look up) */
		log_global(RC_OPPOFAILURE, b->whackfd,
			   "no suitable connection for opportunism between %s and %s",
			   ipstr(&b->our_client, &b1),
			   ipstr(&b->peer_client, &b2));

		/*
		 * Replace negotiation_shunt with failure_shunt
		 * The type of replacement *ought* to be
		 * specified by policy, but we did not find a connection, so
		 * default to HOLD
		 */
		if (b->held) {
			if (replace_bare_shunt(&b->our_client,
					       &b->peer_client,
					       b->policy_prio,
					       b->negotiation_shunt, /* if not from conn, where did this come from? */
					       b->failure_shunt, /* if not from conn, where did this come from? */
					       b->transport_proto,
					       "no suitable connection")) {
				dbg("replaced negotiationshunt with failurehunt=hold because no connection was found");
			} else {
				log_global(RC_LOG, b->whackfd,
					   "failed to replace negotiationshunt with failurehunt=hold");
			}
		}
		return;
	}

	/* If we are to proceed asynchronously, b->background will be true. */
	passert(c->kind == CK_INSTANCE);
	passert(HAS_IPSEC_POLICY(c->policy));
	passert(LHAS(LELEM(RT_UNROUTED) |
		     LELEM(RT_ROUTED_PROSPECTIVE),
		     c->spd.routing));
	if (b->held) {
		/* if we have protoport= set, narrow to it. zero out ephemeral port */
		if (b->transport_proto != 0) {
			if (c->spd.this.port != 0) {
				setportof(htons(c->spd.this.port), &b->our_client);
			}
			if (c->spd.that.port != 0) {
				setportof(htons(c->spd.that.port), &b->peer_client);
			}
		}
		/* packet triggered - not whack triggered */
		dbg("assigning negotiation_shunt to connection");
		/* if we have protoport= set, narrow to it. zero out ephemeral port */
		/* warning: we know ports in this_client/that_client are 0 so far */
		if (c->spd.this.protocol != 0) {
			if (c->spd.this.port != 0)
				setportof(portof(&b->our_client), &c->spd.this.client.addr);
			if (c->spd.that.port != 0)
				setportof(portof(&b->peer_client), &c->spd.that.client.addr);
		}
		if (assign_holdpass(c, &c->spd,
				    b->transport_proto,
				    b->negotiation_shunt,
				    &b->our_client,
				    &b->peer_client)) {
			dbg("assign_holdpass succeeded");
		} else {
			log_global(RC_LOG, b->whackfd, "assign_holdpass failed!");
		}
	}

	dbg("initiate on demand from %s:%d to %s:%d using %s proto=%d because: %s",
	    our_addr, our_port, peer_addr, peer_port,
	    (c->policy & POLICY_AUTH_NULL) ? "AUTH_NULL" : "RSASIG",
	    b->transport_proto,
	    b->want);

	ipsecdoi_initiate(b->background ? null_fd : b->whackfd,
			  c, c->policy, 1,
			  SOS_NOBODY, &inception
			  , NULL /* shall we pass uctx for opportunistic connections? */
		);
}

void initiate_ondemand(const ip_address *our_client,
		       const ip_address *peer_client,
		       int transport_proto,
		       bool held,
		       struct fd *whackfd, bool background,
		       struct xfrm_user_sec_ctx_ike *uctx,
		       const char *why)
{
	struct find_oppo_bundle b = {
		.want = why,   /* fudge */
		.failure_ok = false,
		.our_client = *our_client,
		.peer_client = *peer_client,
		.transport_proto = transport_proto,
		.held = held,
		.policy_prio = BOTTOM_PRIO,
		.negotiation_shunt = SPI_HOLD, /* until we found connection policy */
		.failure_shunt = SPI_HOLD, /* until we found connection policy */
		.whackfd = whackfd, /*on-stack*/
		.background = background,
	};

	initiate_ondemand_body(&b, uctx);
}

/* Find a connection that owns the shunt eroute between subnets.
 * There ought to be only one.
 * This might get to be a bottleneck -- try hashing if it does.
 */
struct connection *shunt_owner(const ip_subnet *ours, const ip_subnet *peers)
{
	struct connection *c;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = c->ac_next) {
		const struct spd_route *sr;

		for (sr = &c->spd; sr; sr = sr->spd_next) {
			if (shunt_erouted(sr->routing) &&
			    samesubnet(ours, &sr->this.client) &&
			    samesubnet(peers, &sr->that.client))
				return c;
		}
	}
	return NULL;
}


/* time before retrying DDNS host lookup for phase 1 */
#define PENDING_DDNS_INTERVAL secs_per_minute

/*
 * Call me periodically to check to see if any DDNS tunnel can come up.
 * The order matters, we try to do the cheapest checks first.
 */

static void connection_check_ddns1(struct connection *c)
{
	struct connection *d;
	ip_address new_addr;
	const char *e;

	/* this is the cheapest check, so do it first */
	if (c->dnshostname == NULL)
		return;

	/* should we let the caller get away with this? */
	if (NEVER_NEGOTIATE(c->policy))
		return;

	/*
	 * We do not update a resolved address once resolved. That might
	 * be considered a bug. Can we count on liveness if the target
	 * changed IP? The connection would * need to gets its host_addr
	 * updated? Do we do that when terminating the conn?
	 */
	if (endpoint_is_specified(&c->spd.that.host_addr)) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" has address",
		    pri_connection(c, &cib));
		return;
	}

	if (c->spd.that.has_port_wildcard ||
	    ((c->policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP &&
	     c->spd.that.has_id_wildcards)) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" with wildcard not started",
		    pri_connection(c, &cib));
		return;
	}

	e = ttoaddr(c->dnshostname, 0, AF_UNSPEC, &new_addr);
	if (e != NULL) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" lookup of \"%s\" failed: %s",
		    pri_connection(c, &cib), c->dnshostname, e);
		return;
	}

	if (isanyaddr(&new_addr)) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" still no address for \"%s\"",
		    pri_connection(c, &cib), c->dnshostname);
		return;
	}

	/* do not touch what is not broken */
	if ((c->newest_isakmp_sa != SOS_NOBODY) &&
	    IS_IKE_SA_ESTABLISHED(state_with_serialno(c->newest_isakmp_sa))) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" is established",
		    pri_connection(c, &cib));
		return;
	}

	/* This cannot currently be reached. If in the future we do, don't do weird things */
	if (sameaddr(&new_addr, &c->spd.that.host_addr)) {
		connection_buf cib;
		dbg("pending ddns: IP address unchanged for connection "PRI_CONNECTION"",
		    pri_connection(c, &cib));
		return;
	}

	ipstr_buf old,new;
	/* I think this is ok now we check everything above ? */

	/*
	 * It seems DNS failure puts a connection into CK_TEMPLATE, so once the
	 * resolve is fixed, it is manually placed in CK_PERMANENT here.
	 * However, that is questionable, eg for connections that are templates
	 * to begin with, such as those with narrowing=yes. These will mistakenly
	 * be placed into CK_PERMANENT.
	 */

	connection_buf cib;
	dbg("pending ddns: changing connection "PRI_CONNECTION" to CK_PERMANENT",
	    pri_connection(c, &cib));
	c->kind = CK_PERMANENT;

	dbg("pending ddns: updating IP address for %s from %s to %s",
	    c->dnshostname, sensitive_ipstr(&c->spd.that.host_addr, &old),
	    sensitive_ipstr(&new_addr, &new));
	c->spd.that.host_addr = new_addr;

	/* a small bit of code from default_end to fixup the end point */
	/* default nexthop to other side */
	if (isanyaddr(&c->spd.this.host_nexthop))
		c->spd.this.host_nexthop = c->spd.that.host_addr;

	/* default client to subnet containing only self */
	if (!c->spd.that.has_client) {
		/* XXX: this uses ADDRESS:PORT */
		endtosubnet(&c->spd.that.host_addr, &c->spd.that.client, HERE);
	}

	/*
	 * reduce the work we do by updating all connections waiting for this
	 * lookup
	 */
	update_host_pairs(c);
	if (c->policy & POLICY_UP) {
		connection_buf cib;
		dbg("pending ddns: re-initiating connection "PRI_CONNECTION"",
		    pri_connection(c, &cib));
		initiate_connections_by_name(c->name, NULL, null_fd, true/*background*/);
	} else {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" was updated, but does not want to be up",
		    pri_connection(c, &cib));
	}

	/* no host pairs, no more to do */
	pexpect(c->host_pair != NULL);	/* ??? surely */
	if (c->host_pair == NULL)
		return;

	for (d = c->host_pair->connections; d != NULL; d = d->hp_next) {
		if (c != d && same_in_some_sense(c, d) && (d->policy & POLICY_UP)) {
			initiate_connections_by_name(d->name, NULL,
						     null_fd, true/*background*/);
		}
	}
}

void connection_check_ddns(struct fd *unused_whackfd UNUSED)
{
	struct connection *c, *cnext;
	threadtime_t start = threadtime_start();

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = cnext) {
		cnext = c->ac_next;
		connection_check_ddns1(c);
	}
	check_orientations();

	threadtime_stop(&start, SOS_NOBODY, "in %s for hostname lookup", __func__);
}

/* time between scans of pending phase2 */
#define PENDING_PHASE2_INTERVAL (2 * secs_per_minute)

/*
 * call me periodically to check to see if pending phase2s ever got
 * unstuck, and if not, perform DPD action.
 */
void connection_check_phase2(struct fd *whackfd)
{
	struct connection *c, *cnext;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = cnext) {
		cnext = c->ac_next;

		if (NEVER_NEGOTIATE(c->policy)) {
			connection_buf cib;
			dbg("pending review: connection "PRI_CONNECTION" has no negotiated policy, skipped",
			    pri_connection(c, &cib));
			continue;
		}

		if (!(c->policy & POLICY_UP)) {
			connection_buf cib;
			dbg("pending review: connection "PRI_CONNECTION" was not up, skipped",
			    pri_connection(c, &cib));
			continue;
		}

		connection_buf cib;
		dbg("pending review: connection "PRI_CONNECTION" checked",
		    pri_connection(c, &cib));

		if (pending_check_timeout(c)) {
			struct state *p1st;
			ipstr_buf b;
			char cib[CONN_INST_BUF];

			libreswan_log(
				"pending IPsec SA negotiation with %s \"%s\"%s took too long -- replacing phase 1",
				ipstr(&c->spd.that.host_addr, &b),
				c->name, fmt_conn_instance(c, cib));

			p1st = find_phase1_state(c,
						 ISAKMP_SA_ESTABLISHED_STATES |
						 IKEV2_ISAKMP_INITIATOR_STATES |
						 PHASE1_INITIATOR_STATES);

			if (p1st != NULL) {
				/* arrange to rekey the phase 1, if there was one. */
				if (c->dnshostname != NULL) {
					restart_connections_by_peer(c);
				} else {
					event_force(EVENT_SA_REPLACE, p1st);
				}
			} else {
				/* start a new connection. Something wanted it up */
				struct initiate_stuff is = {
					.remote_host = NULL,
				};
				initiate_a_connection(c, whackfd, &is);
			}
		}
	}
}

void init_connections(void)
{
	enable_periodic_timer(EVENT_PENDING_DDNS, connection_check_ddns,
			      deltatime(PENDING_DDNS_INTERVAL));
	enable_periodic_timer(EVENT_PENDING_PHASE2, connection_check_phase2,
			      deltatime(PENDING_PHASE2_INTERVAL));
}
