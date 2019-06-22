/* information about connections between hosts
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
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

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "certs.h"

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
#include "af_info.h"

#include "virtual.h"	/* needs connections.h */

#include "hostpair.h"

/* struct host_pair: a nexus of information about a pair of hosts.
 * A host is an IP address, UDP port pair.  This is a debatable choice:
 * - should port be considered (no choice of port in standard)?
 * - should ID be considered (hard because not always known)?
 * - should IP address matter on our end (we don't know our end)?
 * Only oriented connections are registered.
 * Unoriented connections are kept on the unoriented_connections
 * linked list (using hp_next).  For them, host_pair is NULL.
 */

static struct host_pair *host_pairs = NULL;
static struct connection *unoriented_connections = NULL;

void host_pair_enqueue_pending(const struct connection *c,
			       struct pending *p,
			       struct pending **pnext)
{
	*pnext = c->host_pair->pending;
	c->host_pair->pending = p;
}

struct pending **host_pair_first_pending(const struct connection *c)
{
	if (c->host_pair == NULL)
		return NULL;

	return &c->host_pair->pending;
}

/* check to see that Ids of peers match */
bool same_peer_ids(const struct connection *c, const struct connection *d,
		   const struct id *his_id)
{
	return same_id(&c->spd.this.id, &d->spd.this.id) &&
	       same_id(his_id == NULL ? &c->spd.that.id : his_id,
		       &d->spd.that.id);
}

/** returns a host pair based upon addresses.
 *
 * find_host_pair is given a pair of addresses, plus UDP ports, and
 * returns a host_pair entry that covers it. It also moves the relevant
 * pair description to the beginning of the list, so that it can be
 * found faster next time.
 */
struct host_pair *find_host_pair(const ip_endpoint *local,
				 const ip_endpoint *remote)
{
	struct host_pair *p, *prev;

	/* default hisaddr to an appropriate any */
	if (remote == NULL) {
		remote = aftoinfo(endpoint_type(local))->any;
	}

	/*
	 * look for a host-pair that has the right set of ports/address.
	 *
	 */

	for (prev = NULL, p = host_pairs; p != NULL; prev = p, p = p->next) {
		if (p->connections != NULL && (p->connections->kind == CK_INSTANCE) &&
			(p->connections->spd.that.id.kind == ID_NULL))
		{
			DBG(DBG_CONTROLMORE, {
				char ci[CONN_INST_BUF];
				DBG_log("find_host_pair: ignore CK_INSTANCE with ID_NULL hp:\"%s\"%s",
					p->connections->name,
					fmt_conn_instance(p->connections, ci));
                       });
                       continue;
               }

		endpoint_buf b1;
		endpoint_buf b2;
		dbg("find_host_pair: comparing %s to %s but ignoring ports",
		    str_endpoint(&p->local, &b1),
		    str_endpoint(&p->remote, &b2));

		/* XXX: same addr does not compare ports.  */
		if (sameaddr(&p->local, local) &&
		    sameaddr(&p->remote, remote)) {
			if (prev != NULL) {
				prev->next = p->next;   /* remove p from list */
				p->next = host_pairs;   /* and stick it on front */
				host_pairs = p;
			}
			break;
		}
	}
	return p;
}

static void remove_host_pair(struct host_pair *hp)
{
	LIST_RM(next, hp, host_pairs, true/*expected*/);
}

/* find head of list of connections with this pair of hosts */
struct connection *find_host_pair_connections(const ip_address *myaddr,
					      const ip_address *hisaddr)
{
	struct host_pair *hp = find_host_pair(myaddr, hisaddr);

	/*
	DBG(DBG_CONTROLMORE, {
		ipstr_buf bm;
		ipstr_buf bh;
		char ci[CONN_INST_BUF];

		DBG_log("find_host_pair_conn: %s:%d %s:%d -> hp:%s%s",
			ipstr(myaddr, &bm), myport,
			hisaddr != NULL ? ipstr(hisaddr, &bh) : "%any",
			hisport,
			hp != NULL && hp->connections != NULL ?
				hp->connections->name : "none",
			hp != NULL && hp->connections != NULL ?
				fmt_conn_instance(hp->connections, ci) : "");
	    });
	    */

	return hp == NULL ? NULL : hp->connections;
}

void connect_to_host_pair(struct connection *c)
{
	if (oriented(*c)) {
		struct host_pair *hp = find_host_pair(&c->spd.this.host_addr,
						      &c->spd.that.host_addr);

		DBG(DBG_CONTROLMORE, {
			ipstr_buf b1;
			ipstr_buf b2;
			DBG_log("connect_to_host_pair: %s:%d %s:%d -> hp:%s",
				ipstr(&c->spd.this.host_addr, &b1),
				c->spd.this.host_port,
				ipstr(&c->spd.that.host_addr, &b2),
				c->spd.that.host_port,
				(hp != NULL && hp->connections) ?
					hp->connections->name : "none");
		});

		if (hp == NULL) {
			/* no suitable host_pair -- build one */
			hp = alloc_thing(struct host_pair, "host_pair");
			hp->local = endpoint(&c->spd.this.host_addr,
					     nat_traversal_enabled ?
					     pluto_port : c->spd.this.host_port);
			hp->remote = endpoint(&c->spd.that.host_addr,
					      nat_traversal_enabled ?
					      pluto_port : c->spd.that.host_port);
			hp->connections = NULL;
			hp->pending = NULL;
			hp->next = host_pairs;
			host_pairs = hp;
		}
		c->host_pair = hp;
		c->hp_next = hp->connections;
		hp->connections = c;
	} else {
		/* since this connection isn't oriented, we place it
		 * in the unoriented_connections list instead.
		 */
		c->host_pair = NULL;
		c->hp_next = unoriented_connections;
		unoriented_connections = c;
	}
}

void release_dead_interfaces(void)
{
	struct host_pair *hp;

	for (hp = host_pairs; hp != NULL; hp = hp->next) {
		struct connection **pp,
		*p;

		for (pp = &hp->connections; (p = *pp) != NULL; ) {
			if (p->interface->change == IFN_DELETE) {
				/* this connection's interface is going away */
				enum connection_kind k = p->kind;

				release_connection(p, TRUE);

				if (k <= CK_PERMANENT) {
					/* The connection should have survived release:
					 * move it to the unoriented_connections list.
					 */
					passert(p == *pp);

					terminate_connection(p->name, FALSE);
					p->interface = NULL; /* withdraw orientation */

					*pp = p->hp_next; /* advance *pp */
					p->host_pair = NULL;
					p->hp_next = unoriented_connections;
					unoriented_connections = p;
				} else {
					/* The connection should have vanished,
					 * but the previous connection remains.
					 */
					passert(p != *pp);
				}
			} else {
				pp = &p->hp_next; /* advance pp */
			}
		}
	}
}

void delete_oriented_hp(struct connection *c)
{
	struct host_pair *hp = c->host_pair;

	LIST_RM(hp_next, c, hp->connections, true/*expected*/);
	c->host_pair = NULL; /* redundant, but safe */

	/*
	 * if there are no more connections with this host_pair
	 * and we haven't even made an initial contact, let's delete
	 * this guy in case we were created by an attempted DOS attack.
	 */
	if (hp->connections == NULL) {
		/* ??? must deal with this! */
		passert(hp->pending == NULL);
		remove_host_pair(hp);
		pfree(hp);
	}
}

/* update the host pairs with the latest DNS ip address */
void update_host_pairs(struct connection *c)
{
	struct host_pair *const hp = c->host_pair;
	const char *dnshostname = c->dnshostname;

	/* ??? perhaps we should return early if dnshostname == NULL */

	if (hp == NULL)
		return;

	struct connection *d = hp->connections;

	/* ??? looks as if addr_family is not allowed to change.  Bug? */
	/* ??? why are we using d->dnshostname instead of (c->)dnshostname? */
	/* ??? code used to test for d == NULL, but that seems impossible. */

	pexpect(dnshostname == d->dnshostname || streq(dnshostname, d->dnshostname));

	ip_address new_addr;

	if (d->dnshostname == NULL ||
	    ttoaddr(d->dnshostname, 0, d->addr_family, &new_addr) != NULL ||
	    sameaddr(&new_addr, &hp->remote))
		return;

	struct connection *conn_list = NULL;

	while (d != NULL) {
		struct connection *nxt = d->hp_next;

		/*
		 * ??? this test used to assume that dnshostname != NULL
		 * if d->dnshostname != NULL.  Is that true?
		 */
		if (d->dnshostname != NULL && dnshostname != NULL &&
		    streq(d->dnshostname, dnshostname)) {
			/*
			 * If there is a dnshostname and it is the same as
			 * the one that has changed, then change
			 * the connection's remote host address and remove
			 * the connection from the host pair.
			 */

			/*
			 * Unroute the old connection before changing the ip
			 * address.
			 */
			unroute_connection(d);

			/*
			 * If the client is the peer, also update the
			 * client info
			 */
			if (!d->spd.that.has_client) {
				addrtosubnet(&new_addr, &d->spd.that.client);
			}

			d->spd.that.host_addr = new_addr;
			LIST_RM(hp_next, d, d->host_pair->connections, true);

			d->hp_next = conn_list;
			conn_list = d;
		}
		d = nxt;
	}

	while (conn_list != NULL) {
		struct connection *nxt = conn_list->hp_next;

		connect_to_host_pair(conn_list);
		conn_list = nxt;
	}

	if (hp->connections == NULL) {
		passert(hp->pending == NULL); /* ??? must deal with this! */
		LIST_RM(next, hp, host_pairs, true/*expected*/);
		pfree(hp);
	}
}

/* Adjust orientations of connections to reflect newly added interfaces. */
void check_orientations(void)
{
	/* Try to orient all the unoriented connections. */
	{
		dbg("FOR_EACH_UNORIENTED_CONNECTION_... in %s", __func__);
		struct connection *c = unoriented_connections;

		unoriented_connections = NULL;

		while (c != NULL) {
			struct connection *nxt = c->hp_next;

			(void)orient(c);
			connect_to_host_pair(c);
			c = nxt;
		}
	}

	/*
	 * Check that no oriented connection has become double-oriented.
	 * In other words, the far side must not match one of our new
	 * interfaces.
	 */
	{
		struct iface_port *i;

		for (i = interfaces; i != NULL; i = i->next) {
			if (i->change == IFN_ADD) {
				struct host_pair *hp;

				for (hp = host_pairs; hp != NULL;
				     hp = hp->next) {
					/*
					 * XXX: what's with the maybe
					 * compare the port logic?
					 */
					if (sameaddr(&hp->remote,
						     &i->ip_addr) &&
					    (kern_interface != NO_KERNEL ||
					     endpoint_port(&hp->remote) == pluto_port))
					{
						/*
						 * bad news: the whole chain of
						 * connections hanging off this
						 * host pair has both sides
						 * matching an interface.
						 * We'll get rid of them, using
						 * orient and
						 * connect_to_host_pair.
						 * But we'll be lazy and not
						 * ditch the host_pair itself
						 * (the cost of leaving it is
						 * slight and cannot be
						 * induced by a foe).
						 */
						struct connection *c =
							hp->connections;

						hp->connections = NULL;
						while (c != NULL) {
							struct connection *nxt =
								c->hp_next;

							c->interface = NULL;
							(void)orient(c);
							connect_to_host_pair(c);
							c = nxt;
						}
					}
				}
			}
		}
	}
}
