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
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
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

#include "defs.h"
#include "connections.h"
#include "pending.h"
#include "routing.h"		/* for connection_unroute(c) */
#include "log.h"
#include "ip_info.h"
#include "hash_table.h"
#include "iface.h"
#include "orient.h"
#include "host_pair.h"

/*
 * Table of host_pairs (local->remote endpoints/addresses).
 */

const char host_pair_magic[] = "host pair magic";

static void jam_host_pair(struct jambuf *buf, const struct host_pair *hp)
{
	passert(hp->magic == host_pair_magic);
	jam_address(buf, &hp->local);
	jam(buf, "->");
	jam_address(buf, &hp->remote);
}

static hash_t hp_hasher(const ip_address local, const ip_address remote)
{
	hash_t hash = zero_hash;
	if (pexpect(address_is_specified(local))) {
		hash = hash_hunk(address_as_shunk(&local), hash);
	}
	if (address_is_specified(remote)) {
		hash = hash_hunk(address_as_shunk(&remote), hash);
	}
	return hash;
}

static hash_t hash_host_pair_addresses(const struct host_pair *hp)
{
	return hp_hasher(hp->local, hp->remote);
}

HASH_TABLE(host_pair, addresses, , STATE_TABLE_SIZE);

#define LIST_RM(ENEXT, E, EHEAD, EXPECTED)				\
	{								\
		bool found_ = false;					\
		for (typeof(*(EHEAD)) **ep_ = &(EHEAD); *ep_ != NULL; ep_ = &(*ep_)->ENEXT) { \
			if (*ep_ == (E)) {				\
				*ep_ = (E)->ENEXT;			\
				found_ = true;				\
				break;					\
			}						\
		}							\
		/* we must not come up empty-handed? */			\
		pexpect(found_ || !(EXPECTED));				\
	}

/* struct host_pair: a nexus of information about a pair of hosts.
 * A host is an IP address, UDP port pair.  This is a debatable choice:
 * - should port be considered (no choice of port in standard)?
 * - should ID be considered (hard because not always known)?
 * - should IP address matter on our end (we don't know our end)?
 * Only oriented connections are registered.
 * Unoriented connections are kept on the unoriented_connections
 * linked list (using hp_next).  For them, host_pair is NULL.
 */

static struct connection *unoriented_connections = NULL;

void host_pair_enqueue_pending(const struct connection *c,
			       struct pending *p)
{
	p->next = c->host_pair->pending;
	c->host_pair->pending = p;
}

struct pending **host_pair_first_pending(const struct connection *c)
{
	if (c->host_pair == NULL)
		return NULL;

	return &c->host_pair->pending;
}

/*
 * Returns a host-pair based upon addresses.
 *
 * REMOTE can either be a valid address or UNSET_ADDRESS.
 */

static bool host_pair_matches_addresses(const struct host_pair *hp,
					const ip_address local,
					const ip_address remote)
{
	if (!address_eq_address(hp->local, local)) {
		address_buf lb;
		connection_buf cb;
		dbg("  host_pair: skipping %s->%s, local(RHS) does not match "PRI_CONNECTION,
		    str_address(&remote, &lb), str_address(&local, &lb),
		    pri_connection(hp->connections, &cb));
		return false;
	}

	/*
	 * XXX: don't assume unset==unset and/or unset==%any, but can
	 * assume IP!={unset,%any).
	 */

	if (address_is_specified(remote) &&
	    !address_eq_address(remote, hp->remote)) {
		connection_buf cb;
		address_buf lb, rb;
		dbg("  host_pair: skipping %s->%s, specified remote(RHS) does not match "PRI_CONNECTION,
		    str_address(&remote, &lb), str_address(&local, &rb),
		    pri_connection(hp->connections, &cb));
		return false;
	}

	if (!address_is_specified(remote) &&
	    address_is_specified(hp->remote)) {
		connection_buf cb;
		address_buf lb, rb;
		dbg("  host_pair: skipping %s->%s, unspecified remote(RHS) does not match "PRI_CONNECTION,
		    str_address(&local, &lb), str_address(&remote, &rb),
		    pri_connection(hp->connections, &cb));
		return false;
	}

	return true;
}

static struct host_pair *alloc_host_pair(ip_address local, ip_address remote, where_t where)
{
	struct host_pair *hp = alloc_thing(struct host_pair, "host pair");
	dbg_alloc("hp", hp, where);
	hp->magic = host_pair_magic;
	hp->local = local;
	/*
	 * Force unset/NULL to 'any' a.k.a. zero; so hash is
	 * consistent and comparisons work.
	 */
	hp->remote = (address_is_unset(&remote) ? address_type(&local)->address.unspec : remote);
	init_hash_table_entry(&host_pair_addresses_hash_table, hp);
	add_hash_table_entry(&host_pair_addresses_hash_table, hp);
	return hp;
}

static void free_host_pair(struct host_pair **hp, where_t where)
{
	/* ??? must deal with this! */
	passert((*hp)->pending == NULL);
	pexpect((*hp)->connections == NULL);
	del_hash_table_entry(&host_pair_addresses_hash_table, *hp);
	dbg_free("hp", *hp, where);
	pfree(*hp);
	*hp = NULL;
}

struct connection *next_host_pair_connection(const ip_address local,
					     const ip_address remote,
					     struct connection **next,
					     bool first,
					     where_t where)
{
	struct connection *c;
	if (first) {
		address_buf lb, rb;
		dbg("FOR_EACH_HOST_PAIR_CONNECTION(%s->%s) in "PRI_WHERE,
		    str_address(&remote, &lb), str_address(&local, &rb),
		    pri_where(where));
		/*
		 * Find the host-pair list that contains all
		 * connections matching REMOTE->LOCAL.
		 */
		hash_t hash = hp_hasher(local, remote);
		struct list_head *bucket = hash_table_bucket(&host_pair_addresses_hash_table, hash);
		struct host_pair *hp = NULL;
		FOR_EACH_LIST_ENTRY_NEW2OLD(hp, bucket) {
			if (host_pair_matches_addresses(hp, local, remote)) {
				connection_buf cb;
				address_buf lb, rb;
				dbg("  host_pair: %s->%s matches "PRI_CONNECTION,
				    str_address(&remote, &rb), str_address(&local, &lb),
				    pri_connection(hp->connections, &cb));
				break;
			}
		}
		c = (hp != NULL) ? hp->connections : NULL;
	} else {
		c = *next;
	}
	*next = (c != NULL) ? c->hp_next : NULL;
	return c;
}

void connect_to_host_pair(struct connection *c)
{
	if (oriented(c)) {
		ip_address local = c->local->host.addr;
		/* remote could be unset OR any */
		ip_address remote = c->remote->host.addr;
		address_buf lb, rb;
		dbg("looking for host pair matching %s->%s",
		    str_address(&remote, &rb), str_address(&local, &lb));
		hash_t hash = hp_hasher(local, remote);
		struct host_pair *hp = NULL;
		struct list_head *bucket = hash_table_bucket(&host_pair_addresses_hash_table, hash);
		FOR_EACH_LIST_ENTRY_NEW2OLD(hp, bucket) {
			if (host_pair_matches_addresses(hp, local, remote)) {
				break;
			}
		}
		if (hp == NULL) {
			/* no suitable host_pair -- build one */
			ip_address local = c->local->host.addr;
			/* remote could be unset OR any */
			ip_address remote = c->remote->host.addr;
			hp = alloc_host_pair(local, remote, HERE);
		}
		c->host_pair = hp;
		c->hp_next = hp->connections;
		hp->connections = c;
	} else {
		/* since this connection isn't oriented, we place it
		 * in the unoriented_connections list instead.
		 */
		pexpect(c->host_pair == NULL);
		pexpect(c->interface == NULL);
		c->host_pair = NULL;
		c->hp_next = unoriented_connections;
		unoriented_connections = c;
	}
}

void release_dead_interfaces(struct logger *logger)
{
	/*
	 * Release (and for instances, delete) any connections with a
	 * dead interface.
	 *
	 * The connections are scanned new-to-old so that instances
	 * are deleted before templates are released.
	 */
	struct connection_filter cf = { .where = HERE, };
	while (next_connection_new2old(&cf)) {
		struct connection *c = cf.c;

		if (!oriented(c)) {
			connection_buf cb;
			dbg("connection interface un-oriented: "PRI_CONNECTION,
			    pri_connection(c, &cb));
			continue;
		}

		passert(c->interface != NULL); /* aka oriented() */
		if (c->interface->ip_dev->ifd_change != IFD_DELETE) {
			connection_buf cb;
			dbg("connection interface safe: "PRI_CONNECTION,
			    pri_connection(c, &cb));
			continue;
		}

		connection_buf cb;
		dbg("connection interface deleted: "PRI_CONNECTION,
		    pri_connection(c, &cb));

		connection_attach(c, logger);

		/*
		 * This connection instance's interface is going away.
		 *
		 * Note: this used to pass relations as true, to
		 * cleanup everything but that did not take into
		 * account a site to site conn on right=%any also
		 * being an instance.
		 *
		 * Since the search is new2old and a connection
		 * instance's template is older, the connection's
		 * template will only be processed after all instances
		 * have been deleted.
		 */
		remove_connection_from_pending(c);
		delete_states_by_connection(c);
		connection_unroute(c, HERE);
		if (is_instance(c)) {
			delete_connection(&c);
			pexpect(c == NULL);
			continue;
		}

		/*
		 * ... and then disorient it, moving it to the
		 * unoriented list.
		 */
		pexpect(c->host_pair != NULL);
		delete_oriented_hp(c);
		iface_endpoint_delref(&c->interface);
		c->hp_next = unoriented_connections;
		unoriented_connections = c;
		pexpect(c->host_pair == NULL);

		connection_detach(c, logger);
	}
}

void delete_oriented_hp(struct connection *c)
{
	struct host_pair *hp = c->host_pair;

	pexpect(c->host_pair != NULL);
	pexpect(c->interface != NULL);

	LIST_RM(hp_next, c, hp->connections, true/*expected*/);

	pexpect(c->host_pair != NULL);
	c->host_pair = NULL;

	/*
	 * If there are no more connections with this host_pair and we
	 * haven't even made an initial contact, let's delete this guy
	 * in case we were created by an attempted DOS attack.
	 */
	if (hp->connections == NULL) {
		free_host_pair(&hp, HERE);
	}
}

void host_pair_remove_connection(struct connection *c, bool connection_valid)
{
	if (c->host_pair == NULL) {
		/*
		 * When CONNECTION_VALID expect to find/remove C from
		 * the unoriented list.
		 */
		LIST_RM(hp_next, c, unoriented_connections,
			connection_valid);
	} else {
		delete_oriented_hp(c);
	}
}

/* update the host pairs with the latest DNS ip address */
void update_host_pairs(struct connection *c)
{
	struct host_pair *hp = c->host_pair;
	const char *dnshostname = c->config->dnshostname;

	/* ??? perhaps we should return early if dnshostname == NULL */

	if (hp == NULL)
		return;

	struct connection *d = hp->connections;

	/* ??? looks as if addr_family is not allowed to change.  Bug? */
	/* ??? why are we using d->config->dnshostname instead of (c->)dnshostname? */
	/* ??? code used to test for d == NULL, but that seems impossible. */

	pexpect(dnshostname == d->config->dnshostname || streq(dnshostname, d->config->dnshostname));

	ip_address new_addr;

	if (d->config->dnshostname == NULL ||
	    ttoaddress_dns(shunk1(d->config->dnshostname),
			      address_type(&d->remote->host.addr), &new_addr) != NULL ||
	    sameaddr(&new_addr, &hp->remote))
		return;

	struct connection *conn_list = NULL;

	while (d != NULL) {
		struct connection *nxt = d->hp_next;

		/*
		 * ??? this test used to assume that dnshostname != NULL
		 * if d->config->dnshostname != NULL.  Is that true?
		 */
		if (d->config->dnshostname != NULL && dnshostname != NULL &&
		    streq(d->config->dnshostname, dnshostname)) {
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
			connection_unroute(d, HERE);

			/*
			 * If the client is the peer, also update the
			 * client info
			 */
			if (!d->remote->child.has_client) {
				update_first_selector(d, remote, selector_from_address(new_addr));
				spd_route_db_rehash_remote_client(d->spd);
			}

			d->remote->host.addr = new_addr;
			LIST_RM(hp_next, d, d->host_pair->connections, true);

			d->hp_next = conn_list;
			conn_list = d;
		}
		d = nxt;
	}

	while (conn_list != NULL) {
		struct connection *nxt = conn_list->hp_next;

		/* assumption: orientation is the same as before */
		connect_to_host_pair(conn_list);
		conn_list = nxt;
	}

	if (hp->connections == NULL) {
		free_host_pair(&hp, HERE);
	}
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
	dbg("FOR_EACH_UNORIENTED_CONNECTION_... in %s", __func__);
	struct connection *c = unoriented_connections;
	unoriented_connections = NULL;
	while (c != NULL) {
		/* step off */
		struct connection *nxt = c->hp_next;
		orient(&c, logger);
		/*
		 * Either put C back on unoriented, or add to a host
		 * pair.
		 */
		connect_to_host_pair(c);
		c = nxt;
	}

	/*
	 * Check that no oriented connection has become double-oriented.
	 * In other words, the far side must not match one of our new
	 * interfaces.
	 */
	for (struct iface_endpoint *i = interfaces; i != NULL; i = i->next) {
		if (i->ip_dev->ifd_change != IFD_ADD) {
			continue;
		}
		for (unsigned u = 0; u < host_pair_addresses_hash_table.nr_slots; u++) {
			struct list_head *bucket = &host_pair_addresses_hash_table.slots[u];
			struct host_pair *hp = NULL;
			FOR_EACH_LIST_ENTRY_NEW2OLD(hp, bucket) {
				/*
				 * XXX: what's with the maybe compare
				 * the port logic?
				 */
				if (sameaddr(&hp->remote,
					     &i->ip_dev->id_address)) {
					/*
					 * bad news: the whole chain
					 * of connections hanging off
					 * this host pair has both
					 * sides matching an
					 * interface.  We'll get rid
					 * of them, using orient and
					 * connect_to_host_pair.
					 */
					struct connection *c =
						hp->connections;
					hp->connections = NULL;
					while (c != NULL) {
						struct connection *nxt =
							c->hp_next;
						iface_endpoint_delref(&c->interface);
						c->host_pair = NULL;
						c->hp_next = NULL;
						orient(&c, logger);
						connect_to_host_pair(c);
						c = nxt;
					}
					/*
					 * XXX: is this ever not the
					 * case?
					 */
					if (hp->connections == NULL) {
						free_host_pair(&hp, HERE);
					}
				}
			}
		}
	}
}

void host_pair_db_init(struct logger *logger)
{
	init_hash_table(&host_pair_addresses_hash_table, logger);
}
