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

#include "defs.h"
#include "connections.h"
#include "pending.h"
#include "kernel.h"		/* for unroute_connection(c) */
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

static void jam_host_pair(struct jambuf *buf, const void *data)
{
	const struct host_pair *hp = data;
	passert(hp->magic == host_pair_magic);
	jam_address(buf, &hp->local);
	jam(buf, "->");
	jam_address(buf, &hp->remote);
}

static hash_t hp_hasher(const ip_address local, const ip_address remote)
{
	hash_t hash = zero_hash;
	if (pexpect(address_is_specified(local))) {
		hash = hash_table_hasher(address_as_shunk(&local), hash);
	}
	if (address_is_specified(remote)) {
		hash = hash_table_hasher(address_as_shunk(&remote), hash);
	}
	return hash;
}

static hash_t host_pair_hasher(const void *data)
{
	const struct host_pair *hp = data;
	passert(hp->magic == host_pair_magic);
	return hp_hasher(hp->local, hp->remote);
}

static struct list_entry *host_pair_list_entry(void *data)
{
	struct host_pair *hp = data;
	passert(hp->magic == host_pair_magic);
	return &hp->host_pair_entry;
}

struct list_head host_pair_buckets[STATE_TABLE_SIZE];

static struct hash_table host_pairs = {
	.info = {
		.name = "host_pair table",
		.jam = jam_host_pair,
	},
	.hasher = host_pair_hasher,
	.entry = host_pair_list_entry,
	.nr_slots = elemsof(host_pair_buckets),
	.slots = host_pair_buckets,
};

void init_host_pair(void)
{
	init_hash_table(&host_pairs);
}

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

struct host_pair *find_host_pair(const ip_address local,
				 const ip_address remote)
{
	address_buf lb, rb;
	dbg("looking for host pair matching %s->%s",
	    str_address(&local, &lb), str_address(&remote, &rb));
	hash_t hash = hp_hasher(local, remote);
	struct host_pair *hp = NULL;
	struct list_head *bucket = hash_table_bucket(&host_pairs, hash);
	FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, hp) {
		/*
		 * Skip when the first connection is an instance;
		 * why????
		 */
		if (hp->connections != NULL && (hp->connections->kind == CK_INSTANCE) &&
		    (hp->connections->spd.that.id.kind == ID_NULL)) {
			connection_buf ci;
			dbg("find_host_pair: ignore CK_INSTANCE with ID_NULL hp:"PRI_CONNECTION,
			    pri_connection(hp->connections, &ci));
			continue;
		}

		if (!address_eq_address(hp->local, local)) {
			address_buf lb;
			connection_buf cb;
			dbg("host_pair: local %s does not match connection="PRI_CONNECTION,
			    str_address(&local, &lb),
			    pri_connection(hp->connections, &cb));
			continue;
		}

		/* now try to match */

		if (address_is_specified(remote) &&
		    address_eq_address(remote, hp->remote)) {
			connection_buf cb;
			address_buf lb, rb;
			dbg("host_pair: %s->%s exactly matches connection "PRI_CONNECTION,
			    str_address(&local, &lb), str_address(&remote, &rb),
			    pri_connection(hp->connections, &cb));
			return hp;
		}

		if (!address_is_specified(remote) &&
		    !address_is_specified(hp->remote)) {
			connection_buf cb;
			address_buf lb, rb;
			dbg("host_pair: %s->%s any matched connection="PRI_CONNECTION,
			    str_address(&local, &lb), str_address(&remote, &rb),
			    pri_connection(hp->connections, &cb));
			return hp;
		}
	}
	return NULL;
}

static struct host_pair *alloc_host_pair(ip_address local, ip_address remote, where_t where)
{
	struct host_pair *hp = alloc_thing(struct host_pair, "host pair");
	hp->magic = host_pair_magic;
	hp->local = local;
	/*
	 * Force unset/NULL to 'any' a.k.a. zero; so hash is
	 * consistent and comparisons work.
	 */
	hp->remote = (address_is_unset(&remote) ? address_type(&local)->address.any : remote);
	add_hash_table_entry(&host_pairs, hp);
	dbg_alloc("hp", hp, where);
	return hp;
}

static void free_host_pair(struct host_pair **hp, where_t where)
{
	/* ??? must deal with this! */
	passert((*hp)->pending == NULL);
	pexpect((*hp)->connections == NULL);
	del_hash_table_entry(&host_pairs, *hp);
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
	/* for moment just wrap above; should merge */
	struct connection *c;
	if (first) {
		address_buf lb, rb;
		dbg("FOR_EACH_HOST_PAIR_CONNECTION(%s->%s) in "PRI_WHERE,
		    str_address(&local, &lb), str_address(&remote, &rb),
		    pri_where(where));
		struct host_pair *hp = find_host_pair(local, remote);
		c = (hp != NULL) ? hp->connections : NULL;
	} else {
		c = *next;
	}
	*next = (c != NULL) ? c->hp_next : NULL;
	return c;
}

void connect_to_host_pair(struct connection *c)
{
	if (oriented(*c)) {
		struct host_pair *hp = find_host_pair(c->spd.this.host_addr,
						      /* remote could be unset OR any */
						      c->spd.that.host_addr);

		address_buf b1, b2;
		dbg("connect_to_host_pair: %s->%s -> hp@%p: %s",
		    str_address(&c->spd.this.host_addr, &b1),
		    str_address(&c->spd.that.host_addr, &b2),
		    hp, (hp != NULL && hp->connections != NULL) ? hp->connections->name : "none");

		if (hp == NULL) {
			/* no suitable host_pair -- build one */
			ip_address local = c->spd.this.host_addr;
			/* remote could be unset OR any */
			ip_address remote = c->spd.that.host_addr;
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
	 * Delete any connections with a dead interface.  Deleting the
	 * connection could (?) trigger deleting other connections,
	 * but presumably they are further down in the list?
	 */
	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (struct connection **cp = &connections, *c = connections;
	     c != NULL; c = *cp) {

		if (!oriented(*c)) {
			connection_buf cb;
			dbg("connection interface un-oriented: "PRI_CONNECTION,
			    pri_connection(c, &cb));
			cp = &c->ac_next;
			continue;
		}

		passert(c->interface != NULL); /* aka oriented() */
		if (c->interface->ip_dev->ifd_change != IFD_DELETE) {
			connection_buf cb;
			dbg("connection interface safe: "PRI_CONNECTION,
			    pri_connection(c, &cb));
			cp = &c->ac_next;
			continue;
		}

		connection_buf cb;
		dbg("connection interface deleted: "PRI_CONNECTION,
		    pri_connection(c, &cb));

		/* this connection's interface is going away */
		enum connection_kind kind = c->kind;
		passert(c == *cp);
		release_connection(c, true/*relations*/, logger->global_whackfd);
		if (kind == CK_INSTANCE) {
			/* C invalid; was deleted */
			pexpect(c != *cp);
			continue;
		}

		/*
		 * The connection should have survived release: move
		 * it to the unoriented_connections list.
		 */
		passert(c == *cp);
		terminate_connection(c->name,
				     false/*quiet?*/,
				     logger->global_whackfd);
		/*
		 * disorient connection and then put on the unoriented
		 * list.
		 */
		pexpect(c->host_pair != NULL);
		delete_oriented_hp(c);
		c->interface = NULL;
		c->hp_next = unoriented_connections;
		unoriented_connections = c;
		pexpect(c->host_pair == NULL);
		/* advance */
		cp = &c->ac_next;
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
	    ttoaddress_dns(shunk1(d->dnshostname),
			      address_type(&d->spd.that.host_addr), &new_addr) != NULL ||
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
				d->spd.that.client = selector_from_address(new_addr);
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

		/* assumption: orientation is the same as before */
		connect_to_host_pair(conn_list);
		conn_list = nxt;
	}

	if (hp->connections == NULL) {
		free_host_pair(&hp, HERE);
	}
}

/* Adjust orientations of connections to reflect newly added interfaces. */
void check_orientations(void)
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
		orient(c);
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
		for (unsigned u = 0; u < host_pairs.nr_slots; u++) {
			struct list_head *bucket = &host_pairs.slots[u];
			struct host_pair *hp = NULL;
			FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, hp) {
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
						c->interface = NULL;
						c->host_pair = NULL;
						c->hp_next = NULL;
						orient(c);
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
