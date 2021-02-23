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
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "nat_traversal.h"
#include "ip_address.h"
#include "ip_info.h"
#include "hash_table.h"
#include "iface.h"


#include "hostpair.h"

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

static hash_t hp_hasher(const ip_address *local, const ip_address *remote)
{
	hash_t hash = zero_hash;
	hash = hash_table_hasher(address_as_shunk(local), hash);
	hash = hash_table_hasher(address_as_shunk(remote), hash);
	return hash;
}

static hash_t host_pair_hasher(const void *data)
{
	const struct host_pair *hp = data;
	passert(hp->magic == host_pair_magic);
	return hp_hasher(&hp->local, &hp->remote);
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

/** returns a host pair based upon addresses.
 *
 * find_host_pair is given a pair of addresses, plus UDP ports, and
 * returns a host_pair entry that covers it. It also moves the relevant
 * pair description to the beginning of the list, so that it can be
 * found faster next time.
 */

struct host_pair *find_host_pair(const ip_address *local,
				 const ip_address *remote)
{
	/*
	 * Force unset/NULL to 'any' a.k.a. zero; so hash is
	 * consistent and comparisons work.
	 */
	if (remote == NULL || address_is_unset(remote)) {
		remote = &address_type(local)->address.any;
	}

	/*
	 * look for a host-pair that has the right set of ports/address.
	 *
	 */
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

		address_buf b1;
		address_buf b2;
		dbg("host_pair: comparing to %s->%s",
		    str_address(&hp->local, &b1),
		    str_address(&hp->remote, &b2));

		/* XXX: same addr does not compare ports.  */
		if (sameaddr(&hp->local, local) &&
		    sameaddr(&hp->remote, remote)) {
			connection_buf cb;
			dbg("host_pair: match connection="PRI_CONNECTION,
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

struct connection *next_host_pair_connection(const ip_address *local,
					     const ip_address *remote,
					     struct connection **next,
					     bool first,
					     where_t where)
{
	/* for moment just wrap above; should merge */
	struct connection *c;
	if (first) {
		address_buf lb, rb;
		dbg("FOR_EACH_HOST_PAIR_CONNECTION(%s->%s) in "PRI_WHERE,
		    str_address(local, &lb), str_address(remote, &rb),
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
		struct host_pair *hp = find_host_pair(&c->spd.this.host_addr,
						      /* remote could be unset OR any */
						      &c->spd.that.host_addr);

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
	    domain_to_address(shunk1(d->dnshostname),
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
				d->spd.that.client = selector_from_address(&new_addr);
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

/*
 * find_host_connection: find the first satisfactory connection
 *	with this pair of hosts.
 *
 * find_next_host_connection: find the next satisfactory connection
 *	Starts where find_host_connection left off.
 *	NOTE: it will return its argument; if you want to
 *	advance, use c->hp_next.
 *
 * We start with the list that find_host_pair_connections would yield
 * but we narrow the selection.
 *
 * We only yield a connection that can negotiate.
 *
 * The caller can specify policy requirements as
 * req_policy and policy_exact_mask.
 *
 * All policy bits found in req_policy must be in the
 * policy of the connection.
 *
 * For all bits in policy_exact mask, the req_policy
 * and connection's policy must be equal.  Likely candidates:
 * - XAUTH (POLICY_XAUTH)
 * - kind of IKEV1 (POLICY_AGGRESSIVE)
 * These should only be used if the caller actually knows
 * the exact value and has included it in req_policy.
 */
struct connection *find_host_connection(enum ike_version ike_version,
					const ip_endpoint *local_endpoint,
					const ip_endpoint *remote_endpoint,
					lset_t req_policy, lset_t policy_exact_mask)
{
	endpoint_buf lb;
	endpoint_buf rb;
	policy_buf pb;
	dbg("find_host_connection %s local=%s remote=%s policy=%s but ignoring ports",
	    enum_name(&ike_version_names, ike_version),
	    str_endpoint(local_endpoint, &lb),
	    str_endpoint(remote_endpoint, &rb),
	    str_policy(req_policy, &pb));

	/* strip port */
	ip_address local_address = endpoint_address(local_endpoint);
	ip_address remote_address = endpoint_address(remote_endpoint);/*could return unset OR any*/
	struct host_pair *hp = find_host_pair(&local_address, &remote_address);
	if (hp == NULL) {
		return NULL;
	}

	/* XXX: don't be fooled by "next", the search includes hp->connections */
	struct connection *c = find_next_host_connection(ike_version, hp->connections,
							 req_policy, policy_exact_mask);
	/*
	 * This could be a shared IKE SA connection, in which case
	 * we prefer to find the connection that has the IKE SA
	 *
	 * XXX: need to advance candidate before calling
	 * find_next_host_connection() as otherwise it returns the
	 * same connection, ARGH!
	 */
	for (struct connection *candidate = c;
	     candidate != NULL;
	     candidate = find_next_host_connection(ike_version, candidate->hp_next,
						   req_policy, policy_exact_mask)) {
		if (candidate->newest_isakmp_sa != SOS_NOBODY)
			return candidate;
	}

	return c;
}

struct connection *find_next_host_connection(enum ike_version ike_version,
					     struct connection *c,
					     lset_t req_policy, lset_t policy_exact_mask)
{
	policy_buf pb;
	dbg("find_next_host_connection policy=%s",
	    str_policy(req_policy, &pb));

	for (; c != NULL; c = c->hp_next) {
		policy_buf fb;
		dbg("found policy = %s (%s)",
		    str_policy(c->policy, &fb),
		    c->name);

		if (NEVER_NEGOTIATE(c->policy)) {
			/* are we a block or clear connection? */
			lset_t shunt = (c->policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT;
			if (shunt != POLICY_SHUNT_TRAP) {
				/*
				 * We need to match block/clear so we can send back
				 * NO_PROPOSAL_CHOSEN, otherwise not match so we
				 * can hit packetdefault to do real IKE.
				 * clear and block do not have POLICY_OPPORTUNISTIC,
				 * but clear-or-private and private-or-clear do, but
				 * they don't do IKE themselves but allow packetdefault
				 * to be hit and do the work.
				 * if not policy_oppo -> we hit clear/block so this is right c
				 */
				if ((c->policy & POLICY_OPPORTUNISTIC))
					continue;

				/* shunt match - stop the search for another conn if we are groupinstance*/
				if (c->policy & POLICY_GROUPINSTANCE)
					break;
			}
			continue;
		}

		/*
		 * Success may require exact match of:
		 * (1) XAUTH (POLICY_XAUTH)
		 * (2) kind of IKEV1 (POLICY_AGGRESSIVE)
		 * (3) IKE_VERSION
		 * So if any bits are on in the exclusive OR, we fail.
		 * Each of our callers knows what is known so specifies
		 * the policy_exact_mask.
		 */
		if (c->ike_version != ike_version)
			continue;
		if ((req_policy ^ c->policy) & policy_exact_mask)
			continue;

		/*
		 * Success if all specified policy bits are in candidate's policy.
		 * It works even when the exact-match bits are included.
		 */
		if ((req_policy & ~c->policy) == LEMPTY)
			break;
	}

	if (DBGP(DBG_BASE)) {
		if (c == NULL) {
			DBG_log("find_next_host_connection returns <empty>");
		} else {
			connection_buf ci;
			DBG_log("find_next_host_connection returns "PRI_CONNECTION"",
				pri_connection(c, &ci));
		}
	}

	return c;
}

static struct connection *ikev2_find_host_connection(struct msg_digest *md,
						     lset_t policy, bool *send_reject_response)
{
	const ip_endpoint *local_endpoint = &md->iface->local_endpoint;
	const ip_endpoint *remote_endpoint = &md->sender;
	/* just the adddress */
	ip_address local_address = endpoint_address(local_endpoint);
	ip_address remote_address = endpoint_address(remote_endpoint);

	struct connection *c = find_host_connection(IKEv2, local_endpoint,
						    remote_endpoint,
						    policy, LEMPTY);
	if (c == NULL) {
		/*
		 * See if a wildcarded connection can be found.  We
		 * cannot pick the right connection, so we're making a
		 * guess.  All Road Warrior connections are fair game:
		 * we pick the first we come across (if any).  If we
		 * don't find any, we pick the first opportunistic
		 * with the smallest subnet that includes the peer.
		 * There is, of course, no necessary relationship
		 * between an Initiator's address and that of its
		 * client, but Food Groups kind of assumes one.
		 */
		for (struct connection *d = find_host_connection(IKEv2, local_endpoint,
								 &unset_endpoint,
								 policy, LEMPTY);
		     d != NULL; d = find_next_host_connection(IKEv2, d->hp_next, policy, LEMPTY)) {
			if (d->kind == CK_GROUP) {
				continue;
			}
			/*
			 * Road Warrior: we have an instant winner.
			 */
			if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPORTUNISTIC)) {
				c = d;
				break;
			}
			/*
			 * Opportunistic or Shunt: keep searching
			 * selecting the tightest match.
			 */
			if (address_in_selector(&remote_address, &d->spd.that.client) &&
			    (c == NULL || !selector_in_selector(&c->spd.that.client,
								&d->spd.that.client))) {

				c = d;
				/* keep looking */
			}
		}

		if (c == NULL) {
			endpoint_buf b;
			policy_buf pb;
			dbgl(md->md_logger,
			     "%s message received on %s but no connection has been authorized with policy %s",
			     enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
			     str_endpoint(local_endpoint, &b),
			     str_policy(policy, &pb));
			*send_reject_response = true;
			return NULL;
		}

		if (c->kind != CK_TEMPLATE) {
			endpoint_buf b;
			connection_buf cib;
			dbgl(md->md_logger,
			     "%s message received on %s for "PRI_CONNECTION" with kind=%s dropped",
			     enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
			     str_endpoint(local_endpoint, &b),
			     pri_connection(c, &cib),
			     enum_name(&connection_kind_names, c->kind));
			/*
			 * This is used when in IKE_INIT request is
			 * received but hits an OE clear
			 * foodgroup. There is no point sending the
			 * message as it is unauthenticated and cannot
			 * be trusted by the initiator. And the
			 * responder is revealing itself to the
			 * initiator while it is configured to never
			 * talk to that particular initiator. With
			 * this, the system does not need to enforce
			 * this policy using a firewall.
			 *
			 * Note that this technically violates the
			 * IKEv2 specification that states we MUST
			 * answer (with NO_PROPOSAL_CHOSEN).
			 */
			*send_reject_response = false;
			return NULL;
		}
		/* only allow opportunistic for IKEv2 connections */
		if (LIN(POLICY_OPPORTUNISTIC, c->policy) &&
		    c->ike_version == IKEv2) {
			dbgl(md->md_logger, "oppo_instantiate");
			c = oppo_instantiate(c, &c->spd.that.id,
					     &local_address, &remote_address);
		} else {
			/* regular roadwarrior */
			dbgl(md->md_logger, "rw_instantiate");
			c = rw_instantiate(c, &remote_address, NULL, NULL);
		}
	} else {
		/*
		 * We found a non-wildcard connection.
		 * Double check whether it needs instantiation anyway (eg. vnet=)
		 */
		/* vnet=/vhost= should have set CK_TEMPLATE on connection loading */
		passert(c->spd.this.virt == NULL);

		if (c->kind == CK_TEMPLATE && c->spd.that.virt != NULL) {
			dbgl(md->md_logger,
			     "local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation");
			c = rw_instantiate(c, &remote_address, NULL, NULL);
		} else if ((c->kind == CK_TEMPLATE) &&
				(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			dbgl(md->md_logger,
			     "local endpoint has narrowing=yes - needs instantiation");
			c = rw_instantiate(c, &remote_address, NULL, NULL);
		}
	}
	return c;
}

struct connection *find_v2_host_pair_connection(struct msg_digest *md, lset_t *policy,
						bool *send_reject_response)
{
	/* authentication policy alternatives in order of decreasing preference */
	static const lset_t policies[] = { POLICY_ECDSA, POLICY_RSASIG, POLICY_PSK, POLICY_AUTH_NULL };

	struct connection *c = NULL;
	unsigned int i;

	/*
	 * XXX in the near future, this loop should find
	 * type=passthrough and return STF_DROP
	 */
	for (i=0; i < elemsof(policies); i++) {
		/*
		 * When the connection "isn't found" POLICY and
		 * SEND_REJECTED_RESPONSE end up with the values from
		 * the final POLICY_AUTH_NULL search.
		 *
		 * For instance, if an earlier search returns NULL but
		 * clears SEND_REJECT_RESPONSE, that will be lost.
		 */
		*policy = policies[i];
		*send_reject_response = true;
		c = ikev2_find_host_connection(md, *policy,
					       send_reject_response);
		if (c != NULL)
			break;
	}

	if (c == NULL) {
		/* we might want to change this to a debug log message only */
		endpoint_buf b;
		llog(RC_LOG_SERIOUS, md->md_logger,
		     "%s message received on %s but no suitable connection found with IKEv2 policy",
		     enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
		     str_endpoint(&md->iface->local_endpoint, &b));
		return NULL;
	}

	passert(c != NULL);	/* (e != STF_OK) == (c == NULL) */

	connection_buf ci;
	policy_buf pb;
	dbgl(md->md_logger,
	     "found connection: "PRI_CONNECTION" with policy %s",
	     pri_connection(c, &ci),
	     str_policy(*policy, &pb));

	/*
	 * Did we overlook a type=passthrough foodgroup?
	 */
	FOR_EACH_HOST_PAIR_CONNECTION(&md->iface->ip_dev->id_address, NULL, tmp) {
		if ((tmp->policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP) {
			continue;
		}
		if (tmp->kind != CK_INSTANCE) {
			continue;
		}
		ip_address sender = endpoint_address(&md->sender);
		if (!address_in_selector(&sender, &tmp->spd.that.client)) {
			continue;
		}
		dbgl(md->md_logger,
		     "passthrough conn %s also matches - check which has longer prefix match", tmp->name);
		if (c->spd.that.client.maskbits >= tmp->spd.that.client.maskbits) {
			continue;
		}
		dbgl(md->md_logger,
		     "passthrough conn was a better match (%d bits versus conn %d bits) - suppressing NO_PROPSAL_CHOSEN reply",
		     tmp->spd.that.client.maskbits,
		     c->spd.that.client.maskbits);
		return NULL;
	}
	return c;
}
