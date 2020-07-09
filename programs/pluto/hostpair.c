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
#include "spdb.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "nat_traversal.h"
#include "ip_address.h"
#include "ip_info.h"
#include "hash_table.h"
#include "iface.h"

#include "virtual.h"	/* needs connections.h */

#include "hostpair.h"

/*
 * Table of host_pairs (local->remote endpoints/addresses).
 */

const char host_pair_magic[] = "host pair magic";

static void jam_host_pair(struct lswlog *buf, const void *data)
{
	const struct host_pair *hp = data;
	passert(hp->magic == host_pair_magic);
	jam_endpoint(buf, &hp->local);
	jam(buf, "->");
	jam_endpoint(buf, &hp->remote);
}

static hash_t hp_hasher(const ip_endpoint *local, const ip_endpoint *remote)
{
	/* strip port */
	ip_address laddr = endpoint_address(local);
	/* NULL -> any_address aka zero; must hash it */
	ip_address raddr = (remote != NULL ? endpoint_address(remote) : endpoint_type(local)->any_address);
	hash_t hash = zero_hash;
	hash = hash_table_hasher(address_as_shunk(&laddr), hash);
	hash = hash_table_hasher(address_as_shunk(&raddr), hash);
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
	/* NULL -> any_address aka zero; must hash it */
	if (remote == NULL) {
		remote = &endpoint_type(local)->any_address;
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

		endpoint_buf b1;
		endpoint_buf b2;
		dbg("find_host_pair: comparing %s to %s but ignoring ports",
		    str_endpoint(&hp->local, &b1),
		    str_endpoint(&hp->remote, &b2));

		/* XXX: same addr does not compare ports.  */
		if (sameaddr(&hp->local, local) &&
		    sameaddr(&hp->remote, remote)) {
			return hp;
		}
	}
	return NULL;
}

static void remove_host_pair(struct host_pair *hp)
{
	del_hash_table_entry(&host_pairs, hp);
}

/* find head of list of connections with this pair of hosts */
struct connection *find_host_pair_connections(const ip_address *myaddr,
					      const ip_address *peer_addr)
{
	struct host_pair *hp = find_host_pair(myaddr, peer_addr);

#if 0
	address_buf bm, bh;
	connection_buf ci;
	dbg("find_host_pair_conn: %s:%d %s:%d -> hp:%s%s",
	    str_address(myaddr, &bm), myport,
	    peer_addr != NULL ? str_address(peer_addr, &bh) : "%any",
	    peer_port,
	    hp != NULL && hp->connections != NULL ?
	    hp->connections->name : "none",
	    hp != NULL && hp->connections != NULL ?
	    str_conn_instance(hp->connections, ci) : ""));
#endif

	return hp == NULL ? NULL : hp->connections;
}

void connect_to_host_pair(struct connection *c)
{
	if (oriented(*c)) {
		struct host_pair *hp = find_host_pair(&c->spd.this.host_addr,
						      &c->spd.that.host_addr);

		address_buf b1, b2;
		dbg("connect_to_host_pair: %s:%d %s:%d -> hp@%p: %s",
		    str_address(&c->spd.this.host_addr, &b1),
		    c->spd.this.host_port,
		    str_address(&c->spd.that.host_addr, &b2),
		    c->spd.that.host_port,
		    hp, (hp != NULL && hp->connections != NULL) ? hp->connections->name : "none");

		if (hp == NULL) {
			/* no suitable host_pair -- build one */
			hp = alloc_thing(struct host_pair, "host_pair");
			dbg("new hp@%p", hp);
			hp->magic = host_pair_magic;
			hp->local = endpoint3(c->interface->protocol,
					      &c->spd.this.host_addr,
					      ip_hport(nat_traversal_enabled ? IKE_UDP_PORT
						       : c->spd.this.host_port));
			hp->remote = endpoint3(c->interface->protocol,
					       &c->spd.that.host_addr,
					       ip_hport(nat_traversal_enabled ? IKE_UDP_PORT
							: c->spd.that.host_port));
			hp->connections = NULL;
			hp->pending = NULL;
			add_hash_table_entry(&host_pairs, hp);
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

void release_dead_interfaces(struct fd *whackfd)
{
	for (unsigned i = 0; i < host_pairs.nr_slots; i++) {
		struct list_head *bucket = &host_pairs.slots[i];
		struct host_pair *hp = NULL;
		FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, hp) {
			struct connection **pp, *p;

			for (pp = &hp->connections; (p = *pp) != NULL; ) {
				if (p->interface->ip_dev->ifd_change == IFD_DELETE) {
					/* this connection's interface is going away */
					enum connection_kind k = p->kind;

					release_connection(p, true, whackfd);

					if (k <= CK_PERMANENT) {
						/* The connection should have survived release:
						 * move it to the unoriented_connections list.
						 */
						passert(p == *pp);

						terminate_connection(p->name, false, whackfd);
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
		dbg("free hp@%p", hp);
		pfree(hp);
	}
}

void host_pair_remove_connection(struct connection *c, bool connection_valid)
{
	if (c->host_pair == NULL) {
		LIST_RM(hp_next, c, unoriented_connections,
			connection_valid);
	} else {
		delete_oriented_hp(c);
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
				endtosubnet(&new_addr, &d->spd.that.client, HERE);
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
		passert(hp->pending == NULL); /* ??? must deal with this! */
		del_hash_table_entry(&host_pairs, hp);
		dbg("free hp@%p", hp);
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
			if (i->ip_dev->ifd_change != IFD_ADD) {
				continue;
			}
			for (unsigned u = 0; u < host_pairs.nr_slots; u++) {
				struct list_head *bucket = &host_pairs.slots[u];
				struct host_pair *hp = NULL;
				FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, hp) {
					/*
					 * XXX: what's with the maybe
					 * compare the port logic?
					 */
					if (sameaddr(&hp->remote,
						     &i->local_endpoint)) {
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
 * - kind of IKEV1 (POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW)
 * These should only be used if the caller actually knows
 * the exact value and has included it in req_policy.
 */
struct connection *find_host_connection(const ip_endpoint *local,
					const ip_endpoint *remote,
					lset_t req_policy, lset_t policy_exact_mask)
{
	endpoint_buf lb;
	endpoint_buf rb;
	dbg("find_host_connection local=%s remote=%s policy=%s but ignoring ports",
	    str_endpoint(local, &lb), str_endpoint(remote, &rb),
	    bitnamesof(sa_policy_bit_names, req_policy));

	struct connection *c =
		find_next_host_connection(find_host_pair_connections(local, remote),
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
	     candidate = find_next_host_connection(candidate->hp_next, req_policy,
						   policy_exact_mask)) {
		if (candidate->newest_isakmp_sa != SOS_NOBODY)
			return candidate;
	}

	return c;
}

struct connection *find_next_host_connection(
	struct connection *c,
	lset_t req_policy, lset_t policy_exact_mask)
{
	dbg("find_next_host_connection policy=%s",
	    bitnamesof(sa_policy_bit_names, req_policy));

	for (; c != NULL; c = c->hp_next) {
		dbg("found policy = %s (%s)",
		    bitnamesof(sa_policy_bit_names, c->policy),
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
		 * (2) kind of IKEV1 (POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW)
		 * So if any bits are on in the exclusive OR, we fail.
		 * Each of our callers knows what is known so specifies
		 * the policy_exact_mask.
		 */
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
	const ip_endpoint *local = &md->iface->local_endpoint;
	const ip_endpoint *remote = &md->sender;

	struct connection *c = find_host_connection(local, remote, policy, LEMPTY);
	if (c == NULL) {
		/* See if a wildcarded connection can be found.
		 * We cannot pick the right connection, so we're making a guess.
		 * All Road Warrior connections are fair game:
		 * we pick the first we come across (if any).
		 * If we don't find any, we pick the first opportunistic
		 * with the smallest subnet that includes the peer.
		 * There is, of course, no necessary relationship between
		 * an Initiator's address and that of its client,
		 * but Food Groups kind of assumes one.
		 */
		{
			struct connection *d = find_host_connection(local, NULL,
								    policy, LEMPTY);

			while (d != NULL) {
				if (d->kind == CK_GROUP) {
					/* ignore */
				} else {
					if (d->kind == CK_TEMPLATE &&
							!(d->policy & POLICY_OPPORTUNISTIC)) {
						/* must be Road Warrior: we have a winner */
						c = d;
						break;
					}

					/* Opportunistic or Shunt: pick tightest match */
					if (addrinsubnet(remote, &d->spd.that.client) &&
							(c == NULL ||
							 !subnetinsubnet(&c->spd.that.client,
								 &d->spd.that.client))) {
						c = d;
					}
				}
				d = find_next_host_connection(d->hp_next,
						policy, LEMPTY);
			}
		}
		if (c == NULL) {
			endpoint_buf b;
			dbg_md(md, "%s message received on %s but no connection has been authorized with policy %s",
			       enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
			       str_endpoint(local, &b),
			       bitnamesof(sa_policy_bit_names, policy));
			*send_reject_response = true;
			return NULL;
		}

		if (c->kind != CK_TEMPLATE) {
			endpoint_buf b;
			connection_buf cib;
			dbg_md(md, "%s message received on %s for "PRI_CONNECTION" with kind=%s dropped",
			       enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
			       str_endpoint(local, &b),
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
			dbg_md(md, "oppo_instantiate");
			ip_address remote_addr = endpoint_address(remote);
			c = oppo_instantiate(c, &remote_addr, &c->spd.that.id, &c->spd.this.host_addr, remote);
		} else {
			/* regular roadwarrior */
			dbg_md(md, "rw_instantiate");
			ip_address remote_addr = endpoint_address(remote);
			c = rw_instantiate(c, &remote_addr, NULL, NULL);
		}
	} else {
		/*
		 * We found a non-wildcard connection.
		 * Double check whether it needs instantiation anyway (eg. vnet=)
		 */
		/* vnet=/vhost= should have set CK_TEMPLATE on connection loading */
		passert(c->spd.this.virt == NULL);

		if (c->kind == CK_TEMPLATE && c->spd.that.virt != NULL) {
			dbg_md(md, "local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation");
			ip_address remote_addr = endpoint_address(remote);
			c = rw_instantiate(c, &remote_addr, NULL, NULL);
		} else if ((c->kind == CK_TEMPLATE) &&
				(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			dbg_md(md, "local endpoint has narrowing=yes - needs instantiation");
			ip_address remote_addr = endpoint_address(remote);
			c = rw_instantiate(c, &remote_addr, NULL, NULL);
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
		*policy = policies[i] | POLICY_IKEV2_ALLOW;
		*send_reject_response = true;
		c = ikev2_find_host_connection(md, *policy,
					       send_reject_response);
		if (c != NULL)
			break;
	}

	if (c == NULL) {
		/* we might want to change this to a debug log message only */
		endpoint_buf b;
		log_md(RC_LOG_SERIOUS, md,
		       "%s message received on %s but no suitable connection found with IKEv2 policy",
		       enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
		       str_endpoint(&md->iface->local_endpoint, &b));
		return NULL;
	}

	passert(c != NULL);	/* (e != STF_OK) == (c == NULL) */

	connection_buf ci;
	dbg_md(md, "found connection: "PRI_CONNECTION" with policy %s",
	       pri_connection(c, &ci),
	       bitnamesof(sa_policy_bit_names, *policy));

	/*
	 * Did we overlook a type=passthrough foodgroup?
	 */
	{
		struct connection *tmp = find_host_pair_connections(&md->iface->local_endpoint, NULL);

		for (; tmp != NULL; tmp = tmp->hp_next) {
			if ((tmp->policy & POLICY_SHUNT_MASK) != POLICY_SHUNT_TRAP &&
			    tmp->kind == CK_INSTANCE &&
			    addrinsubnet(&md->sender, &tmp->spd.that.client))
			{
				dbg_md(md, "passthrough conn %s also matches - check which has longer prefix match", tmp->name);

				if (c->spd.that.client.maskbits  < tmp->spd.that.client.maskbits) {
					dbg_md(md, "passthrough conn was a better match (%d bits versus conn %d bits) - suppressing NO_PROPSAL_CHOSEN reply",
					       tmp->spd.that.client.maskbits,
					       c->spd.that.client.maskbits);
					return NULL;
				}
			}
		}
	}
	return c;
}
