/*
 * addresspool management functions used with left/rightaddresspool= option.
 * Currently used for IKEv1 XAUTH/ModeConfig options if we are an XAUTH server.
 * And in IKEv2 to respond to Configuration Payload (CP) request.
 *
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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

/* Address Pools
 *
 * With XAUTH/CP, we need a way to allocate an address to a client.
 * This address must be unique on our system.
 * The pools of addresses to be used are declared in our config file.
 * Each connection may specify a pool as a range of IPv4 addresses.
 * All pools must be non-everlapping, but each pool may be
 * used for more than one connection.
 */

#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "connections.h"
#include "defs.h"
#include "constants.h"
#include "addresspool.h"
#include "monotime.h"
#include "ip_address.h"


/*
 * A pool is a range of IPv4 addresses to be individually allocated.
 * A connection may have a pool.
 * That pool may be shared with other connections (hence the reference count).
 *
 * A pool has a linked list of leases.
 * This list is in monotonically increasing order.
 */
struct ip_pool {
	unsigned pool_refcount;	/* reference counted! */
	ip_range r;
	uint32_t size;		/* number of addresses within range */
	uint32_t used;		/* number of addresses in use (includes lingering) */
	uint32_t lingering;	/* number of lingering addresses */
	struct lease_addr *leases;	/* monotonically increasing index values */

	struct ip_pool *next;	/* next pool */
};

/*
 * A lease is an assignment of a single address from a particular pool.
 *
 * Leases are shared between appropriate connections.
 *
 * Because leases are shared, they are reference-counted.
 * (Since we don't (yet?) free leases that could be shared,
 * we don't actually need reference counting.)
 *
 * When a lease ends, if it could not be shared, it is freed.
 * Otherwise it "lingers" so that the same client (based on ID) can later
 * be assigned the same address from the pool.
 *
 * In the future we may implement code to delete a lingering lease to free
 * the address if there is no free address in the pool.
 *
 * Life cycle:
 *
 * - created by lease_an_address if an existing or lingering lease for the
 *   same thatid isn't found.
 *
 * - released (to linger or freed) by rel_lease_addr.
 *
 * - current code never frees a lease that could be shared.
 *   ??? This constitutes a leak.
 */

static bool can_share_lease(const struct connection *c)
{
	/*
	 * Cannot share with PSK - it either uses GroupID or
	 * a non-unique ID_IP due to clients using pre-NAT IP address
	 */
	if (((c->policy & POLICY_PSK) != LEMPTY) || c->spd.that.authby == AUTH_PSK)
		return FALSE;

	/* Cannot share with NULL authentication */
	if (((c->policy & POLICY_AUTH_NULL) != LEMPTY) || c->spd.that.authby == AUTH_NULL)
		return FALSE;

	/* Cannot share NULL/NONE ID. Also cannot share ID_IP due to NAT and dynamic IP */
	if (c->spd.that.id.kind == ID_NULL || c->spd.that.id.kind == ID_NONE ||
		c->spd.that.id.kind == ID_IPV4_ADDR || c->spd.that.id.kind == ID_IPV6_ADDR)
			return FALSE;

	/* If uniqueids=false - this can mean multiple clients on the same ID & CERT */
	if (!uniqueIDs)
		return FALSE;

	DBG(DBG_CONTROL, DBG_log("addresspool can share this lease"));
	return TRUE;
}

struct lease_addr {
	uint32_t index;	/* range start + index == IP address */
	struct id thatid;	/* from connection */
	unsigned refcnt;	/* reference counted */
	monotime_t lingering_since;	/* when did this begin to linger */

	struct lease_addr *next;	/* next in pool's list of leases */
};

/*
 * head of chained addresspool list
 * addresspool come from ipsec.conf or whacked connection.
 */
static struct ip_pool *pluto_pools = NULL;

/* note: free_lease_entry returns a pointer to h's list successor.
 * The caller MUST use this to replace the linked list's pointer to h.
 */
static struct lease_addr *free_lease_entry(struct lease_addr *h) MUST_USE_RESULT;

static struct lease_addr *free_lease_entry(struct lease_addr *h)
{
	struct lease_addr *next = h->next;

	DBG(DBG_CONTROL, DBG_log("addresspool free lease entry ptr %p refcnt %u",
		h, h->refcnt));

	free_id_content(&h->thatid);
	pfree(h);
	return next;
}

static void free_lease_list(struct lease_addr **head)
{
	DBG(DBG_CONTROL,
	    DBG_log("%s: addresspool free the lease list ptr %p",
		    __func__, *head));
	while (*head != NULL)
		*head = free_lease_entry(*head);
}

/*
 *search for a lease in a pool with index i
 *
 * tricky: returns a pointer to the pointer that connects the lease.
 * This allows efficient removal.
 * It the index isn't found, NULL is returned (not a pointer to the
 * pointer to NULL).
 */

static struct lease_addr **ref_to_lease(struct ip_pool *pool, uint32_t i) {
	struct lease_addr **pp;
	struct lease_addr *p;

	for (pp = &pool->leases; (p = *pp) != NULL; pp = &p->next)
		if (p->index == i)
			return pp;
	return NULL;
}

/*
 * mark a lease as ended.
 *
 * If the ID is distinctive and uniqueid is set, the lease "lingers"
 * so that the same client can be reassigned the same address.
 * A lingering lease is available to be re-activated
 * by lease_an_address/find_lingering_lease to the same thatid when uniqueid is
 * set.
 *
 * If uniqueIDs is set or thatid is ID_NONE, we don't know how to share.
 * In that case, we do free the lease since that ID isn't distinctive.
 * Note: without sharing the refcnt should be 1.
 */

void rel_lease_addr(struct connection *c)
{
	struct ip_pool *pool = c->pool;
	uint32_t i;	/* index within range of IPv4 address to be released */
	unsigned refcnt;	/* for DBG logging */
	const char *story;	/* for DBG logging */

	if (!c->spd.that.has_lease)
		return; /* it is not from the addresspool to free */

	passert(addrtypeof(&c->spd.that.client.addr) == AF_INET);

	/* i is index of client.addr within pool's range.
	 * Using unsigned arithmetic means that if client.addr is less than
	 * start, i will wrap around to a very large value.
	 * Therefore a single test against size will indicate
	 * membership in the range.
	 */
	i = ntohl(c->spd.that.client.addr.u.v4.sin_addr.s_addr) -
	    ntohl(pool->r.start.u.v4.sin_addr.s_addr);

	passert(i < pool->size);

	{
		struct lease_addr **pp = ref_to_lease(pool, i);
		struct lease_addr *p;

		passert(pp != NULL);	/* not found */

		p = *pp;

		if (can_share_lease(c)) {
			/* we could share, so leave lease lingering */
			story = "left (shared)";
			passert(p->refcnt > 0);
			p->refcnt--;
			if (p->refcnt == 0) {
				story = "left (to linger)";
				pool->lingering++;
				p->lingering_since = mononow();
			}
			refcnt = p->refcnt;
		} else {
			/* cannot share: free it */
			story = "freed";
			passert(p->refcnt == 1);
			p->refcnt--;
			refcnt = p->refcnt;
			*pp = free_lease_entry(p);
			pool->used--;
		}
	}

	c->spd.that.has_lease = FALSE;

	DBG(DBG_CONTROLMORE, {
		/* text of addresses */
		char ta_range[RANGETOT_BUF];
		ipstr_buf b;
		rangetot(&pool->r, 0, ta_range, sizeof(ta_range));
		DBG_log("%s lease refcnt %u %s from addresspool %s index=%u. pool size %u used %u lingering=%u address",
				story,
				refcnt,
				ipstr(&c->spd.that.client.addr, &b),
				ta_range, i,
				pool->size, pool->used,
				pool->lingering);
	});
}

/*
 * return previous lease if there is one lingering for the same ID
 */
static bool share_lease(const struct connection *c,
			uint32_t *index /*result*/)
{
	struct lease_addr *p;
	bool r = FALSE;

	if (!can_share_lease(c)) {
		DBG(DBG_CONTROL, DBG_log("cannot share a lease, find a new lease IP"));
		return FALSE;
	}

	for (p = c->pool->leases; p != NULL; p = p->next) {
		if (same_id(&p->thatid, &c->spd.that.id)) {
			*index = p->index;
			if (p->refcnt == 0) {
				c->pool->lingering--;
				c->pool->used++;
			}
			p->refcnt++;
			r = TRUE;
			break;
		}
	}

	DBG(DBG_CONTROLMORE, {
		char thatid[IDTOA_BUF];

		idtoa(&c->spd.that.id, thatid, sizeof(thatid));
		if (r) {
			ipstr_buf b;
			ip_address ipaddr;
			uint32_t addr = ntohl(c->pool->r.start.u.v4.sin_addr.s_addr) + *index;
			uint32_t addr_nw = htonl(addr);

			initaddr((unsigned char *)&addr_nw,
				sizeof(addr_nw), AF_INET, &ipaddr);

			DBG_log("in %s: found a lingering addresspool lease %s refcnt %d for '%s'",
				__func__,
				ipstr(&ipaddr, &b),
				p->refcnt,
				thatid);
		} else {
			DBG_log("in %s: no lingering addresspool lease for '%s'",
				__func__,
				thatid);
		}
	});

	return r;
}

err_t lease_an_address(const struct connection *c, const struct state *st,
		     ip_address *ipa /*result*/)
{
	/*
	 * index within address range
	 * Initialized just to silence GCC.
	 */
	uint32_t i = 0;
	bool s;

	DBG(DBG_CONTROL, {
		char rbuf[RANGETOT_BUF];
		char thatidbuf[IDTOA_BUF];
		ipstr_buf b;

		rangetot(&c->pool->r, 0, rbuf, sizeof(rbuf));
		idtoa(&c->spd.that.id, thatidbuf, sizeof(thatidbuf));
		if (st->st_xauth_username != NULL) {
			/* force different leases for different xauth users */
			jam_str(thatidbuf, sizeof(thatidbuf), st->st_xauth_username);
		}

		/* ??? what is that.client.addr and why do we care? */
		DBG_log("request lease from addresspool %s reference count %u thatid '%s' that.client.addr %s",
			rbuf, c->pool->pool_refcount, thatidbuf,
			ipstr(&c->spd.that.client.addr, &b));
	});

	s = share_lease(c, &i);
	if (!s) {
		/*
		 * cannot find or cannot share an existing lease:
		 * allocate a new one
		 */
		const uint32_t size = c->pool->size;
		struct lease_addr **pp;
		struct lease_addr *p;
		struct lease_addr *ll = NULL;	/* longest lingerer */
		bool can_share = can_share_lease(c);

		for (pp = &c->pool->leases; (p = *pp) != NULL; pp = &p->next) {
			/* check that list of leases is
			 * monotonically increasing.
			 */
			passert(p->index >= i);
			if (p->index > i) {
				break;
			}
			/* remember the longest lingering lease found */
			if (can_share && p->refcnt == 0 &&
			    (ll == NULL ||
			     monobefore(ll->lingering_since, p->lingering_since)))
				ll = p;
			/* Subtle point: this addition won't overflow.
			 * 0.0.0.0 cannot be in a range
			 * so the size will be less than 2^32.
			 * No index can equal size
			 * so i cannot exceed it.
			 */
			i = p->index + 1;
		}

		if (i < size) {
			/* we can allocate a new address and lease */
			struct lease_addr *a = alloc_thing(struct lease_addr, "address lease entry");

			a->index = i;
			a->refcnt = 1;
			c->pool->used++;

			duplicate_id(&a->thatid, &c->spd.that.id);

			a->next = p;
			*pp = a;

			DBG(DBG_CONTROLMORE,
				DBG_log("New lease from addresspool index %u", i));
		} else if (ll != NULL) {
			/* we take over this lingering lease */
			DBG(DBG_CONTROLMORE, {
				char thatidbuf[IDTOA_BUF];

				idtoa(&ll->thatid, thatidbuf, sizeof(thatidbuf));
				DBG_log("grabbed lingering lease index %u from %s",
					i, thatidbuf);
			});
			duplicate_id(&ll->thatid, &c->spd.that.id);
			c->pool->lingering--;
			ll->refcnt++;
			i = ll->index;
		} else {
			DBG(DBG_CONTROL,
			    DBG_log("no free address within pool; size %u, used %u, lingering %u",
				size, c->pool->used, c->pool->lingering));
			passert(size == c->pool->used);
			return "no free address in addresspool";
		}
	}

	/* convert index i in range to an IP_address */
	{
		uint32_t addr = ntohl(c->pool->r.start.u.v4.sin_addr.s_addr) + i;
		uint32_t addr_nw = htonl(addr);
		err_t e = initaddr((unsigned char *)&addr_nw, sizeof(addr_nw),
			     AF_INET, ipa);

		if (e != NULL)
			return e;
	}
	DBG(DBG_CONTROL, {
		char rbuf[RANGETOT_BUF];
		char thatidbuf[IDTOA_BUF];
		ipstr_buf a;
		ipstr_buf l;

		rangetot(&c->pool->r, 0, rbuf, sizeof(rbuf));
		idtoa(&c->spd.that.id, thatidbuf, sizeof(thatidbuf));

		DBG_log("%s lease %s from addresspool %s to that.client.addr %s thatid '%s'",
			s ? "re-use" : "new",
			ipstr(ipa, &l),
			rbuf,
			ipstr(&c->spd.that.client.addr, &a),
			thatidbuf);
	});

	return NULL;
}

static void free_addresspool(struct ip_pool *pool)
{
	struct ip_pool **pp;
	struct ip_pool *p;

	/* search for pool in list of pools so we can unlink it */
	if (pool == NULL)
		return;

	for (pp = &pluto_pools; (p = *pp) != NULL; pp = &p->next) {
		if (p == pool) {
			*pp = p->next;	/* unlink pool */
			free_lease_list(&pool->leases);
			pfree(pool);
			return;
		}
	}
	DBG_log("%s addresspool %p not found in list of pools", __func__,
		pool);
}

void unreference_addresspool(struct connection *c)
{
	struct ip_pool *pool = c->pool;

	DBG(DBG_CONTROLMORE, DBG_log("unreference addresspool of conn %s[%lu] kind %s refcnt %u",
				c->name, c->instance_serial,
				enum_name(&connection_kind_names,
					c->kind), pool->pool_refcount));

	passert(pool->pool_refcount > 0);

	pool->pool_refcount--;
	if (pool->pool_refcount == 0) {
		DBG(DBG_CONTROLMORE,
				DBG_log("freeing memory for addresspool ptr %p",
					pool));
		free_addresspool(pool);
	}

	c->pool = NULL;
}

void reference_addresspool(struct connection *c)
{
	struct ip_pool *pool = c->pool;

	DBG(DBG_CONTROLMORE, DBG_log("reference addresspool of conn %s[%lu] kind %s refcnt %u",
				c->name, c->instance_serial,
				enum_name(&connection_kind_names,
					c->kind), pool->pool_refcount));
	pool->pool_refcount++;
}

/*
 * Finds an ip_pool that has exactly matching bounds.
 * If a pool overlaps, an error is logged AND returned
 * *pool is set to the entry found; NULL if none found.
 */
err_t find_addresspool(const ip_range *pool_range, struct ip_pool **pool)
{
	struct ip_pool *h;

	*pool = NULL;	/* nothing found (yet) */
	for (h = pluto_pools; h != NULL; h = h->next) {
		const ip_range *a = pool_range;
		const ip_range *b = &h->r;

		int sc = addrcmp(&a->start, &b->start);

		if (sc == 0 && addrcmp(&a->end, &b->end) == 0) {
			/* exact match */
			*pool = h;
			break;
		} else if (sc < 0 ? addrcmp(&a->end, &b->start) < 0 :
				    addrcmp(&a->start, &b->end) > 0) {
			/* before or after */
		} else {
			/* overlap */
			char prbuf[RANGETOT_BUF];
			char hbuf[RANGETOT_BUF];

			rangetot(pool_range, 0, prbuf, sizeof(prbuf));
			rangetot(&h->r, 0, hbuf, sizeof(hbuf));
			loglog(RC_CLASH,
				"ERROR: new addresspool %s INEXACTLY OVERLAPS with existing one %s.",
					prbuf, hbuf);
			return "ERROR: partial overlap of addresspool";
		}
	}
	return NULL;
}

/*
 * the caller must enforce the following:
 * - Range must not include 0.0.0.0
 * - Only IPv4 allowed.
 * - The range must be non-empty
 */
struct ip_pool *install_addresspool(const ip_range *pool_range)
{
	struct ip_pool **head = &pluto_pools;
	struct ip_pool *p;
	err_t ugh = find_addresspool(pool_range, &p);

	if (ugh != NULL) {
		/* some problem: refuse to install bad addresspool */
		/* ??? Assume diagnostic already logged? */
	} else if (p != NULL) {
		/* re-use existing pool p */
		DBG(DBG_CONTROLMORE, {
			char rbuf[RANGETOT_BUF];

			rangetot(&p->r, 0, rbuf, sizeof(rbuf));
			DBG_log("re-use addresspool %s exists ref count %u used %u size %u ptr %p re-use it",
				rbuf, p->pool_refcount, p->used, p->size, p);
		});
	} else {
		/* make a new pool */
		p = alloc_thing(struct ip_pool, "addresspool entry");

		p->pool_refcount = 0;
		p->r = *pool_range;
		p->size = ntohl(p->r.end.u.v4.sin_addr.s_addr) -
			  ntohl(p->r.start.u.v4.sin_addr.s_addr) + 1;
		p->used = 0;
		p->lingering = 0;

		DBG(DBG_CONTROLMORE, {
			char rbuf[RANGETOT_BUF];

			rangetot(&p->r, 0, rbuf, sizeof(rbuf));
			DBG_log("add new addresspool to global pools %s size %d ptr %p",
				rbuf, p->size, p);
		});
		p->leases = NULL;
		p->next = *head;
		*head = p;
	}
	return p;
}
