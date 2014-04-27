/*
 * addresspool management functions used with left/rightaddresspool= option.
 * Currently used for IKEv1 XAUTH/ModeConfig options if we are an XAUTH server.
 *
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

/* Address Pools
 *
 * With XAUTH, we need a way to allocate an address to a client.
 * This address must be unique on our system.
 * The pools of addresses to be used are declared in our config file.
 * Each connection may specify a pool as a range of IPv4 addresses.
 * All pools must be non-everlapping, but each pool may be
 * used for more than one connection.
 */

#include <time.h>
#include <pthread.h>	/* needed for pthread_self */

#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "connections.h"
#include "defs.h"
#include "lswalloc.h"
#include "constants.h"
#include "demux.h"
#include "packet.h"
#include "xauth.h"
#include "addresspool.h"


/*
 * A pool is a range of IPv4 addresses to be individually allocated.
 * A connection may have a pool.
 * That pool may be shared with other connections (hence the reference count).
 *
 * A pool has a linked list of leases.
 * This list is in monotonically increasing order.
 */
struct ip_pool {
	unsigned refcnt;	/* reference counted! */
	ip_range r;
	u_int32_t size;		/* number of addresses within range */
	u_int32_t used;		/* number of addresses in use */
	u_int32_t lingering;	/* number of lingering addresses */
	struct lease_addr *leases;	/* monotonically increasing index values */

	struct ip_pool *next;	/* next pool */
};

/*
 * A lease is an assignment of a single address from a particular pool.
 *
 * When a lease ends, if ID is NONE it is freed, otherwise it linger
 * so that the same client (based on ID) will be assigned the same address
 * from the pool.
 *
 * In the future we may implement code to delete a lingering lease to free
 * the address if there is no free address in the pool.
 *
 * Life cycle:
 *
 * - created by get_addr_lease if an existing or lingering lease for the
 *   same thatid isn't found.
 *
 * - released (to linger) by linger_lease_entry. linger_lease_entry is called by
 *   rel_lease_addr.
 *
 * - current code never frees a lease (but free_lease_for_index and
 *   free_lease_list could do it).  ??? This constitutes a leak.
 */
struct lease_addr {
	u_int32_t index;	/* range start + index == IP address */
	struct id thatid;	/* from connection */
	unsigned refcnt;	/* reference counted */

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
static struct lease_addr *free_lease_entry(struct lease_addr *h)
{
	struct lease_addr *next = h->next;

	DBG(DBG_CONTROL, DBG_log("addresspool free lease entry ptr %p refcnt"
			        " %u", h, h->refcnt));

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

static struct lease_addr **ref_to_lease(struct ip_pool *pool, u_int32_t i) {
	struct lease_addr **pp;
	struct lease_addr *p;

	for (pp = &pool->leases; (p = *pp) != NULL; pp = &p->next)
		if (p->index == i)
			return pp;
	return NULL;
}

/*
 * mark a lease as ended.
 * If the ID is distinctive and uniqueid is set, the lease "lingers"
 * so that the same client can be reassigned the same address.
 * But the lease isn't freed: it lingers, available to be re-activated
 * by get_addr_lease/find_lingering_lease to the same thatid when uniqueid is
 * set
 *
 * If uniqueid is set, thatid is ID_NONE and refcnt is zero, we do free the
 * lease since that ID isn't distinctive.
 */
static bool end_lease(struct ip_pool *pool, u_int32_t i, bool linger)
{
	struct lease_addr **pp = ref_to_lease(pool, i);
	struct lease_addr *p;
	bool l;

	passert(pp != NULL);	/* not found */

	p = *pp;

	passert(p->refcnt > 0);
	p->refcnt--;
	l = p->refcnt;

	if (p->refcnt == 0) {
		if (linger && uniqueIDs) {
			pool->lingering++;
		} else {
			linger = 0;
			*pp = free_lease_entry(p);	/* free it */
			pool->used--;
		}
	}

	return l;
}

void rel_lease_addr(struct connection *c)
{
	u_int32_t i;	/* index within range of IPv4 address to be released */

	/* text of addresses */
	char ta_client[ADDRTOT_BUF];
	char ta_range[RANGETOT_BUF];
	int l;

	if (!c->spd.that.has_lease)
		return; /* it is not from the addresspool to free */

	passert(addrtypeof(&c->spd.that.client.addr) == AF_INET);

	addrtot(&c->spd.that.client.addr, 0, ta_client, sizeof(ta_client));
	rangetot(&c->pool->r, 0, ta_range, sizeof(ta_range));

	/* i is index of client.addr within pool's range.
	 * Using unsigned arithmetic means that if client.addr is less than
	 * start, i will wrap around to a very large value.
	 * Therefore a single test against size will indicate
	 * membership in the range.
	 */
	i = ntohl(c->spd.that.client.addr.u.v4.sin_addr.s_addr) -
	    ntohl(c->pool->r.start.u.v4.sin_addr.s_addr);

	passert(i < c->pool->size);

	/* set the lease ended */
	l = end_lease(c->pool, i, c->spd.that.id.kind != ID_NONE);
	c->spd.that.has_lease = FALSE;

	DBG(DBG_CONTROLMORE, DBG_log("%s lease %s from addresspool "
				"%s refcnt=%u index=%u. pool size %u used "
				"%u lingering=%u address",
				(l && uniqueIDs) ? "lingering" :
				uniqueIDs ? "lingering" : "freed",
				ta_client, ta_range, l, i,
				c->pool->size, c->pool->used,
				c->pool->lingering));
	}

/*
 * return previous lease if there is one lingering for the same ID
 * but ID_NONE does not count.
 */
static bool revive_lingering_lease(const struct connection *c,
				 u_int32_t *index /*result*/)
{
	struct lease_addr *p;
	bool r = FALSE;

	if (c->spd.that.id.kind == ID_NONE)
		return FALSE;

	for (p = c->pool->leases; p != NULL; p = p->next) {
		if (same_id(&p->thatid, &c->spd.that.id)) {
			*index = p->index;
			p->refcnt++;
			if (p->refcnt == 1) {
				c->pool->lingering--;
				c->pool->used++;
			}
			r = TRUE;
			break;
		}
	}

	DBG(DBG_CONTROLMORE, {
			char thatid[IDTOA_BUF];
			char abuf[ADDRTOT_BUF];
			ip_address ipaddr;
			uint32_t addr;
			uint32_t addr_nw;
			char buf[128];

			if (r) {
				addr = ntohl(c->pool->r.start.u.v4.sin_addr.s_addr) + *index;
				addr_nw = htonl(addr);
				initaddr((unsigned char *)&addr_nw,
					sizeof(addr_nw), AF_INET, &ipaddr);
				addrtot(&ipaddr, 0, abuf, sizeof(abuf));
				snprintf(buf, sizeof(buf), " refcnt %d",
					p->refcnt);
			}
			idtoa(&c->spd.that.id, thatid, sizeof(thatid));
			DBG_log("in %s: %s lingering addresspool lease "
				"%s %s for '%s'", __func__,
				r ? "found a" : "no",
				r ? abuf : "", r ? buf : "", thatid);
			});

	return r;
}

err_t get_addr_lease(const struct connection *c,
		     struct internal_addr *ia /*result*/)
{
	/* return value is from 1 to size. 0 is error */
	u_int32_t i = 0;
	const u_int32_t size = c->pool->size;

	char rbuf[RANGETOT_BUF];
	char thatidbuf[IDTOA_BUF];

	err_t e;
	bool r = FALSE;

	rangetot(&c->pool->r, 0, rbuf, sizeof(rbuf));
	idtoa(&c->spd.that.id, thatidbuf, sizeof(thatidbuf));

	DBG(DBG_CONTROL, {
		char abuf[ADDRTOT_BUF];
		addrtot(&c->spd.that.client.addr, 0, abuf, sizeof(abuf));
		DBG_log("lease request from addresspool"
			" %s size %u reference count %u thread"
			" id %lu thatid '%s' that.client.addr %s",
			rbuf, size,
			c->pool->refcnt, pthread_self(), thatidbuf, abuf);
	});

	if(uniqueIDs)
		r = revive_lingering_lease(c, &i);
	if (!r) {
		/* allocate a new lease */
		struct lease_addr **head = &c->pool->leases;
		struct lease_addr **pp;
		struct lease_addr *p;
		u_int32_t candidate = 0;
		struct lease_addr *a;

		for (pp = head; (p = *pp) != NULL; pp = &p->next) {
			/* check that list of leases is
			 * monotonically increasing.
			 */
			passert(p->index >= candidate);
			if (p->index > candidate)
				break;
			/* Subtle point: this addition won't overflow.
			 * 0.0.0.0 cannot be in a range
			 * so the size will be less than 2^32.
			 * No index can equal size
			 * so candidate cannot exceed it.
			 */
			candidate = p->index + 1;
		}

		if (candidate >= size) {
			DBG(DBG_CONTROL,
			    DBG_log("can't lease a new address from "
				    "addresspool %s size %u "
				    "reference count %u ",
				    rbuf, size,
				    c->pool->refcnt));
			return "no free address in addresspool";
		}
		i = candidate;
		a = alloc_thing(struct lease_addr, "address lease entry");
		a->index = candidate;
		a->refcnt = 1;
		c->pool->used++;

		duplicate_id(&a->thatid, &c->spd.that.id);
		idtoa(&a->thatid, thatidbuf, sizeof(thatidbuf));

		a->next = p;
		*pp = a;
	}

	{
		uint32_t addr = ntohl(c->pool->r.start.u.v4.sin_addr.s_addr) + i;
		uint32_t addr_nw = htonl(addr);

		e = initaddr((unsigned char *)&addr_nw, sizeof(addr_nw),
			     AF_INET, &ia->ipaddr);
	}

	DBG(DBG_CONTROLMORE, {
		char abuf[ADDRTOT_BUF];

		addrtot(&ia->ipaddr, 0, abuf, sizeof(abuf));
		DBG_log("%s lease %s from addresspool %s. index %u size %u used %u lingering %u thatid '%s'",
			r ? "re-use" : "new",
			abuf,
			rbuf, i, size,
			c->pool->used,
			c->pool->lingering, thatidbuf);
	});
	return e;
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

	if (pool == NULL)
		return;

	DBG(DBG_CONTROLMORE, DBG_log("unreference addresspool of conn "
				"%s [%lu] kind %s refcnt %u",
				c->name, c->instance_serial,
				enum_name(&connection_kind_names,
					c->kind), pool->refcnt));

	passert(pool->refcnt > 0);

	pool->refcnt--;
	if (pool->refcnt == 0) {
		DBG(DBG_CONTROLMORE,
				DBG_log("freeing memory for addresspool"
					" ptr %p", pool));
		free_addresspool(pool);
	}

	c->pool = NULL;
}

static void reference_addresspool(struct ip_pool *pool)
{
	pool->refcnt++;
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
			libreswan_log("ERROR: new addresspool %s "
					"INEXACTLY OVERLAPS with existing one %s.",
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
		reference_addresspool(p);
		DBG(DBG_CONTROLMORE, {
			char rbuf[RANGETOT_BUF];

			rangetot(&p->r, 0, rbuf, sizeof(rbuf));
			DBG_log("re-use addresspool %s exists ref count "
				"%u used %u size %u ptr %p re-use it",
				rbuf, p->refcnt, p->used, p->size,
				p);
		});
	} else {
		/* make a new pool */
		p = alloc_thing(struct ip_pool, "addresspool entry");

		p->refcnt = 0;
		reference_addresspool(p);
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
