#define NEVER
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
#include <pthread.h>    /* needed for pthread_self */

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
 * A lease is an assignment of a single address from a particular pool.
 *
 * When a lease ends, if ID is NONE it is freed, othersise it linger
 * so that the same client (based on ID) will  be assigned the same address 
 * from the pool. In the future we may 
 * implement code to delete a lingering lease to free the address if there is
 * no free address in the pool.
 *
 * Life cycle:
 *
 * - created by get_addr_lease if an existing or lingering lease for the
 *   same thatid isn't found.
 *
 * - released (to linger) by linger_lease_entry. linger_lease_entry is called by
 *   rel_lease_addr.
 *
 * - current code never frees a lease but free_lease_for_index and
 *   free_lease_list could do it (LEAK!).
 */
struct lease_addr {
	u_int32_t index;        /* range start + index == IP address */
	struct id thatid;       /* from connection */

	time_t started;         /* first time it was leased to this id */

	/*
	 * 0 until linger_lease_entry is called.
	 * Then it is the time of the linger_lease_entry call.
	 * Goes back to 0 when it is re-allocated through find_lingering_lease
	 * (for the same thatid).
	 * Currently only used as if it were a bool.
	 */
	time_t ended;                   /* 0 is not yet ended; > 0 is when it ended */

	struct lease_addr *next;        /* next in pool's list of leases */
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

	DBG(DBG_CONTROL, DBG_log("addresspool free lease entry ptr %p from"
				 " the list", h));
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
 * mark a lease as ended. It lingers around.
 * But the lease isn't freed: it lingers, available to be re-activated
 * by get_addr_lease/find_lingering_lease (but only for the same thatid).
 */
static bool linger_lease_entry(struct lease_addr *head, u_int32_t i)
{
	struct lease_addr *p;

	DBG(DBG_CONTROL, DBG_log("addresspool request to free lease "
				 "index %u head %p", i, head));

	for (p = head; p != NULL; p = p->next) {
		if (p->index == i) {
			p->ended = time((time_t *)NULL);
			passert(p->ended != 0); /* 0 must be distinct */
			return FALSE;
		}
	}
	return TRUE;
}

#ifdef NEVER    /* not currently used */
static void free_lease_for_index(struct lease_addr **head, u_int32_t i)
{
	struct lease_addr **pp;
	struct lease_addr *p;

	DBG(DBG_CONTROL, DBG_log("addresspool request to free a lease "
				 "index %u head %p", i, *head));
	for (pp = head; (p = *pp) != NULL; pp = &p->next) {
		if (p->index == i) {
			DBG(DBG_CONTROL, DBG_log("addresspool freeing lease "
						 " index %u ptr %p head %p"
						 " thread id %lu",
						 i, p, head,
						 pthread_self()));
			*pp = free_lease_entry(p);
			return;
		}
	}
	passert(FALSE);
}
#endif /* NEVER */

void rel_lease_addr(const struct connection *c)
{
	u_int32_t i;    /* index within range of IPv4 address to be released */

	/* text of addresses */
	char ta_start[ADDRTOT_BUF];
	char ta_end[ADDRTOT_BUF];
	char ta_client[ADDRTOT_BUF];

	if (ip_address_family(&c->spd.that.client.addr) != AF_INET) {
		DBG(DBG_CONTROL, DBG_log(" %s: c->spd.that.client.addr af "
					 "is not AF_INET (aka IPv4 )",
					 __func__));
		return;
	}

	addrtot(&c->spd.that.client.addr, 0, ta_client, sizeof(ta_client));
	addrtot(&c->pool->start, 0, ta_start, sizeof(ta_start));
	addrtot(&c->pool->end, 0, ta_end, sizeof(ta_end));

	/* i is index of client.addr within pool's range.
	 * Using unsigned arithmetic means that if client.addr is less than
	 * start, i will wrap around to a very large value.
	 * Therefore a single test against size will indicate
	 * membership in the range.
	 */
	i = ntohl(c->spd.that.client.addr.u.v4.sin_addr.s_addr) -
	    ntohl(c->pool->start.u.v4.sin_addr.s_addr);

	if (i >= c->pool->size) {
		DBG(DBG_CONTROL,
		    DBG_log("can not free it. that.client.addr %s"
			    " in not from addresspool %s-%s",
			    ta_client, ta_start, ta_end));
		return;
	}

	/* set the lease ended  */
	if (c->spd.that.id.kind == ID_NONE) {
		free_lease_for_index(&c->pool->leases, i);
	} else if (linger_lease_entry(c->pool->leases, i)) {
		/* this should not happen. So worth logging. */
		DBG(DBG_CONTROL, DBG_log("failed to end lease "
					 "that.client.addr %s conn addresspool"
					 "%s-%s index %u size %u used %u"
					 " lingering %u",
					 ta_client, ta_start, ta_end, i,
					 c->pool->size, c->pool->used,
					 c->pool->lingering));
		return;
	}
	c->pool->lingering++;
	c->pool->used--;
	DBG(DBG_CONTROLMORE, DBG_log("ended lease %s from addresspool %s-%s "
				     "index %u. pool size %u used %u lingering %u",
				     ta_client, ta_start, ta_end, i,
				     c->pool->size, c->pool->used,
				     c->pool->lingering));

	return;
}

/*
 * return previous lease if there is one lingering for the same ID
 * but ID_NONE does not count.
 *
 * even when unique id is disabled
 * return the same INTERNAL_IP4_ADDRESS for the same id.
 * ??? Is this reasonable ??
 */
static bool find_lingering_lease(const struct connection *c,
				 u_int32_t *index /*result*/)
{
	struct lease_addr *p;
	char thatid[IDTOA_BUF];

	idtoa(&c->spd.that.id, thatid, sizeof(thatid));
	DBG(DBG_CONTROLMORE, DBG_log("in %s: find old addresspool lease for "
				     "'%s'", __func__, thatid));

	for (p = c->pool->leases; p != NULL; p = p->next) {
		if (p->thatid.kind != ID_NONE &&
		    same_id(&p->thatid, &c->spd.that.id)) {
			DBG(DBG_CONTROLMORE, {
				    uint32_t addr;
				    uint32_t addr_nw;
				    ip_address ipaddr;
				    char abuf1[ADDRTOT_BUF];

				    addr = ntohl(c->pool->start.u.v4.sin_addr.s_addr) + p->index;
				    addr_nw = htonl(addr);
				    initaddr((unsigned char *)&addr_nw,
					     sizeof(addr_nw), AF_INET, &ipaddr);
				    addrtot(&ipaddr, 0, abuf1, sizeof(abuf1));
				    DBG_log("  addresspool found lingering "
					    "address re-use address %s for "
					    "thatid '%s'", thatid, abuf1);
			    });
			*index = p->index;
			if (p->ended != 0) {
				c->pool->lingering--;
				c->pool->used++;
			}
			p->ended = 0;   /* not ended */
			return TRUE;
		}
	}
	DBG(DBG_CONTROLMORE, DBG_log("  no match found for %s", thatid));
	return FALSE;
}

err_t get_addr_lease(const struct connection *c,
		     struct internal_addr *ia /*result*/)
{
	/* return value is from 1 to size. 0 is error */
	u_int32_t i = 0;
	const u_int32_t size = c->pool->size;

	char abuf1[ADDRTOT_BUF];
	char abuf2[ADDRTOT_BUF];
	char abuf3[ADDRTOT_BUF];
	char thatid[IDTOA_BUF];

	uint32_t addr_nw;
	uint32_t addr;
	err_t e;
	bool r;

	addrtot(&c->pool->start, 0, abuf1, sizeof(abuf1));
	addrtot(&c->pool->end, 0, abuf2, sizeof(abuf2));
	addrtot(&c->spd.that.client.addr, 0, abuf3, sizeof(abuf3));
	idtoa(&c->spd.that.id, thatid, sizeof(thatid));

	DBG(DBG_CONTROL,
	    DBG_log("lease request from addresspool"
		    " %s-%s size %u reference count %u thread"
		    " id %lu thatid '%s' that.client.addr %s",
		    abuf1, abuf2, size,
		    c->pool->refcnt, pthread_self(), thatid, abuf3));

	r = find_lingering_lease(c, &i);
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
				    "addresspool %s-%s size %u "
				    "reference count %u ",
				    abuf1, abuf2, size,
				    c->pool->refcnt));
			return "no free address in addresspool";
		}
		i = candidate;
		a = alloc_thing(struct lease_addr, "address lease entry");
		a->index = candidate;
		a->started = time((time_t *)NULL);
		a->ended = 0;   /* not ended */

		duplicate_id(&a->thatid, &c->spd.that.id);
		idtoa(&a->thatid, thatid, sizeof(thatid));

		a->next = p;
		*pp = a;
		c->pool->used++;
	}

	addr = ntohl(c->pool->start.u.v4.sin_addr.s_addr) + i;
	addr_nw = htonl(addr);
	e = initaddr((unsigned char *)&addr_nw, sizeof(addr_nw),
		     AF_INET, &ia->ipaddr);

	DBG(DBG_CONTROLMORE, DBG_log("%s lease %s from addresspool %s-%s. "
				     "index %u size %u used %u lingering %u "
				     "thatid '%s'", r ? "re-use" : "new",
				     (addrtot(&ia->ipaddr, 0, abuf3,
					      sizeof(abuf3)), abuf3),
				     abuf1, abuf2, i, size,
				     c->pool->used,
				     c->pool->lingering, thatid));
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
			*pp = p->next;  /* unlink pool */
			free_lease_list(&pool->leases);
			pfree(pool);
			return;
		}
	}
	DBG_log("%s addresspool %p not found in list of pools", __func__,
		pool);
	return;
}

#ifdef NEVER    /* not currently used */
static void free_addresspools(void)
{
	while (pluto_pools != NULL)
		free_addresspool(pluto_pools);
}
#endif /* NEVER */

void unreference_addresspool(struct ip_pool *pool)
{
	if (pool == NULL) {
		return;
	}
	if (pool->refcnt > 0) {
		pool->refcnt--;
		if (pool->refcnt == 0) {
			DBG(DBG_CONTROLMORE,
					DBG_log("freeing memory for addresspool"
						" ptr %p", pool));
			free_addresspool(pool);
		}
	} else {
		libreswan_log("WARNING: %s can't unreference pool "
				"refcnt %p refcnt %u", __func__, pool,
				pool->refcnt);
	}
}

static void reference_addresspool(struct ip_pool *pool)
{
	pool->refcnt++;
}

/* memcmp, strcmp and friends don't promise the exact value returned.
 * unitize(i) yields a value with the same sign as i but always -1, 0, or 1.
 * Think of it as putting a *cmp result in canonical form.
 */
static int unitize(int i)
{
	return i < 0 ? -1 : i > 0 ? 1 : 0;
}

/* finds an ip_pool that has exactly matching bounds */
static struct ip_pool *find_addresspool(const ip_range *pool_range,
					struct ip_pool **const head)
{
	struct ip_pool *h;

	for (h = *head; h != NULL; h = h->next) {
		int start_cmp =
			unitize(ip_address_cmp(&pool_range->start, &h->start));
		int end_cmp =
			unitize(ip_address_cmp(&pool_range->end, &h->end));

		bool match = start_cmp == 0 && end_cmp == 0;

		/* Test for inexact overlap.
		 * (If we don't care then unitizing is not needed.)
		 *
		 * Case analysis:
		 * both -1: new pool is before h's range
		 * both 0: new pool is the same as h's range
		 * both 1: new pool is after h's range
		 * otherwise: some messy overlap.
		 *
		 * Alternative test that does not need unitizing
		 * (avoiding overflow is a challenge):
		 *	!match && start_cmp * end_cmp <= 0
		 */
		char abuf1[ADDRTOT_BUF];
		char abuf2[ADDRTOT_BUF];
		char abuf3[ADDRTOT_BUF];
		char abuf4[ADDRTOT_BUF];
		addrtot(&pool_range->start, 0, abuf1,
			sizeof(abuf1));
		addrtot(&pool_range->end, 0, abuf2,
			sizeof(abuf2));
		addrtot(&pool_range->start, 0,
			abuf3, sizeof(abuf3));
		addrtot(&pool_range->end, 0,
			abuf4, sizeof(abuf4));

		DBG(DBG_CONTROLMORE, {
			    DBG_log("%s addresspool %s-%s%s%s",
				    match ? "existing" : "new",
				    abuf1, abuf2,
				    start_cmp == 0 ? " same start" : "",
				    end_cmp == 0 ? " same end" : "");
		    });
		if (start_cmp != end_cmp) {
			libreswan_log("WARNING: new addresspool %s-%s "
				      "INEXACTLY OVERLAPPS with existing %s-%s "
				      "an IP address may be leased more than "
				      "once", abuf1, abuf2, abuf3,
				      abuf4);
		}
		if (match)
			return h;
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
	struct ip_pool *pool;

	pool = find_addresspool(pool_range, head);
	if (pool != NULL) {
		/* re-use existing pool */
		reference_addresspool(pool);
		DBG(DBG_CONTROLMORE, {
			    char abuf1[ADDRTOT_BUF];
			    char abuf2[ADDRTOT_BUF];

			    addrtot(&pool->start, 0, abuf1, sizeof(abuf1));
			    addrtot(&pool->end, 0, abuf2, sizeof(abuf2));
			    DBG_log("addresspool %s-%s exists ref count %u "
				    "used %u size %u ptr %p re-use it",
				    abuf1, abuf2, pool->refcnt, pool->used,
				    pool->size, pool);
		    });

		return pool;
	}

	/* make a new pool */

	struct ip_pool *p = alloc_thing(struct ip_pool, "addresspool entry");

	p->refcnt = 0;
	reference_addresspool(p);
	p->start = pool_range->start;
	p->end = pool_range->end;
	p->size = ntohl(p->end.u.v4.sin_addr.s_addr) -
		  ntohl(p->start.u.v4.sin_addr.s_addr) + 1;
	p->used = 0;
	p->lingering = 0;

	DBG(DBG_CONTROLMORE, {
		    char abuf1[ADDRTOT_BUF];
		    char abuf2[ADDRTOT_BUF];

		    addrtot(&p->start, 0, abuf1, sizeof(abuf1));
		    addrtot(&p->end, 0, abuf2, sizeof(abuf2));
		    DBG_log("add new addresspool to global pools %s-%s "
			    "size %d ptr %p",
			    abuf1, abuf2, p->size, p);
	    });
	p->leases = NULL;
	p->next = *head;
	*head = p;
	return p;
}
