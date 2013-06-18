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

static void free_remembered_addresspools(void);
static void free_addresspools(struct ip_pool **pools);
static void free_addresspool(struct ip_pool *pool);
static struct ip_pool *reference_addresspool(struct  ip_pool *pool);
static struct lease_addr *free_lease_entry(struct lease_addr *h);
static int free_lease(struct lease_addr **head, u_int32_t lease);
static void free_lease_list(struct lease_addr **head);
static struct ip_pool *find_addresspool(const ip_range *pool_range,
					struct ip_pool **head);
static bool  find_last_lease(struct connection *c, u_int32_t *index);
static int rel_lease_entry(struct lease_addr **head, u_int32_t lease);

/* root of chained addresspool  list */
struct ip_pool *pluto_pools = NULL; /* addresspool from ipsec.onf */

static void free_lease_list(struct lease_addr **head)
{
	DBG(DBG_CONTROL,
	    DBG_log("%s:%d addresspool free the lease list ptr %p",
		    __func__, __LINE__, *head));
	while (*head != NULL)
		*head =  free_lease_entry(*head);
}

struct lease_addr *free_lease_entry(struct lease_addr *h)
{
	struct lease_addr *next = h->next;

	DBG(DBG_CONTROL, DBG_log("addresspool free lease entry ptr %p from"
				 " the list", h));
	free_id_content(&h->thatid);
	pfreeany(h);
	return next;
}
static int rel_lease_entry(struct lease_addr **head, u_int32_t lease)
{
	struct lease_addr **pp = head;
	struct lease_addr *p;

	DBG(DBG_CONTROL, DBG_log("addresspool request to free lease "
				 "index %u head %p", lease, *head));

	while ((p = *pp) != NULL) {
		if (p->index == lease) {
			p->ends = time((time_t *)NULL);
			return FALSE;
		}
		pp = &p->next;
	}
	return TRUE;
}

int free_lease(struct lease_addr **head, u_int32_t lease)
{
	struct lease_addr **pp = head;
	struct lease_addr *p_prev = *head;
	struct lease_addr *p;

	DBG(DBG_CONTROL, DBG_log("addresspool request to free a lease "
				 "index %u head %p", lease, *head));
	while ((p = *pp) != NULL) {
		if (p->index == lease) {
			if (p_prev == p)
				*head = p->next;
			else
				p_prev->next = p->next;
			p->index = 0;
			DBG(DBG_CONTROL, DBG_log("addresspool freeing lease "
						 " index %u ptr %p head %p"
						 " p_prev %p thread id %lu",
						 lease, p, head, p_prev,
						 pthread_self()));
			pfreeany(p);

			return 0;
		}
		p_prev = p;
		pp = &p->next;
	}
	return TRUE;
}

int rel_lease_addr(struct connection *c)
{
	u_int32_t a;
	u_int32_t i;
	u_int32_t a_s;
	u_int32_t a_e;
	char abuf1[ADDRTOT_BUF];
	char abuf2[ADDRTOT_BUF];
	char abuf3[ADDRTOT_BUF];

	if (ip_address_family(&c->spd.that.client.addr) != AF_INET) {
		DBG(DBG_CONTROL, DBG_log(" %s:%d c->spd.that.client.addr af "
					 "is not AF_INET (aka IPv4 )",
					 __func__, __LINE__));
		return TRUE;
	}

	if (c->pool == NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log(" %s:%d addresspool is null so nothing to free",
			    __func__, __LINE__));
		return TRUE;
	}

	addrtot(&c->spd.that.client.addr, 0, abuf3, sizeof(abuf3));
	addrtot(&c->pool->start, 0, abuf1, sizeof(abuf1));
	addrtot(&c->pool->end, 0, abuf2, sizeof(abuf2));

	a = (u_int32_t)ntohl(c->spd.that.client.addr.u.v4.sin_addr.s_addr);
	a_s = (u_int32_t)ntohl(c->pool->start.u.v4.sin_addr.s_addr);
	a_e = (u_int32_t)ntohl(c->pool->end.u.v4.sin_addr.s_addr);
	if (!((a >= a_s) && (a <= a_e))) {
		DBG(DBG_CONTROL,
		    DBG_log("can not free it. that.client.addr %s"
			    " in not from addresspool %s-%s",
			    abuf3, abuf1, abuf2));
		return TRUE;
	}
	i = a - a_s;

	/* set the lease entry as free */
	if (rel_lease_entry(&c->pool->lease, i)) {
		/* this should not happen. So worth logging. */
		DBG(DBG_CONTROL, DBG_log("failed to set unused address "
					 "that.client.addr %s conn addresspool"
					 "%s-%s index %u size %u used %u"
					 " cached %u",
					 abuf3, abuf1, abuf2, i,
					 c->pool->size,  c->pool->used,
					 c->pool->cached));
		return TRUE;
	}
	c->pool->cached++;
	c->pool->used--;
	DBG(DBG_CONTROLMORE, DBG_log("freed lease %s from addresspool %s-%s"
				     " index %u. pool size %u used %u cached %u",
				     abuf3, abuf1, abuf2, i, c->pool->size,
				     c->pool->used, c->pool->cached));

	return FALSE;
}

static bool  find_last_lease(struct connection *c, u_int32_t *index)
{

	struct lease_addr **pp = &c->pool->lease;
	struct lease_addr *p = *pp;
	char thatid[IDTOA_BUF];

	idtoa(&c->spd.that.id, thatid, sizeof(thatid));
	DBG(DBG_CONTROLMORE, DBG_log("in %s:%d find old addresspool lease for "
				     "'%s'", __func__, __LINE__, thatid));

	while ( (p = *pp) !=  NULL) {
		if ((p->thatid.kind != ID_NONE) &&
		    same_id(&p->thatid, &c->spd.that.id)) {
			DBG(DBG_CONTROLMORE, DBG_log("  addresspool found the"
						     " old id. re-use address '%s'",
						     thatid));
			*index = p->index;
			if ( p->ends)
				c->pool->cached--;
			p->ends = FALSE;
			return TRUE;
		}
		pp = &p->next;
	}
	DBG(DBG_CONTROLMORE, DBG_log("  no match found for %s", thatid));
	return FALSE;
}

err_t get_addr_lease(struct connection *c, struct internal_addr *ia)
{
	/* return value is from 1 to size. 0 is error */
	u_int32_t i = 0;
	u_int32_t i_p = 0;
	u_int32_t size =  c->pool->size;
	struct lease_addr **pp = &c->pool->lease;
	struct lease_addr **head = &c->pool->lease;
	struct lease_addr *p = *pp;
	struct lease_addr *h_p = *pp;
	struct lease_addr *a;

	char abuf1[ADDRTOT_BUF];
	char abuf2[ADDRTOT_BUF];
	char abuf3[ADDRTOT_BUF];
	char thatid[IDTOA_BUF];

	uint32_t addr_nw;
	uint32_t addr;
	err_t e = NULL;
	bool r;

	addrtot(&c->pool->start, 0, abuf1, sizeof(abuf1));
	addrtot(&c->pool->end, 0, abuf2, sizeof(abuf2));
	addrtot(&c->spd.that.client.addr, 0, abuf3, sizeof(abuf3));
	idtoa(&c->spd.that.id, thatid, sizeof(thatid));

	DBG(DBG_CONTROL,
	    DBG_log("lease request for addresspool"
		    " %s-%s size %u reference count %u thread"
		    " id %lu thatid '%s' that.client.addr %s",
		    abuf1, abuf2, c->pool->size,
		    c->pool->refcnt, pthread_self(), thatid, abuf3));

	r = find_last_lease(c, &i);
	if (!r) {
		while ( (p = *pp) !=  NULL) {
			i = p->index;
			if ((i - i_p ) > 1)
				break;
			i_p = i;
			h_p = p;
			pp = &p->next;
		}

		if (( *head == NULL) && (size > 0)) {
			i_p = 0;
		} else if ((i_p++) >= size ) {
			DBG(DBG_CONTROL,
			    DBG_log("can't lease a new address from "
				    "addresspool %s-%s size %u "
				    "reference count %u ", abuf1, abuf2,
				    c->pool->size, c->pool->refcnt));
			return "no free address in addresspool ";
		}
		i = i_p;
		a = alloc_thing(struct  lease_addr, "address lease entry");
		a->index = i_p;
		a->starts = time((time_t *)NULL);
		a->ends = FALSE;

		duplicate_id(&a->thatid, &c->spd.that.id);
		idtoa(&a->thatid, thatid, sizeof(thatid));

		a->next = p;
		if (h_p != NULL)
			h_p->next = a;
		else
			*head = a;
		c->pool->used++;
	}

	addr = (u_int32_t)ntohl(c->pool->start.u.v4.sin_addr.s_addr);
	addr += i;
	addr_nw = htonl(addr);
	e = initaddr((unsigned char *)&addr_nw, sizeof(addr_nw),
		     AF_INET, &ia->ipaddr);

	DBG(DBG_CONTROLMORE, DBG_log("%s lease %s from addresspool %s-%s. "
				     "index %u size %u used %u cached %u thatid '%s'",
				     r ? "re-use" : "new",
				     (addrtot(&ia->ipaddr, 0, abuf3,
					      sizeof(abuf3)), abuf3),
				     abuf1, abuf2, i, c->pool->size,
				     c->pool->used,
				     c->pool->cached, thatid));
	if (e)
		return e;

	return NULL;
}

static void free_remembered_addresspools(void)
{
	free_addresspools(&pluto_pools);
}

struct ip_pool *free_addresspool_entry(struct ip_pool *p)
{
	struct ip_pool *nxt = NULL;

	if (p == NULL)
		return NULL;

	if (p->next != NULL)
		nxt = p->next;

	unreference_addrespool(p);

	return nxt;
}

static void free_addresspools(struct ip_pool **pools)
{
	while (*pools != NULL)
		*pools = free_addresspool_entry(*pools);
}

void unreference_addrespool(struct ip_pool *pool)
{
	if (pool == NULL)
		return;

	pool->refcnt--;
	if (pool->refcnt == 0) {
		free_lease_list(&pool->lease);
		DBG(DBG_CONTROLMORE, DBG_log("freeing memory for addresspool"
					     " ptr %p", pool));
		pfreeany(pool);
	}
}

void free_addresspool( struct ip_pool *pool)
{
	/* free the the addressess ? or the list */
	free_lease_list(&pool->lease);
	pfreeany(pool);
}

struct ip_pool *reference_addresspool(struct  ip_pool *pool)
{
	pool->refcnt++;
	return pool;
}

static struct ip_pool *find_addresspool(const ip_range *pool_range,
					struct ip_pool **head)
{
	struct ip_pool *h = *head;

	if (h) {
		while (h) {
			int sflag, eflag;
			sflag = memcmp(&h->start.u.v4.sin_addr.s_addr,
				       &pool_range->start.u.v4.sin_addr.s_addr,
				       sizeof(h->start.u.v4.sin_addr.s_addr));
			eflag = memcmp(&h->end.u.v4.sin_addr.s_addr,
				       &pool_range->end.u.v4.sin_addr.s_addr,
				       sizeof(h->end.u.v4.sin_addr.s_addr));

			DBG(DBG_CONTROLMORE, {
				    char abuf2[ADDRTOT_BUF];
				    char abuf1[ADDRTOT_BUF];
				    addrtot(&pool_range->start, 0, abuf1,
					    sizeof(abuf1));
				    addrtot(&pool_range->end, 0, abuf2,
					    sizeof(abuf2));
				    DBG_log("%s addresspool %s-%s %s %s ",
					    ((sflag ==
					      0) &
					     (eflag ==
					      0)) ? "existing " : "new ",
					    abuf1, abuf2,
					    (sflag == 0) ? "same start " : " ",
					    (eflag == 0) ? "same end" : "");
			    });

			if ((sflag ==  0 ) & ( eflag == 0)) {
				reference_addresspool(h);
				return h;
			}
			h = h->next;
		}
	}
	return NULL;
}

struct ip_pool *install_addresspool(const ip_range *pool_range,
				    struct ip_pool **head)
{
	struct ip_pool *pool;

	if ((pool = find_addresspool(pool_range, head)) != NULL) {
		DBG(DBG_CONTROLMORE, {
			    char abuf2[ADDRTOT_BUF];
			    char abuf1[ADDRTOT_BUF];
			    addrtot(&pool->start, 0, abuf1, sizeof(abuf1));
			    addrtot(&pool->end, 0, abuf2, sizeof(abuf2));
			    DBG_log("addresspool %s-%s exists ref count %u "
				    "used %u size %u ptr %p",
				    abuf1, abuf2, pool->refcnt, pool->used,
				    pool->size, pool);
		    });

		return pool;
	}

	struct ip_pool *p = alloc_thing(struct ip_pool, "addresspool entry");

	reference_addresspool(p);
	p->start =  pool_range->start;
	p->end = pool_range->end;
	p->size = (u_int32_t)ntohl(p->end.u.v4.sin_addr.s_addr) -
		  (u_int32_t)ntohl(p->start.u.v4.sin_addr.s_addr);
	p->size++;
	p->used = 0;
	p->cached = 0;

	DBG(DBG_CONTROLMORE, {
		    char abuf2[ADDRTOT_BUF];
		    char abuf1[ADDRTOT_BUF];
		    DBG_log("adding addresspool to global pools %s-%s "
			    "size %d ptr %p",
			    (addrtot(&p->start, 0, abuf1,
				     sizeof(abuf1)), abuf1),
			    (addrtot(&p->end, 0, abuf2,
				     sizeof(abuf2)), abuf2 ),
			    p->size, p);
	    });
	p->lease = NULL;
	p->next = *head;
	*head = p;
	return p;
}
