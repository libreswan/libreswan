/* 
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

void unreference_addrespool(struct  ip_pool **pp); 
void free_remembered_addresspools(void);
void free_addresspools(struct ip_pool **pools);
void free_addresspool(struct ip_pool *pool);
struct ip_pool *free_addresspool_entry(struct ip_pool *p);
struct ip_pool *reference_addresspool(struct  ip_pool *pool);
struct lease_addr *delete_lease_entry(struct lease_addr *h);
int get_next_free_addr(struct lease_addr **head,u_int32_t *idx, u_int32_t  size);
int delete_lease(struct lease_addr **head, u_int32_t lease);
void delete_lease_list(struct lease_addr **head);
struct ip_pool *find_addresspool(ip_range *pool_range, struct ip_pool **head);

/* root of chained addresspool  list */
struct ip_pool *pluto_pools = NULL; /* addresspool from ipsec.onf */

void delete_lease_list(struct lease_addr **head)
{
	while (*head != NULL) 
		*head =  delete_lease_entry (*head);
}

struct lease_addr *delete_lease_entry(struct lease_addr *h)
{
	struct lease_addr *next = h->next;
	pfreeany(h);
	return next;
}

int delete_lease(struct lease_addr **head, u_int32_t lease)
{
	struct lease_addr **pp = head;
	struct lease_addr *p_prev = *head;
	struct lease_addr *p;

	DBG(DBG_CONTROL ,DBG_log("addresspool request to free lease " 
				"index %u head %p", lease, *head));
	while ((p = *pp) != NULL) {
		if (p->idx == lease) {
			if (p_prev == p) {
				*head = p->next;
			}
			else {
				p_prev->next = p->next;
			}
			/*
			DBG(DBG_CONTROL ,DBG_log("addresspool could have freeed lease "
						"index %u ptr %p head %p", lease, p, *head));

			*/
			p->idx=0;
			DBG(DBG_CONTROL ,DBG_log("addresspool freeing lease "
						" index %u ptr %p", lease, p));
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

	if (ip_address_family(&c->spd.that.client.addr) != AF_INET)
	{	
		DBG(DBG_CONTROL ,DBG_log(" %s:%d c->spd.that.client.addr af "
					"is not AF_INET", __func__, __LINE__));
		return TRUE;
	}

	if (!c->pool) {
		DBG(DBG_CONTROL ,DBG_log(" %s:%d pool is null so no freeing"
					, __func__, __LINE__));
		return  TRUE;
	}

	addrtot(&c->spd.that.client.addr,0, abuf3, sizeof(abuf3)); 
	addrtot(&c->pool->start,0, abuf1, sizeof(abuf1));
	addrtot(&c->pool->end,0, abuf2, sizeof(abuf2));

	a = (u_int32_t)ntohl(c->spd.that.client.addr.u.v4.sin_addr.s_addr);
	a_s = (u_int32_t)ntohl(c->pool->start.u.v4.sin_addr.s_addr);   
	a_e = (u_int32_t)ntohl(c->pool->end.u.v4.sin_addr.s_addr);  
	if (!((a >= a_s) && (a <= a_e))){
		DBG(DBG_CONTROL 
				,DBG_log("can not free a pool adress "
					"that.client.addr %s in not from "
					"addresspool %s-%s"
					, abuf3, abuf1, abuf2));
		return TRUE;
	}
	i = a - a_s;

	/* delte the entry from  the linked list */
	if (delete_lease(&c->pool->lease, i)) {
		/* this should not happen. So worth logging. */
		DBG(DBG_CONTROL ,DBG_log("failed to free unused address "
					"that.client.addr %s conn addresspool"
					"%s-%s index %u used %u size %u"
					, abuf3, abuf1, abuf2, i, c->pool->used
					, c->pool->size)); 
		return TRUE;
	}
	c->pool->used--;
	DBG(DBG_CONTROL ,DBG_log("deleted lease %s from addresspool %s-%s " 
				"index %u used %u size %u"
				, abuf3, abuf1, abuf2, i, c->pool->used
				, c->pool->size));
	return FALSE;
}

int get_next_free_addr(struct lease_addr **head, u_int32_t *idx, u_int32_t  size) 
{
	/* return value is from 1 to size. 0 is error */
	u_int32_t i = 0;
	u_int32_t i_p = 0;
	struct lease_addr **pp = head;
	struct lease_addr *p = *head;
	struct lease_addr *a;
	struct lease_addr *h_p = *head; 
        
	while ( (p = *pp) !=  NULL){
		i = p->idx ;
		if ((i - i_p ) > 1) {
			break;	
		}
		i_p = i;
		h_p = p;
		pp = &p->next;
	} 

	if (( *head == NULL) && (size > 0)) {
		i_p = 0;
	}
	else if ((i_p++) >= size ) {
		return TRUE;
	}

	*idx = i_p;
	a = alloc_thing(struct  lease_addr, "address lease entry");
	a->idx = i_p;
	a->next = p; 
	DBG(DBG_CONTROL ,DBG_log("addresspool new lease entry index %u ptr "
				"%p prev ptr %p head %p", i_p, a, h_p, *head));

	if (h_p != NULL) 
		h_p->next = a;
	else 
		*head = a;	
	return FALSE;
}

err_t get_addr_lease(struct connection *c, struct internal_addr *ia)
{
	char abuf1[ADDRTOT_BUF];
	char abuf2[ADDRTOT_BUF];
	char abuf3[ADDRTOT_BUF]; 
	uint32_t i = 0;
	uint32_t free_addr_nw;
	uint32_t free_addr;
	err_t e = NULL;

	addrtot(&c->pool->start,0, abuf1, sizeof(abuf1));
	addrtot(&c->pool->end,0, abuf2, sizeof(abuf2));

	DBG(DBG_CONTROLMORE,
			DBG_log("lease request from the addresspool "
				"%s-%s size %u reference count %u", abuf1
				, abuf2, c->pool->size, c->pool->refcnt)); 

	if (get_next_free_addr(&c->pool->lease, &i, c->pool->size)){
		DBG(DBG_CONTROLMORE,
				DBG_log("can't lease a new address from "
					"addresspool %s-%s size %u " 
					"reference count %u ", abuf1, abuf2
					, c->pool->size, c->pool->refcnt));
		return "no free address in the addresspool ";
	}	
	c->pool->used++;
	free_addr = (u_int32_t)ntohl(c->pool->start.u.v4.sin_addr.s_addr);
	free_addr += i;
	free_addr_nw = htonl(free_addr);
	e = initaddr((unsigned char *)&free_addr_nw, sizeof(free_addr_nw)
			, AF_INET, &ia->ipaddr);
	if (e) 
		return e;

	DBG(DBG_CONTROLMORE, DBG_log("leased %s from the addresspool %s-%s. "
				"index %u  used %u size %u "
				, (addrtot(&ia->ipaddr,0, abuf3, sizeof(abuf3)), abuf3)
				, abuf1, abuf2, i,c->pool->used, c->pool->size));
	return NULL;
}
void free_remembered_addresspools(void)
{
	free_addresspools(&pluto_pools);
}


struct ip_pool *free_addresspool_entry(struct ip_pool *p)
{
	struct ip_pool *nxt = p->next;

	if (p->refcnt > 0)
		unreference_addrespool(&p);

	if (p->refcnt ==  0) 
		pfreeany(p);

	return nxt;
}

	void
free_addresspools(struct ip_pool **pools)
{
	while (*pools != NULL)
		*pools = free_addresspool_entry(*pools);
} 


void unreference_addrespool(struct ip_pool **pool)
{
	struct ip_pool *p = *pool;
	if (p == NULL)
		return;

	p->refcnt--;
	if (p->refcnt == 0)
		free_addresspool(p);
} 

void free_addresspool( struct ip_pool *pool)
{
	/* free the the addressess ? or the list */
	pfreeany(pool);
}

struct ip_pool *reference_addresspool(struct  ip_pool *pool) 
{	
	pool->refcnt++;
	return pool;
} 


struct ip_pool *find_addresspool(ip_range *pool_range, struct ip_pool **head)  
{	
	struct ip_pool *h = *head;
	if (h) {
		while (h) {
			int sflag, eflag;
			sflag = memcmp(&h->start.u.v4.sin_addr.s_addr
					, &pool_range->start.u.v4.sin_addr.s_addr
					, sizeof(h->start.u.v4.sin_addr.s_addr));
			eflag = memcmp(&h->end.u.v4.sin_addr.s_addr
					, &pool_range->end.u.v4.sin_addr.s_addr
					, sizeof(h->end.u.v4.sin_addr.s_addr));

			DBG(DBG_CONTROLMORE, {
					char abuf2[ADDRTOT_BUF];
					char abuf1[ADDRTOT_BUF];
					addrtot(&pool_range->start,0, abuf1 , sizeof(abuf1));
					addrtot(&pool_range->end,0, abuf2 , sizeof(abuf2));
					DBG_log("%s addresspool %s-%s %s %s ", 
						((sflag == 0) & (eflag == 0)) ? "existing " : "new " 
						, abuf1, abuf2
						, (sflag == 0) ? "same start " : " " 
						, (eflag == 0) ? "same end" : "");
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

struct ip_pool *install_addresspool(ip_range *pool_range, struct ip_pool **head) 
{
	struct ip_pool *pool;

	if ((pool = find_addresspool(pool_range, head)) != NULL) {
		DBG(DBG_CONTROLMORE, {
				char abuf2[ADDRTOT_BUF];
				char abuf1[ADDRTOT_BUF];
				addrtot(&pool->start,0, abuf1 , sizeof(abuf1));
				addrtot(&pool->end,0, abuf2 , sizeof(abuf2));
				DBG_log("addresspool %s-%s exists ref count %u "
					"used %u size %u ptr %p"
					, abuf1, abuf2, pool->refcnt, pool->used
					, pool->size, pool); 
				}
		   );

		return pool;
	}

	struct ip_pool *p = alloc_thing(struct ip_pool, "addresspool entry");

	reference_addresspool(p);
	p->start =  pool_range->start;
	p->end = pool_range->end;
	p->size = (u_int32_t)ntohl(p->end.u.v4.sin_addr.s_addr)
		- (u_int32_t)ntohl(p->start.u.v4.sin_addr.s_addr);
	p->size++; 
	p->used = 0;

	DBG(DBG_CONTROLMORE, {
			char abuf2[ADDRTOT_BUF];
			char abuf1[ADDRTOT_BUF];
			DBG_log("adding addresspool to global pools %s-%s "
				"size %d ptr %p"
				, (addrtot(&p->start,0, abuf1 , sizeof(abuf1)), abuf1)
				, (addrtot(&p->end,0, abuf2 , sizeof(abuf2)),abuf2 )
				, p->size, p);
			})
	p->lease = NULL;
	p->next = *head;
	*head = p;
	return p;
}
