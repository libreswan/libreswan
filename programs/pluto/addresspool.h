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
 */

#ifndef _ADDRESSPOOL_H
#define _ADDRESSPOOL_H

/* 
 * A pool is a range of IPv4 addresses to be individually allocated.
 * A connection may have a pool.
 * That pool may be shared with other connections (hence the reference count).
 *
 * A pool has a linked list of leases.
 * This list is in monotonically increasing order.
 */
struct ip_pool {
	unsigned refcnt;        /* reference counted! */
	ip_address start;       /* start of IP range in pool */
	ip_address end;         /* end of IP range in pool (included) */
	u_int32_t size;         /* number of addresses within range */
	u_int32_t used;         /* count, addresses in use */
	u_int32_t lingering;    /* count, lingering addresses */
	struct lease_addr *leases;      /* monotonically increasing index values */

	struct ip_pool *next;   /* next pool */
};

struct ip_pool *install_addresspool(const ip_range *pool_range);
err_t get_addr_lease(const struct connection *c, struct internal_addr *ia /*result*/);
void rel_lease_addr(const struct connection *c);

extern void unreference_addresspool(struct ip_pool *pool);

#endif /* _ADDRESSPOOL_H */
