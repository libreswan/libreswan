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
*/

#ifndef _ADDRESSPOOL_H
#define _ADDRESSPOOL_H 

struct ip_pool_old {
	unsigned refcnt;    /* reference counted! */
	ip_address start;
	ip_address end;
	u_int32_t  size;
	struct lease_addr_list  *lease_list;

};

struct lease_addr 
{
	u_int32_t index;        /* index in addresspool. The first address 0 */
	struct id thatid; 	/* from connection */
	time_t starts;		/* first time it was leased to this id */
	time_t ends;		/* 0 is never. > 0 is when it ended */

	struct lease_addr *next;
};

struct ip_pool
{
	unsigned refcnt;    /* reference counted! */
	ip_address start;
	ip_address end;
	u_int32_t  size;
	u_int32_t  used;
	u_int32_t  cached;
	struct lease_addr *lease;
	struct ip_pool *next;
};
struct ip_pool *pluto_pools;
struct ip_pool *install_addresspool(const ip_range *pool_range, struct ip_pool **head);
err_t  get_addr_lease(struct connection *c, struct internal_addr *ia);
int rel_lease_addr(struct connection *c);
void unreference_addrespool(struct  ip_pool *pool);
struct ip_pool *free_addresspool_entry(struct ip_pool *p);
#endif /* _ADDRESSPOOL_H */
