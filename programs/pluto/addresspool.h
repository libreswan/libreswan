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
		u_int32_t idx;
		struct lease_addr *next;
};

struct ip_pool
{
	unsigned refcnt;    /* reference counted! */
	ip_address start;
	ip_address end;
	u_int32_t  size;
	u_int32_t  used;
	struct lease_addr *lease;
	struct ip_pool *next;
};
struct ip_pool *pluto_pools;
struct ip_pool *install_addresspool(ip_range *pool_range, struct ip_pool **head);
err_t  get_addr_lease(struct connection *c, struct internal_addr *ia);
int rel_lease_addr(struct connection *c);
#endif /* _ADDRESSPOOL_H */
