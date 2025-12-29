/* address pool, for libreswan
 *
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef IP_POOL_H
#define IP_POOL_H

#include "err.h"
#include "ip_base.h"
#include "ip_address.h"
#include "ip_subnet.h"
#include "ip_version.h"
#include "ip_range.h"

typedef struct {
	struct ip_base ip;	/* MUST BE FIRST */

	struct ip_bytes lo;
	struct ip_bytes hi;
	/* nr of bits to deligate */
	unsigned subprefix;
} ip_pool;

#define PRI_POOL "<pool-%s:"PRI_IP_VERSION"["PRI_IP_BYTES"]->["PRI_IP_BYTES"]>/%u"
#define pri_pool(R)					\
	((R)->ip.is_set ? "set" : "unset"),		\
		pri_ip_version((R)->ip.version),	\
		pri_ip_bytes((R)->lo),			\
		pri_ip_bytes((R)->hi),			\
		(R)->subprefix

void pexpect_pool(const ip_pool *r, where_t where);

/* caller knows best */
ip_pool pool_from_raw(where_t where, const struct ip_info *afi,
			const struct ip_bytes start,
			const struct ip_bytes end,
			unsigned subprefix);

ip_pool pool_from_address(const ip_address subnet);
ip_pool pool_from_cidr(const ip_cidr cidr);
ip_pool pool_from_subnet(const ip_subnet subnet);
ip_pool pool_from_range(const ip_range range);

err_t addresses_to_nonzero_pool(const ip_address start, const ip_address end,
				 ip_pool *dst) MUST_USE_RESULT;

err_t pool_to_subnet(const ip_pool pool, ip_subnet *subnet) MUST_USE_RESULT;

diag_t ttopool_num(shunk_t input, const struct ip_info *afi, ip_pool *dst) MUST_USE_RESULT;

/* comma/space separated list */

typedef struct {
	unsigned len;
	ip_pool *list;
} ip_pools;

extern const ip_pools empty_ip_pools;

diag_t ttopools_num(shunk_t input, const char *delims,
		     const struct ip_info *afi,
		     ip_pools *output) MUST_USE_RESULT;

size_t jam_pools(struct jambuf *buf, ip_pools pools);

/*
 * Formatting
 */

typedef struct {
	char buf[sizeof(address_buf) + 1/*"-"*/ + sizeof(address_buf)];
} pool_buf;

size_t jam_pool(struct jambuf *buf, const ip_pool *pool);
const char *str_pool(const ip_pool *pool, pool_buf *buf);

/*
 * Magic values.
 *
 * XXX: While the headers call the all-zero address "ANY" (INADDR_ANY,
 * IN6ADDR_ANY_INIT), the headers also refer to the IPv6 value as
 * unspecified (for instance IN6_IS_ADDR_UNSPECIFIED()) leaving the
 * term "unspecified" underspecified.
 *
 * Consequently an AF_UNSPEC address (i.e., uninitialized or unset),
 * is identified by *_unset().
 */

extern const ip_pool unset_pool;

bool pool_is_unset(const ip_pool *r);			/* handles NULL */
const struct ip_info *pool_type(const ip_pool *r);	/* handles NULL */
const struct ip_info *pool_info(const ip_pool r);

bool pool_is_zero(ip_pool pool);	/* ::-ffff... or 0.0.0.0-0.0.0.0 */
bool pool_is_all(const ip_pool r);	/* ::-:: or 0.0.0.0-0.0.0.0 */
bool pool_is_cidr(ip_pool r);		/* prefix/host=0..prefix/host=-1 */

bool pool_eq_address(const ip_pool pool, const ip_address address);
bool pool_eq_subnet(const ip_pool pool, const ip_subnet subnet);
bool pool_eq_pool(const ip_pool l, const ip_pool r);

bool address_in_pool(const ip_address address, const ip_pool pool);
bool subnet_in_pool(const ip_subnet subnet, const ip_pool pool);
bool cidr_in_pool(const ip_cidr cidr, const ip_pool pool);
bool pool_in_pool(const ip_pool inner, const ip_pool outer);

bool pool_overlaps_pool(const ip_pool l, const ip_pool r);

/*
 * pool_host_len: Calculate the number of significant bits in the
 * size of the pool.  floor(log2(|high-low| + 1)).
 *
 * If POOL is CIDR then this returns the number of HOST IDENTIFIER
 * bits.
 */

int pool_host_len(const ip_pool pool); /* <0 when non-CIDR */
int pool_prefix_len(const ip_pool pool); /* <0 when non-CIDR */

/*
 * pool_size: the number of IP addresses within an ip_pool.
 *
 * Special return values:
 *   0 indicates that the pool isn't of IPv4 or IPv6 addresses.
 *   UINTMAX_MAX indicates that the pool size is UINTMAX_MAX or more
 */
uintmax_t pool_size(const ip_pool r);

/*
 * operations
 */

ip_address pool_start(const ip_pool pool); /* floor */
ip_address pool_end(const ip_pool pool); /* ceiling */

err_t pool_offset_to_cidr(const ip_pool pool, uintmax_t offset,
			   ip_cidr *cidr) MUST_USE_RESULT;

err_t cidr_to_pool_offset(const ip_pool pool,
			   const ip_cidr cidr,
			   uintmax_t *offset) MUST_USE_RESULT;

#endif
