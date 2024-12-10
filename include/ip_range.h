/* address range, for libreswan
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

#ifndef IP_RANGE_H
#define IP_RANGE_H

#include "err.h"
#include "ip_address.h"
#include "ip_subnet.h"
#include "ip_version.h"

typedef struct {
	bool is_set;
	enum ip_version version;
	struct ip_bytes lo;
	struct ip_bytes hi;
} ip_range;

#define PRI_RANGE "<range-%s:IPv%d["PRI_IP_BYTES"]->["PRI_IP_BYTES"]>"
#define pri_range(R)					\
		((R)->is_set ? "set" : "unset"),	\
		(R)->version,				\
		pri_ip_bytes((R)->lo),			\
		pri_ip_bytes((R)->hi)

void pexpect_range(const ip_range *r, where_t where);
#define prange(R) pexpect_range(R, HERE)

/* caller knows best */
ip_range range_from_raw(where_t where, const struct ip_info *afi,
			const struct ip_bytes start,
			const struct ip_bytes end);

ip_range range_from_address(const ip_address subnet);
ip_range range_from_subnet(const ip_subnet subnet);

err_t addresses_to_nonzero_range(const ip_address start, const ip_address end,
				 ip_range *dst) MUST_USE_RESULT;

err_t range_to_subnet(const ip_range range, ip_subnet *subnet) MUST_USE_RESULT;

err_t ttorange_num(shunk_t input, const struct ip_info *afi, ip_range *dst) MUST_USE_RESULT;

/* comma/space separated list */

typedef struct {
	unsigned len;
	ip_range *list;
} ip_ranges;

extern const ip_ranges empty_ip_ranges;

diag_t ttoranges_num(shunk_t input, const char *delims,
		     const struct ip_info *afi,
		     ip_ranges *output) MUST_USE_RESULT;

size_t jam_ranges(struct jambuf *buf, ip_ranges ranges);

/*
 * Formatting
 */

typedef struct {
	char buf[sizeof(address_buf) + 1/*"-"*/ + sizeof(address_buf)];
} range_buf;

size_t jam_range(struct jambuf *buf, const ip_range *range);
const char *str_range(const ip_range *range, range_buf *buf);

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

extern const ip_range unset_range;

bool range_is_unset(const ip_range *r);			/* handles NULL */
const struct ip_info *range_type(const ip_range *r);	/* handles NULL */
const struct ip_info *range_info(const ip_range r);

bool range_is_zero(ip_range range);	/* ::-ffff... or 0.0.0.0-0.0.0.0 */
bool range_is_all(const ip_range r);	/* ::-:: or 0.0.0.0-0.0.0.0 */
bool range_is_cidr(ip_range r);		/* prefix/host=0..prefix/host=-1 */

bool range_eq_address(const ip_range range, const ip_address address);
bool range_eq_subnet(const ip_range range, const ip_subnet subnet);
bool range_eq_range(const ip_range l, const ip_range r);

bool address_in_range(const ip_address address, const ip_range range);
bool subnet_in_range(const ip_subnet subnet, const ip_range range);
bool range_in_range(const ip_range inner, const ip_range outer);

bool range_overlaps_range(const ip_range l, const ip_range r);

/*
 * range_host_len: Calculate the number of significant bits in the
 * size of the range.  floor(log2(|high-low| + 1)).
 *
 * If RANGE is CIDR then this returns the number of HOST IDENTIFIER
 * bits, otherwise it returns something slightly higher.
 */
int range_host_len(const ip_range range);
int range_prefix_len(const ip_range range);

/*
 * range_size: the number of IP addresses within an ip_range.
 *
 * Special return values:
 *   0 indicates that the range isn't of IPv4 or IPv6 addresses.
 *   UINTMAX_MAX indicates that the range size is UINTMAX_MAX or more
 */
uintmax_t range_size(const ip_range r);

/*
 * operations
 */

ip_address range_start(const ip_range range); /* floor */
ip_address range_end(const ip_range range); /* ceiling */

err_t range_offset_to_address(const ip_range range, uintmax_t offset,
			      ip_address *address) MUST_USE_RESULT;

err_t address_to_range_offset(const ip_range range, const ip_address address,
			      uintmax_t *offset) MUST_USE_RESULT;

#endif
