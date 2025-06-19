/* ip subnet, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019-2020 Andrew Cagney <cagney@gnu.org>
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

#ifndef IP_SUBNET_H
#define IP_SUBNET_H

/*
 * This defines a traditional subnet:
 *
 *    ADDRESS_PREFIX / MASK
 *
 */

#include "ip_base.h"
#include "ip_address.h"
#include "ip_endpoint.h"
#include "ip_cidr.h"
#include "ip_bytes.h"
#include "ip_version.h"
#include "err.h"

struct jambuf;

typedef struct {
	struct ip_base ip;	/* MUST BE FIRST */
	bool is_set;

	/*
	 * We need something that makes static IPv4 initializers
	 * possible (struct in_addr requires htonl() which is run-time
	 * only).
	 */
	struct ip_bytes bytes;
	/*
	 * (routing prefix) bits.
	 */
	unsigned maskbits;
} ip_subnet;

#define PRI_SUBNET "<subnet-%s:IPv%d["PRI_IP_BYTES"]/%u>"
#define pri_subnet(S)					\
		((S)->is_set ? "set" : "unset"),	\
			(S)->ip.version,		\
		pri_ip_bytes((S)->bytes),		\
		(S)->maskbits

void pexpect_subnet(const ip_subnet *s, where_t where);
#define psubnet(S) pexpect_subnet(S, HERE)

/*
 * Constructors
 */

ip_subnet subnet_from_raw(where_t where, const struct ip_info *afi,
			  const struct ip_bytes prefix,
			  unsigned prefix_length);

/* ADDRESS..ADDRESS */
ip_subnet subnet_from_address(const ip_address address);
/* ADDRESS/PREFIX_BITS */
ip_subnet subnet_from_cidr(const ip_cidr cidr);

/* barf if not valid */
err_t address_mask_to_subnet(const ip_address address, const ip_address mask, ip_subnet *subnet);

extern err_t addresses_to_nonzero_subnet(const ip_address from, const ip_address to,
					 ip_subnet *dst) MUST_USE_RESULT;

/*
 * Format as a string.
 */

typedef struct {
	char buf[sizeof(address_buf) + 4/*"/NNN"*/];
} subnet_buf;
extern const char *str_subnet(const ip_subnet *subnet, subnet_buf *out);
extern size_t jam_subnet(struct jambuf *buf, const ip_subnet *subnet);

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

extern const ip_subnet unset_subnet;

bool subnet_is_unset(const ip_subnet *subnet);			/* handles NULL */
const struct ip_info *subnet_type(const ip_subnet *subnet);	/* handles NULL */
const struct ip_info *subnet_info(const ip_subnet subnet);

bool subnet_is_zero(const ip_subnet subnet);	/* ::/128 or 0.0.0.0/32 */
bool subnet_is_all(const ip_subnet subnet);	/* ::/0 or 0.0.0.0/0 */

bool address_in_subnet(const ip_address address, const ip_subnet subnet);
bool subnet_in_subnet(const ip_subnet lhs, const ip_subnet rhs);

bool subnet_eq_address(const ip_subnet selector, const ip_address address);
/* subnet_eq_range() === range_eq_subnet() */
bool subnet_eq_subnet(const ip_subnet a, const ip_subnet b);

/* Given ROUTING_PREFIX|HOST_ID return ROUTING_PREFIX|0 */
ip_address subnet_prefix(const ip_subnet subnet);
ip_address subnet_prefix_mask(const ip_subnet subnet);
unsigned subnet_prefix_bits(const ip_subnet subnet);
uintmax_t subnet_size(const ip_subnet subnet);

extern err_t ttosubnet_num(shunk_t src, const struct ip_info *afi,
			   ip_subnet *dst, ip_address *nonzero_host);

/* comma/space separated list */

typedef struct {
	unsigned len;
	ip_subnet *list;
} ip_subnets;

diag_t ttosubnets_num(shunk_t input, const struct ip_info *afi, ip_subnets *output);

size_t jam_subnets(struct jambuf *buf, const ip_subnets subnets);

#endif
