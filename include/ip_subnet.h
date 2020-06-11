/* ip subnet, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
 * This is not the subnet you're looking for.
 *
 * In libreswan ip_subnet is used to store client routing information.
 * IKEv2 calls this traffic selectors and it allows the negotiation
 * of:
 *
 *    LO_ADDRESS..HI_ADDRESS : LO_PORT..HI_PORT
 *
 * The structures below can only handle a limited subset of this,
 * namely:
 *
 *    NETWORK_PREFIX | 0 / MASK : PORT
 *
 * where PORT==0 imples 0..65535, and (presumably) port can only be
 * non-zero when the NETWORK_PREFIX/MASK is for a single address.
 */

/*
 * Define SUBNET_TYPE to enable traditional subnets; expect everything
 * to break.
 */

#include "ip_address.h"
#include "ip_endpoint.h"

#include "where.h"		/* used by endtosubnet() */

struct lswlog;

typedef struct {
#ifdef SUBNET_TYPE
	/* proper subnet, not libreswan mashup */
	ip_address addr;
#else
	/* (routing)prefix|host(id):port */
	ip_endpoint addr;
	bool is_selector;
#endif
	/* (routing prefix) bits */
	int maskbits;
	bool is_subnet;
} ip_subnet;

#define PRI_SUBNET "{"PRI_ADDRESS"} maskbits=%u is_subnet=%s is_selector=%s"
#define pri_subnet(S, B)						\
	pri_address(&(S)->addr, B),					\
		(S)->maskbits,						\
		bool_str((S)->is_subnet),				\
		bool_str((S)->is_selector)

#define psubnet(S)							\
	{								\
		if ((S) != NULL && (S)->addr.version != 0) {		\
			if ((S)->is_subnet == false ||			\
			    (S)->is_selector == true) {			\
				address_buf b_;				\
				where_t here_ = HERE;			\
				dbg("EXPECTATION FAILED: %s is not a subnet; "PRI_SUBNET" "PRI_WHERE, \
				    #S, pri_subnet(S, &b_),		\
				    pri_where(here_));			\
			}						\
		}							\
	}

/*
 * Constructors
 */

/* ADDRESS..ADDRESS:0..65535 */
ip_subnet subnet_from_address(const ip_address *address);

/*
 * Format as a string.
 */

typedef struct {
	char buf[sizeof(address_buf) + 4/*"/NNN"*/];
} subnet_buf;
extern const char *str_subnet(const ip_subnet *subnet, subnet_buf *out);
extern size_t jam_subnet(struct lswlog *buf, const ip_subnet *subnet);

/*
 * Magic values.
 *
 * XXX: While the headers call the all-zero address "ANY" (INADDR_ANY,
 * IN6ADDR_ANY_INIT), the headers also refer to the IPv6 value as
 * unspecified (for instance IN6_IS_ADDR_UNSPECIFIED()) leaving the
 * term "unspecified" underspecified.
 *
 * Consequently an AF_UNSPEC address (i.e., uninitialized or unset),
 * is identified by *_type() returning NULL.
 */

extern const ip_subnet unset_subnet;

const struct ip_info *subnet_type(const ip_subnet *subnet);

bool subnet_is_set(const ip_subnet *subnet);
bool subnet_is_specified(const ip_subnet *subnet);

/* default route - ::/0 or 0.0.0.0/0 - matches all addresses */
bool subnet_contains_all_addresses(const ip_subnet *subnet);
/* unspecified address - ::/128 or 0.0.0.0/32 - matches no addresses */
bool subnet_contains_no_addresses(const ip_subnet *subnet);
#if 0
/* ADDRESS..ADDRESS:0..65535 in SUBNET */
bool subnet_contains_address(const ip_subnet *subnet, const ip_address *address);
/* ADDRESS..ADDRESS:PORT..PORT in SUBNET */
bool subnet_contains_endpoint(const ip_subnet *subnet, const ip_address *address);
#endif

/* h(ost) or n(etwork) ordered */
int subnet_hport(const ip_subnet *subnet);

/* when applied to an address, leaves just the routing prefix */
extern ip_address subnet_mask(const ip_subnet *subnet);
/* Given ROUTING_PREFIX|HOST_ID return ROUTING_PREFIX|0 */
ip_address subnet_prefix(const ip_subnet *subnet);

/*
 * old
 */
#include "err.h"

extern err_t ttosubnet(const char *src, size_t srclen, int af, int clash, ip_subnet *dst);
#define SUBNETTOT_BUF   sizeof(subnet_buf)
extern err_t initsubnet(const ip_address *addr, int maskbits, int clash,
		 ip_subnet *dst);
extern err_t endtosubnet(const ip_endpoint *end, ip_subnet *dst, where_t where);

/* misc. conversions and related */
extern err_t rangetosubnet(const ip_address *from, const ip_address *to,
		    ip_subnet *dst);

/* tests */
extern bool samesubnet(const ip_subnet *a, const ip_subnet *b);
extern bool addrinsubnet(const ip_address *a, const ip_subnet *s);
extern bool subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
extern bool subnetishost(const ip_subnet *s);
#define subnetisaddr(sn, a) (subnetishost(sn) && addrinsubnet((a), (sn)))

#endif
