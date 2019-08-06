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
 * In libreswan ip_subnet is something of a mashup.  In addition to
 * a traditional subnet:
 *
 *    (NETWORK)PREFIX | 0..0 / MASK
 *
 * with attributes such as MASK, BITS, PREFIX, it is used to store
 * "routed endpoints" (is that a term?) as in:
 *
 *    (NETWORK)PREFIX | HOST(IDENTIFIER) : PORT / MASK
 *
 * with the additional attributes of ENDPOINT, PORT, ADDRESS.
 *
 * XXX: does the latter need to be split adding ip_routepoint?
 * Depends on what you think a SUBNET is.
 */

#include "ip_endpoint.h"

struct lswlog;

typedef struct {
	/* (routing)prefix|host(id):port */
	ip_endpoint addr;
	/* (routing prefix) bits */
	int maskbits;
} ip_subnet;

/*
 * Format as a string.
 */

typedef struct {
	char buf[sizeof(address_buf) + 4/*/NNN*/];
} subnet_buf;
const char *str_subnet(const ip_subnet *subnet, subnet_buf *out);
void jam_subnet(struct lswlog *buf, const ip_subnet *subnet);

const struct ip_info *subnet_info(const ip_subnet *subnet);

/*
 * Extract details
 */

/* when applied to an address, leaves just the routing prefix */
ip_address subnet_mask(const ip_subnet *subnet);

/* [floor..ceiling] vs [floor..roof) */
/* PREFIX&MASK; aka IPv4 network, IPv6 anycast */
ip_address subnet_floor(const ip_subnet *subnet);
/* PREFIX|~MASK; aka IPv4 broadcast but not IPv6 */
ip_address subnet_ceiling(const ip_subnet *subnet);

/* PREFIX|HOST:PORT */
ip_endpoint subnet_endpoint(const ip_subnet *subnet);

/*
 * old
 */
#include "err.h"

extern err_t ttosubnet(const char *src, size_t srclen, int af, ip_subnet *dst);
extern void subnettot(const ip_subnet *src, int format, char *buf, size_t buflen);
#define SUBNETTOT_BUF   sizeof(subnet_buf)
extern err_t initsubnet(const ip_address *addr, int maskbits, int clash,
		 ip_subnet *dst);
extern err_t addrtosubnet(const ip_address *addr, ip_subnet *dst);

/* misc. conversions and related */
extern err_t rangetosubnet(const ip_address *from, const ip_address *to,
		    ip_subnet *dst);
extern int subnettypeof(const ip_subnet *src);

/* tests */
extern bool samesubnet(const ip_subnet *a, const ip_subnet *b);
extern bool addrinsubnet(const ip_address *a, const ip_subnet *s);
extern bool subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
extern bool subnetishost(const ip_subnet *s);
extern bool samesubnettype(const ip_subnet *a, const ip_subnet *b);
#define subnetisaddr(sn, a) (subnetishost(sn) && addrinsubnet((a), (sn)))
extern bool subnetisnone(const ip_subnet *sn);

#endif
