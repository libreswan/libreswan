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
 * In libreswan ip_subnet is used to store client routing information
 * (IKEv2 calls this traffic selectors).
 *
 * In addition to what might traditionally be thought of as a subnet:
 *
 *    (NETWORK)PREFIX | 0..0 / MASK
 *
 * with attributes such as MASK, BITS, PREFIX, an ip_subnet can also
 * contain a port (and if IKEv2 had its way, a port range):
 *
 *    (NETWORK)PREFIX | HOST(IDENTIFIER) : PORT / MASK
 *
 * adding the the additional attributes of PORT, ADDRESS and ENDPOINT
 * - ADDRESS:PORT.
 */

#ifdef SUBNET_TYPE
#include "ip_address.h"
#else
#include "ip_endpoint.h"
#endif

struct lswlog;

typedef struct {
#ifdef SUBNET_TYPE
	/*
	 * XXX:
	 *
	 * As a starting point, since initsubnet() constructs subnets
	 * using an address/mask (the port is added later) reflect
	 * that in the structure.
	 *
	 * However this structure is deficient when it comes to
	 * describing IKEv2's "3.13.1. Traffic Selector"
	 * https://tools.ietf.org/html/rfc7296#section-3.13.1
	 *
	 * Use ip_address and not an ip_endpoint (keeping the port[s]
	 * separate).  The the latter may strictly limit the port's
	 * range [0..65535] preventing the wildcard port from being
	 * represented.  IPv2 means that a range might be better
	 * (making this structure decidedly non-subnet like).
	 */
	ip_address address;
	int maskbits
	/*
	 * Allow -1 and interpret that to mean wildcard (as in all
	 * ports [0..65535]).
	 *
	 * The old ip_address's sockaddr_in* only had 16-bits of space
	 * which isn't sufficient to encode this additional
	 * information.
	 *
	 * XXX: IKEv2 code checks for both end.port==0 (er, 0's only
	 * reserved for TCP and UDP) and end.has_port_wildcard.  See
	 * https://daniel.haxx.se/blog/2014/10/25/pretending-port-zero-is-a-normal-one/
	 */
	int port;
#else
	/* (routing)prefix|host(id):port */
	ip_endpoint addr;
	/* (routing prefix) bits */
	int maskbits;
#endif
} ip_subnet;

/*
 * Construct a subnet exactly as specified (presumably the caller has
 * performed all checks).
 */
ip_subnet subnet(const ip_address *address, int maskbits, int port);

#if 0
/* IKEv2 */
err_t ts_to_subnet(const ip_address *starting_address, const ip_address *ending address,
		   uint16_t start_port, uint16_t end_port);
/* IKEv1? */
#endif

/*
 * Format as a string.
 */

typedef struct {
	char buf[sizeof(address_buf) + 4/*/NNN*/];
} subnet_buf;
extern const char *str_subnet(const ip_subnet *subnet, subnet_buf *out);
extern void jam_subnet(struct lswlog *buf, const ip_subnet *subnet);

/*
 * Extract details
 */

/* mutually exclusive */
#if 0
extern const ip_subnet subnet_invalid;
#define subnet_is_invalid(S) (subnet_type(S) == NULL)
bool subnet_is_any(const ip_subnet *subnet);
#endif
bool subnet_is_specified(const ip_subnet *subnet);

const struct ip_info *subnet_type(const ip_subnet *subnet);

/* when applied to an address, leaves just the routing prefix */
extern ip_address subnet_mask(const ip_subnet *subnet);

/* [floor..ceiling] vs [floor..roof) */
/* PREFIX&MASK; aka IPv4 network, IPv6 anycast */
extern ip_address subnet_floor(const ip_subnet *subnet);
/* PREFIX|~MASK; aka IPv4 broadcast but not IPv6 */
extern ip_address subnet_ceiling(const ip_subnet *subnet);

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

/* tests */
extern bool samesubnet(const ip_subnet *a, const ip_subnet *b);
extern bool addrinsubnet(const ip_address *a, const ip_subnet *s);
extern bool subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
extern bool subnetishost(const ip_subnet *s);
extern bool samesubnettype(const ip_subnet *a, const ip_subnet *b);
#define subnetisaddr(sn, a) (subnetishost(sn) && addrinsubnet((a), (sn)))
extern bool subnetisnone(const ip_subnet *sn);

#endif
