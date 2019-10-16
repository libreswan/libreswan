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

#ifdef SUBNET_TYPE
#include "ip_address.h"
#else
#include "ip_endpoint.h"
#endif

#include "where.h"		/* used by endtosubnet() */

struct lswlog;

typedef struct {
#ifdef SUBNET_TYPE
	/*
	 * XXX: Data structure sufficient for IKEv2
	 */
	ip_address lo_address, hi_address;
	uint16_t lo_hport, hi_hport;
#else
	/* (routing)prefix|host(id):port */
	ip_endpoint addr;
	/* (routing prefix) bits */
	int maskbits;
#endif
} ip_subnet;

/*
 * Constructors
 */

/* ADDRESS..ADDRESS:0..65535 */
ip_subnet subnet_from_address(const ip_address *address);
/* ENDPOINT.ADDRESS..ENDPOINT.ADDRESS:ENDPOINT.PORT..ENDPOINT.PORT */
/* XXX: what hapens if ENDPOINT.PORT==0 */
ip_subnet subnet_from_endpoint(const ip_endpoint *endpoint);

/*
 * Format as a string.
 */

typedef struct {
	char buf[sizeof(address_buf) + 4/*/NNN*/ + 6/*:65535*/];
} subnet_buf;
extern const char *str_subnet(const ip_subnet *subnet, subnet_buf *out);
extern const char *str_subnet_port(const ip_subnet *subnet, subnet_buf *out);

extern void jam_subnet(struct lswlog *buf, const ip_subnet *subnet);
extern void jam_subnet_port(struct lswlog *buf, const ip_subnet *subnet);

/*
 * Extract details
 */

const struct ip_info *subnet_type(const ip_subnet *subnet);

/* mutually exclusive */
/* not very well defined, is no_addresses "specified" */
extern const ip_subnet subnet_invalid;
#if 0
#define subnet_is_invalid(S) (subnet_type(S) == NULL)
#endif
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
int subnet_nport(const ip_subnet *subnet);

ip_subnet set_subnet_hport(const ip_subnet *subnet,
			   int hport) MUST_USE_RESULT;

#define update_subnet_hport(SUBNET, HPORT)			\
	{ *(SUBNET) = set_subnet_hport(SUBNET, HPORT); }
#define update_subnet_nport(SUBNET, NPORT)			\
	{ *(SUBNET) = set_subnet_hport(SUBNET, ntohs(NPORT)); }

/* when applied to an address, leaves just the routing prefix */
extern ip_address subnet_mask(const ip_subnet *subnet);
/* Given ROUTING_PREFIX|HOST_ID return ROUTING_PREFIX|0 */
ip_address subnet_prefix(const ip_subnet *subnet);

extern const struct ip_blit set_bits;
extern const struct ip_blit clear_bits;
extern const struct ip_blit keep_bits;

ip_address subnet_blit(const ip_subnet *in,
		       const struct ip_blit *network,
		       const struct ip_blit *host);

/*
 * old
 */
#include "err.h"

extern err_t ttosubnet(const char *src, size_t srclen, int af, int clash, ip_subnet *dst);
extern void subnettot(const ip_subnet *src, int format, char *buf, size_t buflen);
#define SUBNETTOT_BUF   sizeof(subnet_buf)
extern err_t initsubnet(const ip_address *addr, int maskbits, int clash,
		 ip_subnet *dst);
extern err_t endtosubnet(const ip_endpoint *end, ip_subnet *dst, where_t where);
#define addrtosubnet(ADDR, DST) endtosubnet(ADDR, DST, HERE)

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
