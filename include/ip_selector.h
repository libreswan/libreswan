/* ip traffic selector, for libreswan
 *
 * Copyright (C) 2020-2021  Andrew Cagney
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

#ifndef IP_SELECTOR_H
#define IP_SELECTOR_H

#include "ip_address.h"
#include "ip_endpoint.h"
#include "ip_subnet.h"
#include "ip_protoport.h"
#include "ip_protocol.h"
#include "ip_cidr.h"
#include "ip_range.h"
#include "ip_bytes.h"
#include "ip_version.h"
#include "ip_index.h"

struct jambuf;

/*
 * IKEv2 style traffic selectors can describe.
 *
 *    LO_ADDRESS..HI_ADDRESS : LO_PORT..HI_PORT
 *
 * However, this is currently implemented using a subnet which,
 * bizarrely, can describe:
 *
 *    NETWORK_PREFIX | 0 / MASK : PORT
 *
 * where PORT==0 imples 0..65535, and (presumably) port can only be
 * non-zero when the NETWORK_PREFIX/MASK is for a single address.
 */

typedef struct {
	bool is_set;
	/*
	 * Index into the struct ip_info array; must be stream
	 * friendly.
	 */
	enum ip_version ip_version; /* 0, IPv4(4), IPv6(6) */
	/*
	 * We need something that makes static IPv4 initializers
	 * possible (struct in_addr requires htonl() which is run-time
	 * only).
	 */
	struct ip_bytes lo;
	struct ip_bytes hi;
	unsigned ipproto;
	/*
	 * For moment, one port
	 */
	int hport;
} ip_selector;

#define PRI_SELECTOR "<selector-%s:IPv%d,%s["PRI_IP_BYTES".."PRI_IP_BYTES"]:%u>"
#define pri_selector(S)						\
		((S)->is_set ? "set" : "unset"),		\
		(S)->ip_version,					\
		((S)->ipproto > 255 ? "IPPROTO>255" :		\
		 protocol_from_ipproto((S)->ipproto)->name),	\
		pri_ip_bytes((S)->lo),				\
		pri_ip_bytes((S)->hi),				\
		(S)->hport

void pexpect_selector(const ip_selector *s, where_t where);
#define pselector(S) pexpect_selector(S, HERE)

ip_selector selector_from_raw(where_t where, const struct ip_info *afi,
			      const struct ip_bytes lo,
			      const struct ip_bytes hi,
			      const struct ip_protocol *protocol, const ip_port port);

ip_selector selector_from_address(const ip_address address);
ip_selector selector_from_address_protocol(const ip_address address,
					   const struct ip_protocol *protocol);
ip_selector selector_from_address_protocol_port(const ip_address address,
						const struct ip_protocol *protocol,
						const ip_port port);

ip_selector selector_from_endpoint(const ip_endpoint address);

ip_selector selector_from_cidr(const ip_cidr cidr);

ip_selector selector_from_subnet(const ip_subnet subnet);
ip_selector selector_from_subnet_protocol_port(const ip_subnet subnet,
					       const struct ip_protocol *protocol,
					       const ip_port port);

ip_selector selector_from_range(const ip_range range);
ip_selector selector_from_range_protocol_port(const ip_range range,
					      const struct ip_protocol *protocol,
					      const ip_port port);

ip_selector selector_from_address_protoport(const ip_address address,
					    const ip_protoport protoport);
ip_selector selector_from_subnet_protoport(const ip_subnet subnet,
					   const ip_protoport protoport);

err_t ttoselector_num(shunk_t src, const struct ip_info *afi,
		      ip_selector *dst, ip_address *nonzero_host);

/* comma/space separated list */

typedef struct {
	unsigned len;
	ip_selector *list;
} ip_selectors;

extern const ip_selectors empty_ip_selectors;

diag_t ttoselectors_num(shunk_t input, const char *delims,
			const struct ip_info *afi,
			ip_selectors *output, ip_address *nonzero_host);

size_t jam_selectors(struct jambuf *buf, const ip_selectors selectors);

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

extern const ip_selector unset_selector;

bool selector_is_unset(const ip_selector *selector);			/* handles NULL */
const struct ip_info *selector_type(const ip_selector *selector);	/* handles NULL */
const struct ip_info *selector_info(const ip_selector selector);

bool selector_is_zero(const ip_selector selector);	/* ::/128 or 0.0.0.0/32 */
bool selector_is_all(const ip_selector selector);	/* ::/0 or 0.0.0.0/0 */
bool selector_is_subnet(const ip_selector selector);	/* i.e., no proto/port */
bool selector_is_address(const ip_selector selector);

/* attributes */

const struct ip_protocol *selector_protocol(const ip_selector selector);
ip_range selector_range(const ip_selector selector);
ip_port selector_port(const ip_selector selector);
/* ip_ports selector_port_range(const ip_selector *selector); */

/* hacks */
int selector_hport(const ip_selector selector);

/* assuming a subnet like XFRM does */
ip_address selector_prefix(const ip_selector selector);
ip_address selector_prefix_mask(const ip_selector selector);

int selector_prefix_len(const ip_selector selector); /* <0 when non-CIDR*/
int selector_host_len(const ip_selector selector); /* <0 when non-CIDR*/

bool address_in_selector(const ip_address l, const ip_selector r);
bool endpoint_in_selector(const ip_endpoint l, const ip_selector r);
bool subnet_in_selector(const ip_subnet l, const ip_selector r);
bool range_in_selector(const ip_range l, const ip_selector r);
bool selector_in_selector(const ip_selector l, const ip_selector r);

bool selector_eq_address(const ip_selector selector, const ip_address address);
bool selector_eq_endpoint(const ip_selector selector, const ip_endpoint endpoint);
bool selector_eq_subnet(const ip_selector selector, const ip_subnet subnet);
bool selector_eq_range(const ip_selector selector, const ip_range range);
bool selector_eq_selector(const ip_selector l, const ip_selector r);

bool selector_overlaps_selector(const ip_selector l, const ip_selector r);

/* printing */

typedef struct {
	char buf[(sizeof(address_buf) + 4/*/NNN*/ + 6/*/CHAOS*/ + 6/*/65535*/)*2 + 1/*-*/];
} selector_buf;

const char *str_selector(const ip_selector *selector, selector_buf *out);
const char *str_selector_range(const ip_selector *selector, subnet_buf *buf);
const char *str_selector_range_port(const ip_selector *selector, selector_buf *out);

size_t jam_selector(struct jambuf *buf, const ip_selector *selector);
size_t jam_selector_range(struct jambuf *buf, const ip_selector *selector);
size_t jam_selector_range_port(struct jambuf *buf, const ip_selector *selector);

typedef struct {
	char buf[sizeof(selector_buf) + sizeof("=UNKNOWN=UNKNOWN=>") + sizeof(selector_buf)];
} selector_pair_buf;

const char *str_selector_pair(const ip_selector *src, const ip_selector *dst, selector_pair_buf *out);
size_t jam_selector_pair(struct jambuf *buf, const ip_selector *src, const ip_selector *dst);

const char *str_selector_pair_sensitive(const ip_selector *src, const ip_selector *dst, selector_pair_buf *out);
size_t jam_selector_pair_sensitive(struct jambuf *buf, const ip_selector *src, const ip_selector *dst);

/*
 * XXX: hacks to get around .client not containing a proper selector
 * and instead needing to compare just the client's subnet.
 *
 * These are needed by code manipulating end.client because it is
 * serving double time.  It holding either:
 *
 * - the configured client subnet
 * - a connection's shunt
 */

ip_subnet selector_subnet(const ip_selector selector);
bool selector_range_eq_selector_range(const ip_selector lhs, const ip_selector rhs);
bool address_in_selector_range(const ip_address l, const ip_selector r);

#endif
