/* ip endpoint (address + port), for libreswan
 *
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

#ifndef IP_ENDPOINT_H
#define IP_ENDPOINT_H

#include <stdbool.h>

#include "chunk.h"
#include "err.h"
#include "ip_address.h"
#include "ip_port.h"
#include "ip_protoport.h"

struct jambuf;
struct ip_protocol;

/*
 * ip_endpoint and ip_address should be distinct types where the
 * latter consists of ADDRESS:PORT.  Unfortunately separating them is
 * going to be slow.
 *
 * Defining ENDPOINT_TYPE causes the the types to become distinct.
 */

typedef struct {
	/*
	 * Index into the struct ip_info array; must be stream
	 * friendly.
	 */
	unsigned version; /* 0, 4, 6 */
	/*
	 * We need something that makes static IPv4 initializers possible
	 * (struct in_addr requires htonl() which is run-time only).
	 */
	struct ip_bytes bytes;
	/*
	 * In pluto "0" denotes all ports (or, in the context of an
	 * endpoint, is that none?).
	 */
	int hport;
	unsigned ipproto;
	bool is_endpoint;
/*ifndef ENDPOINT_TYPE*/
	bool is_address;
/*#endif*/
} ip_endpoint;

#define PRI_ENDPOINT "%s (version=%d hport=%u ipproto=%u is_address=%s is_endpoint=%s)"
#define pri_endpoint(A, B)						\
		str_endpoint(A, B),					\
		(A)->version,						\
		(A)->hport,						\
		(A)->ipproto,						\
		bool_str((A)->is_address),				\
		bool_str((A)->is_endpoint)

void pexpect_endpoint(const ip_endpoint *e, const char *t, where_t where);
#define pendpoint(E) pexpect_endpoint(E, #E, HERE)

ip_address strip_endpoint(const ip_endpoint *address, where_t where);

/*
 * Constructors.
 */

ip_endpoint endpoint(const ip_address *address, int port);

ip_endpoint endpoint3(const struct ip_protocol *protocol,
		      const ip_address *address, ip_port port);

/*
 * Formatting
 *
 * Endpoint formatting is always "cooked".  For instance, the address
 * "::1" is printed as "[::1]:PORT" (raw would print it as
 * "[0:0....:0]:PORT"
 *
 * XXX: sizeof("") includes '\0'.  What's an extra few bytes between
 * friends?
 */

typedef struct {
	char buf[sizeof("[") + sizeof(address_buf) + sizeof("]:65535")];
} endpoint_buf;

const char *str_endpoint(const ip_endpoint *, endpoint_buf *);
size_t jam_endpoint(struct jambuf *, const ip_endpoint*);
const char *str_sensitive_endpoint(const ip_endpoint *, endpoint_buf *);
size_t jam_sensitive_endpoint(struct jambuf *, const ip_endpoint*);

typedef struct {
	char buf[sizeof(endpoint_buf) + sizeof("--UNKNOWN--UNKNOWN-->") + sizeof(endpoint_buf)];
} endpoints_buf;

size_t jam_endpoints(struct jambuf *jambuf, const ip_endpoint *src, const ip_endpoint *dst);
const char *str_endpoints(const ip_endpoint *src, const ip_endpoint *dst, endpoints_buf *buf);

/*
 * Logic
 */

bool endpoint_eq(const ip_endpoint *l, const ip_endpoint *r);
bool endpoint_address_eq(const ip_endpoint *endpoint, const ip_address *address);

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

extern const ip_endpoint unset_endpoint;
bool endpoint_is_unset(const ip_endpoint *endpoint);

const struct ip_info *endpoint_type(const ip_endpoint *endpoint);
const struct ip_protocol *endpoint_protocol(const ip_endpoint *endpoint);

bool endpoint_is_any(const ip_endpoint *endpoint);
bool endpoint_is_specified(const ip_endpoint *endpoint);

ip_address endpoint_address(const ip_endpoint *endpoint);
ip_endpoint set_endpoint_address(const ip_endpoint *endpoint,
				 const ip_address) MUST_USE_RESULT;

ip_port endpoint_port(const ip_endpoint *endpoint);
ip_endpoint set_endpoint_port(const ip_endpoint *endpoint,
			      ip_port port) MUST_USE_RESULT;
void update_endpoint_port(ip_endpoint *endpoint, ip_port port);

int endpoint_hport(const ip_endpoint *endpoint);

#endif
