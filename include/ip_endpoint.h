/* ip endpoint (address + port), for libreswan
 *
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

#ifndef IP_ENDPOINT_H
#define IP_ENDPOINT_H

#include <stdbool.h>

#include "chunk.h"
#include "err.h"
#include "ip_address.h"
#include "ip_sockaddr.h"

struct lswlog;

/*
 * ip_endpoint and ip_address should be distinct types where the
 * latter consists of ADDRESS:PORT.  Unfortunately separating them is
 * going to be slow.
 *
 * Defining ENDPOINT_TYPE causes the the types to become distinct.
 */

#ifdef ENDPOINT_TYPE
typedef struct {
	ip_address address;
	/*
	 * In pluto "0" denotes all ports (or, in the context of an
	 * endpoint, is that none?).
	 */
	int hport;
} ip_endpoint;
#else
typedef ip_address ip_endpoint;
#endif

/*
 * Constructors.
 */

ip_endpoint endpoint(const ip_address *address, int port);

/*
 * Formatting
 *
 * Endpoint formatting is always "cooked".  For instance, the address
 * "::1" is printed as "[::1]:PORT" (raw would print it as
 * "[0:0....:0]:PORT"
 */

typedef struct {
	char buf[1/*[*/ + sizeof(address_buf) + 1/*]*/ + 5/*:65535*/];
} endpoint_buf;

const char *str_endpoint(const ip_endpoint *, endpoint_buf *);
void jam_endpoint(struct lswlog *, const ip_endpoint*);
const char *str_sensitive_endpoint(const ip_endpoint *, endpoint_buf *);
void jam_sensitive_endpoint(struct lswlog *, const ip_endpoint*);

/*
 * Logic
 */

bool endpoint_eq(const ip_endpoint l, ip_endpoint r);

/*
 * Magic values.
 *
 * XXX: While the headers call the all-zero address "ANY" (INADDR_ANY,
 * IN6ADDR_ANY_INIT), the headers also refer to the IPv6 value as
 * unspecified (for instance IN6_IS_ADDR_UNSPECIFIED()) leaving the
 * term "unspecified" underspecified.
 *
 * Consequently to identify an AF_UNSPEC (i.e., uninitialized)
 * address, see if *_type() returns NULL.
 */

/* AF_UNSPEC(==0); ADDR = 0; PORT = 0, */
#ifdef ENDPOINT_TYPE
extern const ip_endpoint endpoint_invalid;
#else
#define endpoint_invalid address_invalid
#endif

/* mutually exclusive */
#if 0
#define endpoint_is_invalid(A) (endpoint_type(A) == NULL)
bool endpoint_is_any(const ip_endpoint *endpoint);
#endif
bool endpoint_is_specified(const ip_endpoint *endpoint);

/* returns NULL when address_invalid */
const struct ip_info *endpoint_type(const ip_endpoint *endpoint);

/* Host or Network byte order */
int endpoint_hport(const ip_endpoint *endpoint);
int endpoint_nport(const ip_endpoint *endpoint);

ip_endpoint set_endpoint_hport(const ip_endpoint *endpoint,
			       int hport) MUST_USE_RESULT;

#define update_endpoint_hport(ENDPOINT, HPORT)			\
	{ *(ENDPOINT) = set_endpoint_hport(ENDPOINT, HPORT); }
#define update_endpoint_nport(ENDPOINT, NPORT)			\
	{ *(ENDPOINT) = set_endpoint_hport(ENDPOINT, ntohs(NPORT)); }

/* currently forces port to zero */
ip_address endpoint_address(const ip_endpoint *endpoint);

/*
 * conversions
 */

/* convert the endpoint to a sockaddr; return true size */
size_t endpoint_to_sockaddr(const ip_endpoint *endpoint, ip_sockaddr *sa);
/* convert sockaddr to an endpoint */
err_t sockaddr_to_endpoint(const ip_sockaddr *sa, socklen_t sa_len, ip_endpoint *endpoint);

/*
 * Old style.
 */

/*
 * XXX: compatibility.
 *
 * setportof() should be replaced by update_{subnet,endpoint}_nport();
 * code is assuming ip_subnet.addr is an endpoint.
 */
#define portof(SRC) endpoint_nport((SRC))
#define setportof(PORT, DST) update_endpoint_nport(DST, PORT)

#endif
