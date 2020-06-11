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

struct lswlog;
struct ip_protocol;

/*
 * ip_endpoint and ip_address should be distinct types where the
 * latter consists of ADDRESS:PORT.  Unfortunately separating them is
 * going to be slow.
 *
 * Defining ENDPOINT_TYPE causes the the types to become distinct.
 */

#ifdef ENDPOINT_TYPE
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
	struct ip_bytes { uint8_t byte[16]; } bytes;
	/*
	 * In pluto "0" denotes all ports (or, in the context of an
	 * endpoint, is that none?).
	 */
	int hport;
	unsigned ipproto;
	bool is_endpoint;
} ip_endpoint;
#else
typedef ip_address ip_endpoint;
#endif

#define pendpoint(E)							\
	{								\
		if ((E) != NULL && (E)->version != 0) {			\
			/* i.e., is set */				\
			if ((E)->is_endpoint == false ||		\
			    (E)->is_address == true ||			\
			    (E)->hport == 0 ||				\
			    (E)->ipproto == 0) {			\
				address_buf b_;				\
				where_t here_ = HERE;			\
				dbg("EXPECTATION FAILED: %s is not an endpoint; "PRI_ADDRESS" "PRI_WHERE, \
				    #E, pri_address(E, &b_),		\
				    pri_where(here_));			\
			}						\
		}							\
	}

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
 */

typedef struct {
	char buf[1/*[*/ + sizeof(address_buf) + 1/*]*/ + 5/*:65535*/];
} endpoint_buf;

const char *str_endpoint(const ip_endpoint *, endpoint_buf *);
size_t jam_endpoint(struct lswlog *, const ip_endpoint*);
const char *str_sensitive_endpoint(const ip_endpoint *, endpoint_buf *);
size_t jam_sensitive_endpoint(struct lswlog *, const ip_endpoint*);

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
 * Consequently an AF_UNSPEC address (i.e., uninitialized or unset),
 * is identified by *_type() returning NULL.
 */

extern const ip_endpoint unset_endpoint;

const struct ip_info *endpoint_type(const ip_endpoint *endpoint);
const struct ip_protocol *endpoint_protocol(const ip_endpoint *endpoint);
ip_address endpoint_address(const ip_endpoint *endpoint);

bool endpoint_is_set(const ip_endpoint *endpoint);
bool endpoint_is_any(const ip_endpoint *endpoint);
bool endpoint_is_specified(const ip_endpoint *endpoint);

/* Host or Network byte order */
int endpoint_hport(const ip_endpoint *endpoint);
ip_port endpoint_port(const ip_endpoint *endpoint);

ip_endpoint set_endpoint_hport(const ip_endpoint *endpoint,
			       int hport) MUST_USE_RESULT;
ip_endpoint set_endpoint_address(const ip_endpoint *endpoint,
				 const ip_address) MUST_USE_RESULT;

/*
 * Old style.
 */

/*
 * XXX: compatibility.
 *
 * setportof() should be replaced by update_{subnet,endpoint}_nport();
 * code is assuming ip_subnet.addr is an endpoint.
 */
#define portof(SRC) nport(endpoint_port((SRC)))
#define setportof(NPORT, ENDPOINT) { *(ENDPOINT) = set_endpoint_hport((ENDPOINT), ntohs(NPORT)); }

#endif
