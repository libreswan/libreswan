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

struct lswlog;

/*
 * XXX: while ip_endpoint and ip_address should be unique types where
 * an endpoint has both an address and a port, separating them is a
 * mess.
 */

#ifdef ENDPOINT_ADDRESS_PORT
typedef struct {
	ip_address address;
	int port;
} ip_endpoint;
#else
typedef ip_address ip_endpoint;
#endif

ip_endpoint endpoint(const ip_address *address, int port);
err_t sockaddr_as_endpoint(const struct sockaddr *sa, socklen_t sa_len, ip_endpoint *endpoint);

int endpoint_port(const ip_endpoint *endpoint);
ip_endpoint set_endpoint_port(const ip_endpoint *endpoint, int port);

/* forces port to zero */
ip_address endpoint_address(const ip_endpoint *endpoint);
int endpoint_type(const ip_endpoint *endpoint);
const struct ip_info *endpoint_info(const ip_endpoint *endpoint);

/*
 * formatting
 */

typedef struct {
	char buf[1/*[*/ + sizeof(address_buf) + 1/*]*/ + 5/*:65535*/];
} endpoint_buf;

/*
 * Always cooked.
 */
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
 * Consequently, "invalid" refers to AF_UNSPEC, "any" refers to
 * AF_{INET,INET6)=0, and "specified" refers to other stuff.
 */

/* AF_UNSPEC(==0); ADDR = 0; PORT = 0, */
#ifdef ENDPOINT_ADDRESS
extern ip_endpoint endpoint_invalid;
#else
#define endpoint_invalid address_invalid
#endif
bool endpoint_is_invalid(const ip_endpoint *address);
bool endpoint_is_valid(const ip_endpoint *address);

#endif
