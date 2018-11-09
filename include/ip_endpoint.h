/* ip endpoint (address + port), for libreswan
 *
 * Copyright (C) 2018  Andrew Cagney
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

/*
 * XXX: while ip_endpoint and ip_address should be separate doing so
 * is a mess.
 */
#ifdef IP_ENDPOINT
#include <sys/socket.h>
typedef struct {
	struct sockaddr socket;
} ip_endpoint;
#else
#include "ip_address.h"
typedef ip_address ip_endpoint;
#endif

struct lswlog;

ip_endpoint endpoint(const ip_address *address, int port);

/* forces port to zero */
ip_address endpoint_address(const ip_endpoint *endpoint);
int endpoint_port(const ip_endpoint *endpoint);
int endpoint_type(const ip_endpoint *endpoint);

/*
 * formatting
 */

typedef struct {
	char buf[1/*[*/ + sizeof(ip_address_buf) + 1/*]*/ + 5/*:65535*/];
} ip_endpoint_buf;

/*
 * Always cooked.
 */
const char *str_endpoint(const ip_endpoint *, ip_endpoint_buf *);
void fmt_endpoint(struct lswlog *, const ip_endpoint*);
const char *str_sensitive_endpoint(const ip_endpoint *, ip_endpoint_buf *);
void fmt_sensitive_endpoint(struct lswlog *, const ip_endpoint*);

#endif
