/* default route lookup, for libreswan
 *
 * Copyright (C) 2018,2022 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef ADDR_LOOKUP_H
#define ADDR_LOOKUP_H

#include <stdbool.h>

#include "verbose.h"
#include "ip_address.h"

struct starter_end;
struct logger;

struct resolve_host {
	enum keyword_host type;
	ip_address addr;
	const char *name;
};

struct resolve_end {
	const char *leftright;
	struct resolve_host host;
	struct resolve_host nexthop; /* aka gateway */
};

void resolve_default_route(struct resolve_end *host,
			   struct resolve_end *peer,
			   const struct ip_info *host_afi,
			   struct verbose verbose);

enum route_status {
	ROUTE_SUCCESS,
	ROUTE_GATEWAY_FAILED,
	ROUTE_SOURCE_FAILED,
	ROUTE_FATAL, /* already logged */
};

struct ip_route {
	ip_address source;
	ip_address gateway;
};

enum route_status get_route(ip_address dest, struct ip_route *route, struct logger *logger);

#endif
