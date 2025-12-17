/* resolve helper, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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
 *
 */

#ifndef RESOLVE_HELPER_H
#define RESOLVE_HELPER_H

#include "verbose.h"
#include "end.h"
#include "defaultroute.h"

struct logger;
struct connection;

struct resolved_host_addrs {
	struct route_addrs resolve[END_ROOF];
	const struct ip_info *afi;
	bool ok;
};

typedef void (resolve_helper_cb)(struct connection *c,
				 const struct resolved_host_addrs *resolved_host_addrs,
				 struct verbose verbose);

void request_resolve_help(struct connection *c,
			  resolve_helper_cb *callback,
			  struct logger *logger);

#endif
