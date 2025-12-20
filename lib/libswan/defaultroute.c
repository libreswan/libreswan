/*
 * addr_lookup: resolve_defaultroute_one() -- attempt to resolve a default route
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
 */

#include "defaultroute.h"

bool route_addr_needs_dns(const struct route_addr *addr)
{
	return (addr->type == KH_IPHOSTNAME &&
		!address_is_specified(addr->addr));
}


bool route_addrs_need_dns(const struct route_addrs *addrs)
{
	return (route_addr_needs_dns(&addrs->host) ||
		route_addr_needs_dns(&addrs->nexthop));
}

