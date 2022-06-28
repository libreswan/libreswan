/* routecheck, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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
 */

#include "lswtool.h"
#include "lswlog.h"
#include "addr_lookup.h"
#include "ip_address.h"
#include "stdlib.h"

int main(int argc, char **argv)
{
	struct logger *logger = tool_init_log(argv[0]);

	if (argc == 1) {
		llog(WHACK_STREAM|NO_PREFIX, logger, "Usage:");
		llog(WHACK_STREAM|NO_PREFIX, logger, "  ipsec showroute <destination-address>");
		llog(WHACK_STREAM|NO_PREFIX, logger, "prints:");
		llog(WHACK_STREAM|NO_PREFIX, logger, "  <host-interface> <gateway> <destination-address>");
		llog(WHACK_STREAM|NO_PREFIX, logger, "for the given <destination-address>");
		exit(1);
	}

	ip_address dst;
	err_t e = ttoaddress_dns(shunk1(argv[1]), NULL, &dst);
	if (e != NULL) {
		llog(WHACK_STREAM, logger, "%s: %s", argv[1], e);
		exit(1);
	}

	struct ip_route route;
	switch (get_route(dst, &route, logger)) {
	case ROUTE_SUCCESS:
	{
		address_buf sb, gb, ab;
		llog(WHACK_STREAM|NO_PREFIX, logger, "%s %s %s",
		     str_address(&route.source, &sb),
		     str_address(&route.gateway, &gb),
		     str_address(&dst, &ab));
		exit(0);
	}
	case ROUTE_GATEWAY_FAILED:
	{
		address_buf ab;
		llog(ERROR_STREAM, logger, "%s: gateway failed",
		     str_address(&dst, &ab));
		exit(1);
	}
	case ROUTE_SOURCE_FAILED:
	{
		address_buf ab;
		llog(ERROR_STREAM, logger, "%s: source failed",
		     str_address(&dst, &ab));
		exit(1);
	}
	case ROUTE_FATAL:
	{
		address_buf ab;
		llog(ERROR_STREAM, logger, "%s: fatal",
		     str_address(&dst, &ab));
		exit(1);
	}
	}

	exit(1);
}
