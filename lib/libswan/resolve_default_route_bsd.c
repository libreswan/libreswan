/* BSD route resolution, for libreswan
 *
 * Copyright (C) 2017 Antony Antony
 * Copyright (C) 2018 Paul Wouters
 * Copyright (C) 2022 Andrew Cagney

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

#include "addr_lookup.h"
#include "constants.h"
#include "ipsecconf/confread.h"
#include "lswlog.h"		/* for fatal() */

void resolve_default_route(struct starter_end *host,
			   struct starter_end *peer,
			   lset_t verbose_rc_flags UNUSED,
			   struct logger *logger)
{
	/* What kind of result are we seeking? */
	bool seeking_src = (host->addrtype == KH_DEFAULTROUTE ||
			    peer->addrtype == KH_DEFAULTROUTE);
	bool seeking_gateway = (host->nexttype == KH_DEFAULTROUTE ||
				peer->nexttype == KH_DEFAULTROUTE);
	if (!seeking_src && !seeking_gateway)
		return;	/* this end already figured out */

	fatal(PLUTO_EXIT_FAIL, logger,
	      "addcon: without XFRM, cannot resolve_defaultroute()");
}

enum route_status get_route(ip_address dest UNUSED, struct ip_route *route UNUSED, struct logger *logger UNUSED)
{
	return ROUTE_GATEWAY_FAILED;
}
