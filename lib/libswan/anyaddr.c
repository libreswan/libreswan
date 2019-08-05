/*
 * special addresses
 * Copyright (C) 2000  Henry Spencer.
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

#include <string.h>
#include <arpa/inet.h>		/* for ntohl() */

#include "ip_address.h"

#ifndef IN6ADDR_LOOPBACK_INIT
#define IN6ADDR_LOOPBACK_INIT   { { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
				      0, 1 } } }
#endif

static struct in6_addr v6loop = IN6ADDR_LOOPBACK_INIT;

/*
 * isanyaddr - test for the any-address value; this version treats 0
 * (aka AF_UNSPEC?) as any addr!
 */
int isanyaddr(src)
const ip_address * src;
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
	case AF_INET6:
		return address_is_any(src);
	case 0:
		/* a zeroed structure is considered any address */
		return 1;
	default:
		return 0;
	}
}

/*
   - isloopbackaddr - test for the loopback-address value
 */
int isloopbackaddr(src)
const ip_address * src;
{
	uint32_t v4loop = htonl(INADDR_LOOPBACK);
	int cmp;

	switch (src->u.v4.sin_family) {
	case AF_INET:
		cmp = memcmp(&src->u.v4.sin_addr.s_addr, &v4loop,
			     sizeof(v4loop));
		break;
	case AF_INET6:
		cmp = memcmp(&src->u.v6.sin6_addr, &v6loop, sizeof(v6loop));
		break;
	default:
		return 0;
	}

	return (cmp == 0) ? 1 : 0;
}
