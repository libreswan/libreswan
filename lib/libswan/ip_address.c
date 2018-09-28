/*
 * low-level ip_address ugliness
 *
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

#include "internal.h"
#include "libreswan.h"
#include "ip_address.h"
#include "lswlog.h"

/*
 * portof - get the port field of an ip_address in network order.
 *
 * Return -1 if ip_address isn't valid.
 */

int nportof(const ip_address * src)
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return src->u.v4.sin_port;

	case AF_INET6:
		return src->u.v6.sin6_port;

	default:
		return -1;
	}
}

int hportof(const ip_address *src)
{
	int nport = nportof(src);
	if (nport >= 0) {
		return ntohs(nport);
	} else {
		return -1;
	}
}

/*
 * setportof - set the network ordered port field of an ip_address
 */

ip_address nsetportof(int port /* network order */, ip_address dst)
{
	switch (dst.u.v4.sin_family) {
	case AF_INET:
		dst.u.v4.sin_port = port;
		break;
	case AF_INET6:
		dst.u.v6.sin6_port = port;
		break;
	default:
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("Will not set port on bogus address 0.0.0.0");
	}
	return dst;
}

ip_address hsetportof(int port /* host byte order */, ip_address dst)
{
	return nsetportof(htons(port), dst);
}

/*
 * sockaddrof - get a pointer to the sockaddr hiding inside an ip_address
 */
struct sockaddr *sockaddrof(const ip_address *src)
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return (struct sockaddr *)&src->u.v4;

	case AF_INET6:
		return (struct sockaddr *)&src->u.v6;

	default:
		return NULL;	/* "can't happen" */
	}
}

/*
 * sockaddrlenof - get length of the sockaddr hiding inside an ip_address
 *
 * Return 0 on error.
 */
size_t sockaddrlenof(const ip_address * src)
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return sizeof(src->u.v4);

	case AF_INET6:
		return sizeof(src->u.v6);

	default:
		return 0;
	}
}

/*
 * simplified interface to addrtot()
 *
 * Caller should allocate a buffer to hold the result as long
 * as the resulting string is needed.  Usually just long enough
 * to output.
 */

const char *ipstr(const ip_address *src, ipstr_buf *b)
{
	addrtot(src, 0, b->private_buf, sizeof(b->private_buf));
	return b->private_buf;
}
