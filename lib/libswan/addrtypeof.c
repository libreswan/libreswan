/*
 * extract parts of an ip_address
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

#include "ip_address.h"

/*
   - addrtypeof - get the type of an ip_address
 */
int addrtypeof(src)
const ip_address * src;
{
	return src->u.v4.sin_family;
}

/*
   - addrbytesptr_read - get pointer to the address bytes of an ip_address for reading
 */
size_t                          /* 0 for error */
addrbytesptr_read(src, dstp)
const ip_address * src;
const unsigned char **dstp;   /* NULL means just a size query */
{
	const unsigned char *p;
	size_t n;

	switch (src->u.v4.sin_family) {
	case AF_INET:
		p = (const unsigned char *) &src->u.v4.sin_addr.s_addr;
		n = 4;
		break;
	case AF_INET6:
		p = (const unsigned char *) &src->u.v6.sin6_addr;
		n = 16;
		break;
	default:
		return 0;
	}

	if (dstp != NULL)
		*dstp = p;
	return n;
}

/*
   - addrbytesptr_write - get pointer to the address bytes of an ip_address for writing
 */
size_t                          /* 0 for error */
addrbytesptr_write(src, dstp)
ip_address * src;
unsigned char **dstp;   /* NULL means just a size query */
{
	unsigned char *p;
	size_t n;

	switch (src->u.v4.sin_family) {
	case AF_INET:
		p = (unsigned char *)&src->u.v4.sin_addr.s_addr;
		n = 4;
		break;
	case AF_INET6:
		p = (unsigned char *)&src->u.v6.sin6_addr;
		n = 16;
		break;
	default:
		return 0;

		break;
	}

	if (dstp != NULL)
		*dstp = p;
	return n;
}

/*
   - addrlenof - get length of the address bytes of an ip_address
 */
size_t                          /* 0 for error */
addrlenof(src)
const ip_address * src;
{
	return addrbytesptr_read(src, NULL);
}

/*
   - addrbytesof - get the address bytes of an ip_address
 */
size_t                          /* 0 for error */
addrbytesof(src, dst, dstlen)
const ip_address * src;
unsigned char *dst;
size_t dstlen;
{
	const unsigned char *p;
	size_t n;
	size_t ncopy;

	n = addrbytesptr_read(src, &p);
	if (n == 0)
		return 0;

	if (dstlen > 0) {
		ncopy = n;
		if (ncopy > dstlen)
			ncopy = dstlen;
		memcpy(dst, p, ncopy);
	}
	return n;
}
