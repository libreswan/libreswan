/*
 * initialize address structure
 * Copyright (C) 2000  Henry Spencer.
 * Copyroght (C) 2009 Paul Wouters <paul@xelerance.com>
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

#include <string.h>

#include "ip_address.h"
#include "libreswan/passert.h"

/*
   - initaddr - initialize ip_address from bytes
 */
err_t initaddr(const unsigned char *src, size_t srclen, int af, ip_address *dst)
{
	switch (af) {
	case AF_INET:
		if (srclen != 4)
			return "IPv4 address must be exactly 4 bytes";
		passert(srclen == sizeof(struct in_addr));
		*dst = address_from_in_addr((const struct in_addr *)src);
		break;
	case AF_INET6:
		if (srclen != 16)
			return "IPv6 address must be exactly 16 bytes";
		passert(srclen == sizeof(struct in6_addr));
		*dst = address_from_in6_addr((const struct in6_addr *)src);
		break;
	default:
		return "unknown address family in initaddr";
	}
	return NULL;
}
