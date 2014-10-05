/*
 * initialize address structure
 * Copyright (C) 2000  Henry Spencer.
 * Copyroght (C) 2009 Paul Wouters <paul@xelerance.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */
#include "libreswan.h"

err_t add_port(int af, ip_address *addr, unsigned short port)
{
	switch (af) {
	case AF_INET:
		addr->u.v4.sin_port = port;
		break;
	case AF_INET6:
		addr->u.v6.sin6_port = port;
		break;
	default:
		return "unknown address family in add_port";
	}
	return NULL;
}

/*
   - initaddr - initialize ip_address from bytes
 */
err_t                           /* NULL for success, else string literal */
initaddr(src, srclen, af, dst)
const unsigned char *src;
size_t srclen;
int af;                         /* address family */
ip_address *dst;
{
	switch (af) {
	case AF_INET:
		if (srclen != 4)
			return "IPv4 address must be exactly 4 bytes";

#if !defined(__KERNEL__)
		/* On BSD, the kernel compares the entire struct sockaddr when
		 * using bind(). However, this is as large as the largest
		 * address family, so the 'remainder' has to be 0. Linux
		 * compares interface addresses with the length of sa_len,
		 * instead of sizeof(struct sockaddr), so in that case padding
		 * is not needed.
		 *
		 * Patch by Stefan Arentz <stefan@soze.com>
		 */
		bzero(&dst->u.v4, sizeof(dst->u.v4));
#endif
		dst->u.v4.sin_family = af;
		dst->u.v4.sin_port = 0;
#ifdef NEED_SIN_LEN
		dst->u.v4.sin_len = sizeof(struct sockaddr_in);
#endif
		memcpy((char *)&dst->u.v4.sin_addr.s_addr, src, srclen);
		break;
	case AF_INET6:
		if (srclen != 16)
			return "IPv6 address must be exactly 16 bytes";

#if !defined(__KERNEL__)
		bzero(&dst->u.v6, sizeof(dst->u.v6));
#endif
		dst->u.v6.sin6_family = af;
		dst->u.v6.sin6_flowinfo = 0;            /* unused */
		dst->u.v6.sin6_port = 0;
#ifdef NEED_SIN_LEN
		dst->u.v6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		memcpy((char *)&dst->u.v6.sin6_addr, src, srclen);
		break;
	default:
		return "unknown address family in initaddr";
	}
	return NULL;
}
