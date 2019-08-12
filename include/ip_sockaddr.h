/* unix socaddr mashup, for libreswan

 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef IP_SOCKADDR_H
#define IP_SOCKADDR_H

#include <netinet/in.h>		/* for struct sockaddr_in */
#ifdef HAVE_INET6_IN6_H
#include <netinet6/in6.h>	/* for struct sockaddr_in6 */
#endif

/*
 * Size the socaddr buffer big enough for all known
 * alternatives.  On linux, at least, this isn't true:
 *
 * passert(sizeof(struct sockaddr) >= sizeof(struct sockaddr_in));
 * passert(sizeof(struct sockaddr) >= sizeof(struct sockaddr_in6));
 */

typedef union {
	/* sa.sa_* */
	struct sockaddr sa;
	/* sin.sin_* */
	struct sockaddr_in sin;
	/* sin6.sin6_* */
	struct sockaddr_in6 sin6;
} ip_sockaddr;

#endif
