/*
 * convert from text form of subnet specification to binary
 *
 * Copyright (C) 2000  Henry Spencer.
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
 */

#include <string.h>

#include "ip_subnet.h"
#include "libreswan.h"		/* for ttoulb() */

#ifndef DEFAULTSUBNET
#define DEFAULTSUBNET "%default"
#endif

/*
 * ttosubnet - convert text "addr/mask" to address and mask
 * Mask can be integer bit count.
 */
err_t ttosubnet(src, srclen, af, dst)
const char *src;
size_t srclen;	/* 0 means "apply strlen" */
int af;	/* AF_INET or AF_INET6 */
ip_subnet *dst;
{
	const char *slash;
	const char *colon;
	const char *mask;
	size_t mlen;
	const char *oops;
	unsigned long bc;
	static const char def[] = DEFAULTSUBNET;
#define DEFLEN (sizeof(def) - 1)	/* -1 for NUL */
	static const char defis4[] = "0/0";
#define DEFIS4LEN (sizeof(defis4) - 1)
	static const char defis6[] = "::/0";
#define DEFIS6LEN (sizeof(defis6) - 1)
	ip_address addrtmp;
	ip_address masktmp;
	int nbits;
	int i;

	if (srclen == 0) {
		srclen = strlen(src);
		if (srclen == 0)
			return "empty string";
	}

	/*
	 * you cannot use af==AF_UNSPEC and src=0/0,
	 * makes no sense as will it be AF_INET
	 */
	if (srclen == DEFLEN && strncmp(src, def, srclen) == 0) {
		switch (af) {
		case AF_INET:
			src = defis4;
			srclen = DEFIS4LEN;
			break;
		case AF_INET6:
			src = defis6;
			srclen = DEFIS6LEN;
			break;
		default:
			return "unknown address family with " DEFAULTSUBNET " subnet not allowed.";
		}
	}

	slash = memchr(src, '/', srclen);
	if (slash == NULL)
		return "no / in subnet specification";

	mask = slash + 1;
	mlen = srclen - (mask - src);
	oops = ttoaddr_num(src, slash - src, af, &addrtmp);
	if (oops != NULL)
		return oops;

	if (af == AF_UNSPEC)
		af = addrtypeof(&addrtmp);

	switch (af) {
	case AF_INET:
		nbits = 32;
		break;
	case AF_INET6:
		nbits = 128;
		break;
	default:
		return "unknown address family in ttosubnet";
	}

	/* extract port, as last : */
	colon = memchr(mask, ':', mlen);
	if (colon == 0) {
		setportof(0, &addrtmp);
	} else {
		unsigned long port;

		oops =  ttoulb(colon + 1, mlen - (colon - mask + 1), 0, 0xFFFF, &port);
		if (oops != NULL)
			return oops;

		setportof(htons(port), &addrtmp);
		mlen = colon - mask;
	}

	/* extract mask */
	oops = ttoulb(mask, mlen, 10, nbits, &bc);
	if (oops == NULL) {
		/* ttoul succeeded, it's a bit-count mask */
		i = bc;
	} else if (af == AF_INET) {
		oops = ttoaddr_num(mask, mlen, af, &masktmp);
		if (oops != NULL)
			return oops;

		i = masktocount(&masktmp);
		if (i < 0)
			return "non-contiguous or otherwise erroneous mask";
	} else {
		return "masks are not permitted for IPv6 addresses";
	}
	return initsubnet(&addrtmp, i, '0', dst);
}
