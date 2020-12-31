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
#include "ip_info.h" 	/* ipv6_info */
#include "lswlog.h"	/* for dbg() */

#ifndef DEFAULTSUBNET
#define DEFAULTSUBNET "%default"
#endif

/*
 * initsubnet - initialize ip_subnet from address and count
 *
 * The only hard part is checking for host-part bits turned on.
 *
 * Return NULL for success, else string literal.
 */
static err_t initsubnet(const ip_address *addr,
			int maskbits,
			int clash,	/* '0' zero host-part bits, 'x' die on them */
			ip_subnet *dst,
			struct logger *logger)
{
	unsigned char *p;
	int n;
	int c;
	unsigned m;
	bool die = false;
	bool warn = 0;

	dst->addr = *addr;
	chunk_t addr_chunk = address_as_chunk(&dst->addr);
	n = addr_chunk.len;
	p = addr_chunk.ptr; /* cast void* */
	if (n == 0)
		return "unknown address family";

	switch (clash) {
	case '0':
		die = 0;
		break;
	case 'x':
		die = 1;
		break;
	case '6':
		pexpect(logger != NULL);
		if (address_type(addr) == &ipv6_info)
			die = 1;
		warn = 1;
		break;

	default:
		return "unknown clash-control value in initsubnet";
	}

	c = maskbits / 8;
	if (c > n)
		return "impossible mask count";

	p += c;
	n -= c;

	m = 0xff;
	c = maskbits % 8;
	if (n > 0 && c != 0)	/* partial byte */
		m >>= c;

	bool warning = false;
	for (; n > 0; n--) {
		if ((*p & m) != 0) {
			if (die)
				return "improper subnet, host-part bits on";
			if (warn && !warning)
				warning = true;
			*p &= ~m;
		}
		m = 0xff;
		p++;
	}

	dst->maskbits = maskbits;

	if (warning) {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "WARNING:improper subnet mask, host-part bits on input ");
			jam_address(buf, addr);
			jam(buf, "/%d ", maskbits);
			jam(buf, " extracted subnet ");
			jam_subnet(buf, dst);
		}
	}

	return NULL;
}

/*
 * ttosubnet - convert text "addr/mask" to address and mask
 * Mask can be integer bit count.
 */
err_t ttosubnet(const char *src,
		size_t srclen,	/* 0 means "apply strlen" */
		int af,	/* AF_INET or AF_INET6 */
		int clash,  /* '0' zero host-part bits, 'x' die on them, '6' die on IPv6 and warn on IPv4 */
		ip_subnet *dst,
		struct logger *logger)
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
	return initsubnet(&addrtmp, i, clash, dst, logger);
}
