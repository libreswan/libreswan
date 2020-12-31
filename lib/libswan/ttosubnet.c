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
 * ttosubnet - convert text "addr/mask" to address and mask
 * Mask can be integer bit count.
 */
err_t ttosubnet(const char *srcstr, size_t srclen,	/* 0 means "apply strlen" */
		int af,	/* AF_INET or AF_INET6 */
		int clash,  /* '0' zero host-part bits, 'x' die on them, '6' die on IPv6 and warn on IPv4 */
		ip_subnet *dst,
		struct logger *logger)
{
	err_t oops;
	const struct ip_info *afi = aftoinfo(af); /* could be NULL */

	/*
	 * XXX: should always pass in the length!
	 */
	if (srclen == 0) {
		srclen = strlen(srcstr);
		if (srclen == 0) {
			return "empty string";
		}
	}
	shunk_t src = shunk2(srcstr, srclen);

	/*
	 * Match %default, can't work when AFI=NULL.
	 *
	 * you cannot use af==AF_UNSPEC and src=0/0,
	 * makes no sense as will it be AF_INET
	 */
	if (hunk_strcaseeq(src, DEFAULTSUBNET)) {
		if (afi == NULL) {
			return "unknown address family with " DEFAULTSUBNET " subnet not allowed.";
		}
		*dst = afi->all_addresses; /* 0.0.0.0/0 or ::/0 */
		return NULL;
	}

	/* split the input into ADDR "/" (mask)... */
	char slash;
	shunk_t addr = shunk_token(&src, &slash, "/");
	if (slash == '\0') {
		/* consumed entire input */
		return "no / in subnet specification";
	}

	ip_address addrtmp;
	oops = numeric_to_address(addr, afi, &addrtmp);
	if (oops != NULL) {
		return oops;
	}

	if (afi == NULL) {
		afi = address_type(&addrtmp);
	}
	if (afi == NULL) {
		/* XXX: pexpect()? */
		return "unknown address family in ttosubnet";
	}

	/* split the input into MASK [ ":" (port) ... ] */
	char colon;
	shunk_t mask = shunk_token(&src, &colon, ":");
	uintmax_t maskbits;
	oops = shunk_to_uintmax(mask, NULL, 10, &maskbits, afi->mask_cnt);
	if (oops != NULL) {
		if (afi == &ipv4_info) {
			ip_address masktmp;
			oops = numeric_to_address(mask, afi, &masktmp);
			if (oops != NULL) {
				return oops;
			}

			int i = masktocount(&masktmp);
			if (i < 0) {
				return "non-contiguous or otherwise erroneous mask";
			}
			maskbits = i;
		} else {
			return "masks are not permitted for IPv6 addresses";
		}
	}

	/* the :PORT */
	if (colon != '\0') {
		uintmax_t port;
		err_t oops = shunk_to_uintmax(src, NULL, 0, &port, 0xFFFF);
		if (oops != NULL) {
			return oops;
		}
		addrtmp = set_endpoint_hport(&addrtmp, port);
	}

	bool die = false;
	bool warn = 0;
	switch (clash) {
	case '0':
		die = 0;
		break;
	case 'x':
		die = 1;
		break;
	case '6':
		if (afi == &ipv6_info)
			die = 1;
		warn = 1;
		break;
	default:
		return "unknown clash-control value in initsubnet";
	}

	chunk_t addr_chunk = address_as_chunk(&addrtmp);
	unsigned n = addr_chunk.len;
	uint8_t *p = addr_chunk.ptr; /* cast void* */
	if (n == 0)
		return "unknown address family";

	unsigned c = maskbits / 8;
	if (c > n)
		return "impossible mask count";

	p += c;
	n -= c;

	unsigned m = 0xff;
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

	/*
	 * XXX: see above, this isn't a true subnet as addrtmp can
	 * have its port set.
	 */
	dst->addr = addrtmp;
	dst->maskbits = maskbits;

	if (warning) {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "WARNING:improper subnet mask, host-part bits on input ");
			jam_address(buf, &addrtmp);
			jam(buf, "/%ju ", maskbits);
			jam(buf, " extracted subnet ");
			jam_subnet(buf, dst);
		}
	}

	return NULL;
}
