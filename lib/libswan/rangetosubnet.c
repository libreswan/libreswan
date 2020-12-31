/*
 * express an address range as a subnet (if possible)
 *
 * Copyright (C) 2000, 2002  Henry Spencer.
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public
 * License for more details.
 */

#include "ip_subnet.h"
#include "passert.h"
#include "ip_info.h" 	/* ipv6_info */
#include "lswlog.h"	/* for dbg() */

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
 * rangetosubnet - turn an address range into a subnet, if possible
 *
 * A range which is a valid subnet will have a network part which is the
 * same in the from value and the to value, followed by a host part which
 * is all 0 in the from value and all 1 in the to value.
 *
 * ??? this really should use ip_range rather than a pair of ip_address values
 */
err_t rangetosubnet(from, to, dst)
const ip_address *from;
const ip_address *to;
ip_subnet *dst;
{
	const struct ip_info *ft = address_type(from);
	const struct ip_info *tt = address_type(to);
	if (ft == NULL || tt == NULL) {
		return "unknown address type";
	}
	if (ft != tt) {
		return "mismatched address types";
	}

	unsigned fb;
	unsigned tb;
	const unsigned char *f;
	const unsigned char *t;
	int i;
	int nnet;
	unsigned m;

	shunk_t fs = address_as_shunk(from);
	const uint8_t *fp = fs.ptr; /* cast cast void * */
	passert(fs.len > 0);
	size_t n = fs.len;

	shunk_t ts = address_as_shunk(to);
	const uint8_t *tp = ts.ptr; /* cast const void * */
	passert(fs.len == ts.len);

	f = fp;
	t = tp;
	nnet = 0;
	for (i = n; i > 0 && *f == *t; i--, f++, t++)
		nnet += 8;
	if (i > 0 && !(*f == 0x00 && *t == 0xff)) {	/* mid-byte bdry. */
		fb = *f++;
		tb = *t++;
		i--;
		m = 0x80;
		while ((fb & m) == (tb & m)) {
			fb &= ~m;
			tb |= m;
			m >>= 1;
			nnet++;
		}
		if (fb != 0x00 || tb != 0xff)
			return "not a valid subnet";
	}
	for (; i > 0 && *f == 0x00 && *t == 0xff; i--, f++, t++)
		continue;

	if (i != 0)
		return "invalid subnet";

	return initsubnet(from, nnet, 'x', dst, NULL);
}
