/*
 * express an address range as a subnet (if possible)
 *
 * Copyright (C) 2000  Henry Spencer.
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

	return initsubnet(from, nnet, 'x', dst);
}
