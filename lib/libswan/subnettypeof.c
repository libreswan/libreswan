/*
 * extract parts of an ip_subnet, and related
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

#include "ip_subnet.h"

/*
 * masktocount - convert a mask, expressed as an address, to a bit count
 */
int	/* -1 if not valid mask */
masktocount(src)
const ip_address * src;
{
	int b;
	const unsigned char *p;
	const unsigned char *stop;

	shunk_t sc = address_as_shunk(src);
	const uint8_t *bp = sc.ptr; /* cast const void * */
	size_t n = sc.len;
	if (n == 0)
		return -1;

	p = bp;
	stop = bp + n;

	n = 0;
	while (p < stop && *p == 0xff) {
		p++;
		n += 8;
	}
	if (p < stop && *p != 0) {	/* boundary in mid-byte */
		b = *p++;
		while (b & 0x80) {
			b <<= 1;
			n++;
		}
		if ((b & 0xff) != 0)
			return -1;	/* bits not contiguous */
	}
	while (p < stop && *p == 0)
		p++;

	if (p != stop)
		return -1;

	return n;
}
