/* ip subnet, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "ip_subnet.h"
#include "lswlog.h"

bool subnetisnone(const ip_subnet *sn)
{
	ip_address base = ip_subnet_floor(sn);
	return isanyaddr(&base) && subnetishost(sn);
}

ip_address ip_subnet_floor(const ip_subnet *subnet)
{
	return subnet->addr;
}

ip_address ip_subnet_ceiling(const ip_subnet *subnet)
{
	/* start with address */
	chunk_t base = same_ip_address_as_chunk(&subnet->addr);
	passert((size_t)subnet->maskbits <= base.len * 8);
	uint8_t buf[16] = { 0, };
	passert(base.len <= sizeof(buf))
	memcpy(buf, base.ptr, base.len);

	/* maskbits = 9 -> byte = 1; bits = 1 */
	unsigned byte = subnet->maskbits / 8;
	unsigned bits = subnet->maskbits - (byte * 8);
	/* 1 << (8-1) -> 0x80 - 1 -> 0x7f */
	if (bits != 0) {
		buf[byte] |= (1 << (8 - bits)) - 1;
		byte++;
	}
	for (; byte < base.len; byte++) {
		buf[byte] = 0xff;
	}

	ip_address mask;
	initaddr(buf, base.len, addrtypeof(&subnet->addr), &mask);
	return mask;
}
