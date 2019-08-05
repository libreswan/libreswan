/* ip subnet, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
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

#include "jambuf.h"
#include "ip_subnet.h"
#include "libreswan/passert.h"
#include "lswlog.h"	/* for pexpect() */

ip_endpoint subnet_endpoint(const ip_subnet *src)
{
	return src->addr;
}

const struct ip_info *subnet_info(const ip_subnet * src)
{
	return address_info(&src->addr);
}

static ip_address mashup(const ip_subnet *src,
			 uint8_t prefix_and, uint8_t prefix_or,
			 uint8_t host_and, uint8_t host_or)
{
	/* strip port; copy type */
	ip_address mask = endpoint_address(&src->addr);
	chunk_t raw = address_as_chunk(&mask);

	if (!pexpect((size_t)src->maskbits <= raw.len * 8)) {
		return address_invalid;	/* "can't happen" */
	}

	uint8_t *p = raw.ptr; /* cast void* */

	/* the cross over byte */
	size_t xbyte = src->maskbits / 8;
	unsigned xbit = src->maskbits % 8;

	/* leading bytes: & PREFIX_AND | PREFIX_OR */
	unsigned b = 0;
	for (; b < xbyte; b++) {
		p[b] &= prefix_and;
		p[b] |= prefix_or;
	}

	/* cross over: & {PREFIX,HOST}_AND | {PREFIX,HOST}_OR */
	if (xbit != 0) {
		uint8_t mask = (0xff << (8 - xbit)) & 0xff;
		uint8_t and = ((prefix_and & mask) |
			       (host_and & ~mask));
		uint8_t or = ((prefix_or & mask) |
			      (host_or & ~mask));
		p[b] &= and;
		p[b] |= or;
		b++;
	}

	/* trailing bytes: & HOST_AND | HOST_OR */
	for (; b < raw.len; b++) {
		p[b] &= host_and;
		p[b] |= host_or;
	}

	return mask;
}

/*
 * subnet mask - get the mask of a subnet, as an address
 *
 * For instance 1.2.3.4/24 -> 255.255.255.0.
 */

ip_address subnet_mask(const ip_subnet *src)
{
	return mashup(src,
		      /*prefix and/or*/ 0x00, 0xff,
		      /*host and/or*/ 0x00, 0x00);
}

bool subnetisnone(const ip_subnet *sn)
{
	ip_address base = subnet_floor(sn);
	return isanyaddr(&base) && subnetishost(sn);
}

ip_address subnet_floor(const ip_subnet *subnet)
{
	return mashup(subnet,
		      /*prefix and/or*/ 0xff, 0x00,
		      /*host and/or*/ 0x00, 0x00);
}

ip_address subnet_ceiling(const ip_subnet *subnet)
{
	return mashup(subnet,
		      /*prefix and/or*/ 0xff, 0x00,
		      /*host and/or*/ 0x00, 0xff);
}

void jam_subnet(jambuf_t *buf, const ip_subnet *subnet)
{
	jam_address(buf, &subnet->addr); /* sensitive? */
	jam(buf, "/%u", subnet->maskbits);
}

const char *str_subnet(const ip_subnet *subnet, subnet_buf *out)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(out->buf);
	jam_subnet(&buf, subnet);
	return out->buf;
}
