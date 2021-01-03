/* ip port range, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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

#include <arpa/inet.h>		/* for ntohs() */

#include "jambuf.h"
#include "constants.h"		/* for thingeq() */
#include "ip_port_range.h"

const ip_port_range unset_port_range; /* aka all ports? */

ip_port_range ip_port_range_from_ports(ip_port lo, ip_port hi)
{
	ip_port_range port_range = {
		.lo = lo,
		.hi = hi,
	};
	return port_range;
}

bool port_range_is_unset(ip_port_range port_range)
{
	return thingeq(port_range, unset_port_range);
}

size_t jam_port_range(struct jambuf *buf, ip_port_range port_range)
{
	unsigned lo = hport(port_range.lo);
	unsigned hi = hport(port_range.hi);
	if (lo == hi) {
		return jam(buf, "%u", lo);
	} else {
		return jam(buf, "%u-%u", lo, hi);
	}

}

const char *str_port_range(ip_port_range port, port_range_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_port_range(&jambuf, port);
	return buf->buf;
}
