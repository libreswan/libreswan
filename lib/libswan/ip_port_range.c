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
#include "ip_port_range.h"
#include "lswlog.h"		/* for pexpect() */

const ip_port_range unset_port_range;

ip_port_range port_range_from_ports(ip_port lo, ip_port hi)
{
	ip_port_range r = {
		.ip.is_set = true,
		.lo = lo.hport,
		.hi = hi.hport,
	};
	pexpect(r.lo <= r.hi);
	return r;
}

size_t jam_port_range(struct jambuf *buf, ip_port_range r)
{
	if (!r.ip.is_set) {
		return jam(buf, "<unset-port-range>");
	}

	if (r.lo == r.hi) {
		return jam(buf, "%u", r.lo);
	} else {
		return jam(buf, "%u-%u", r.lo, r.hi);
	}

}

const char *str_port_range(ip_port_range port, port_range_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_port_range(&jambuf, port);
	return buf->buf;
}
