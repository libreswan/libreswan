/* ip endpoint (address + port), for libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include "jambuf.h"
#include "ip_endpoint.h"

ip_endpoint endpoint(const ip_address *address, int port)
{
	return hsetportof(port, *address);
}

ip_address endpoint_address(const ip_endpoint *endpoint)
{
	if (isvalidaddr(endpoint)) {
		return hsetportof(0, *endpoint);
	} else {
		return *endpoint; /* empty_address? */
	}
}

int endpoint_port(const ip_endpoint *endpoint)
{
	return hportof(endpoint);
}

int endpoint_type(const ip_endpoint *endpoint)
{
	return addrtypeof(endpoint);
}

const char *str_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_endpoint(&buf, endpoint);
	return dst->buf;
}

const char *str_sensitive_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_sensitive_endpoint(&buf, endpoint);
	return dst->buf;
}

void jam_sensitive_endpoint(jambuf_t *buf, const ip_endpoint *endpoint)
{
	if (!log_ip) {
		jam(buf, "<address:port>");
		return;
	}
	jam_endpoint(buf, endpoint);
}

/*
 * Format an endpoint.
 *
 * Either ADDRESS:PORT (IPv4) or [ADDDRESS]:PORT, but when PORT is
 * invalid, just the ADDRESS is formatted.
 *
 * From wikipedia: For TCP, port number 0 is reserved and
 * cannot be used, while for UDP, the source port is optional
 * and a value of zero means no port.
 */
void jam_endpoint(jambuf_t *buf, const ip_endpoint *endpoint)
{
	ip_address address = endpoint_address(endpoint);
	int port = endpoint_port(endpoint);
	int type = endpoint_type(endpoint);

	switch (type) {
	case AF_INET: /* N.N.N.N[:PORT] */
		jam_address_cooked(buf, &address);
		if (port > 0) {
			jam(buf, ":%d", port);
		}
		break;
	case AF_INET6: /* [N:..:N]:PORT or N:..:N */
		if (port > 0) {
			jam(buf, "[");
			jam_address_cooked(buf, &address);
			jam(buf, "]");
			jam(buf, ":%d", port);
		} else {
			jam_address_cooked(buf, &address);
		}
		break;
	case 0:
		jam(buf, "<invalid-endpoint>");
		return;
	default:
		jam(buf, "<ip-type-%d>", type);
		return;
	}
}
