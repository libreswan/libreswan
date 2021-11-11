/* ip selector, for libreswan
 *
 * Copyright (C) 2020  Andrew Cagney
 * Copyright (C) 2000  Henry Spencer.
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

#include "lswlog.h"

#include "ip_traffic.h"
#include "ip_info.h"
#include "ip_protocol.h"

const ip_traffic unset_traffic;

ip_traffic traffic_from_raw(where_t where, enum ip_version version,
			    const struct ip_protocol *protocol,
			    const struct ip_bytes src_bytes, ip_port src_port,
			    const struct ip_bytes dst_bytes, ip_port dst_port)
{
	ip_traffic traffic = {
		.is_set = true,
		.version = version,
		.ipproto = protocol->ipproto,
		.src = {
			.bytes = src_bytes,
			.hport = src_port.hport,
		},
		.dst = {
			.bytes = dst_bytes,
			.hport = dst_port.hport,
		},
	};
	pexpect_traffic(&traffic, where);
	return traffic;
}

const struct ip_info *traffic_type(const ip_traffic *traffic)
{
	if (traffic == NULL) {
		return NULL;
	}

	if (!traffic->is_set) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(traffic->version);
}

const struct ip_protocol *traffic_protocol(const ip_traffic t)
{
	return protocol_by_ipproto(t.ipproto);
}

ip_endpoint traffic_src(const ip_traffic traffic)
{
	return endpoint_from_raw(HERE, traffic.version, traffic.src.bytes,
				 traffic_protocol(traffic),
				 ip_hport(traffic.src.hport));
}

ip_endpoint traffic_dst(const ip_traffic traffic)
{
	return endpoint_from_raw(HERE, traffic.version, traffic.dst.bytes,
				 traffic_protocol(traffic),
				 ip_hport(traffic.dst.hport));
}

size_t jam_traffic(struct jambuf *buf, const ip_traffic *t)
{
	const struct ip_info *afi = traffic_type(t);
	if (afi == NULL) {
		return jam(buf, "<unset-traffic>");
	}

	const struct ip_protocol *proto = protocol_by_ipproto(t->ipproto);

	size_t s = 0;
	s += afi->address.jam(buf, afi, &t->src.bytes);
	s += jam(buf, ":%d", t->src.hport);
	s += jam(buf, "-%s->", proto->name);
	s += afi->address.jam(buf, afi, &t->dst.bytes);
	s += jam(buf, ":%d", t->dst.hport);
	return s;
}

const char *str_traffic(const ip_traffic *traffic, traffic_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_traffic(&buf, traffic);
	return dst->buf;
}

void pexpect_traffic(const ip_traffic *t, where_t where)
{
	if (t == NULL) {
		return;
	}

	if (t->version == 0 ||
	    t->ipproto == 0 ||
	    t->src.hport == 0 ||
	    t->dst.hport == 0) {
		if (t->is_set) {
			traffic_buf b;
			log_pexpect(where, "invalid traffic: "PRI_TRAFFIC,
				    pri_traffic(t, &b));

		}
	} else if (!t->is_set) {
		traffic_buf b;
		log_pexpect(where, "invalid traffic: "PRI_TRAFFIC,
			    pri_traffic(t, &b));
	}
}
