/* ip traffic selector, for libreswan
 *
 * Copyright (C) 2020-2021  Andrew Cagney
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

#ifndef IP_TRAFFIC_H
#define IP_TRAFFIC_H

#include "ip_bytes.h"
#include "ip_port.h"
#include "ip_endpoint.h"

struct ip_protocol;

struct jambuf;

/*
 * Traffic (packet flow) between two endpoints.
 */

typedef struct {
	bool is_set;
	/*
	 * Index into the struct ip_info array; must be stream
	 * friendly.
	 */
	enum ip_version version; /* 0, 4, 6 */
	/*
	 * We need something that makes static IPv4 initializers
	 * possible (struct in_addr requires htonl() which is run-time
	 * only).
	 */
	unsigned ipproto;
	struct {
		struct ip_bytes bytes;
		int hport;
	} src, dst;
} ip_traffic;

#define PRI_TRAFFIC "%s is_set=%s version=%d ipproto=%d src.bytes="PRI_BYTES" src.hport=%d dst.bytes="PRI_BYTES" dst.hport=%d"
#define pri_traffic(S,B)				\
	str_traffic(S, B),				\
		bool_str((S)->is_set),			\
		(S)->version,				\
		(S)->ipproto,				\
		pri_bytes((S)->src.bytes),		\
		(S)->src.hport,				\
		pri_bytes((S)->dst.bytes),		\
		(S)->dst.hport

void pexpect_traffic(const ip_traffic *s, where_t where);
#define ptraffic(S) pexpect_traffic(S, HERE)

ip_traffic traffic_from_raw(where_t where, enum ip_version version,
			    const struct ip_protocol *protocol,
			    const struct ip_bytes src_bytes, const ip_port src_port,
			    const struct ip_bytes dst_bytes, const ip_port dst_port);

/*
 * Magic values.
 *
 * XXX: While the headers call the all-zero address "ANY" (INADDR_ANY,
 * IN6ADDR_ANY_INIT), the headers also refer to the IPv6 value as
 * unspecified (for instance IN6_IS_ADDR_UNSPECIFIED()) leaving the
 * term "unspecified" underspecified.
 *
 * Consequently an AF_UNSPEC address (i.e., uninitialized or unset),
 * is identified by *_unset().
 */

extern const ip_traffic unset_traffic;

const struct ip_info *traffic_type(const ip_traffic *traffic);	/* handles NULL; returns NULL */

/* attributes */

const struct ip_protocol *traffic_protocol(const ip_traffic traffic);

ip_endpoint traffic_src(const ip_traffic traffic);
ip_endpoint traffic_dst(const ip_traffic traffic);

/*
 * Output.
 */

typedef struct {
	/* way over size? */
	char buf[sizeof(endpoint_buf) + sizeof("-->") + sizeof(protocol_buf) + sizeof(endpoint_buf) + 1/*canary*/];
} traffic_buf;

size_t jam_traffic(struct jambuf *buf, const ip_traffic *traffic);
const char *str_traffic(const ip_traffic *traffic, traffic_buf *buf);

#endif
