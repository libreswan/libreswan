/* ip packet extracted from acquire, for libreswan
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

#ifndef IP_PACKET_H
#define IP_PACKET_H

#include "ip_bytes.h"
#include "ip_port.h"
#include "ip_endpoint.h"
#include "ip_selector.h"

struct ip_protocol;

struct jambuf;

/*
 * Packet between two endpoints.
 */

typedef struct {
	bool is_set;
	enum ip_version ip_version;
	unsigned ipproto;

	struct {
		struct ip_bytes bytes;
		/*
		 * Note: An acquire triggered by a packet that did not
		 * specify the source port (i.e., it's ephemeral) will
		 * have .src.hport set to zero.
		 */
		int hport;
	} src, dst;
	/*XXX sec_label?*/
} ip_packet;

#define PRI_PACKET "<packet-%s:IPv%d["PRI_IP_BYTES"]:%u-%u->["PRI_IP_BYTES"]:%u>"
#define pri_packet(S)							\
	((S)->is_set ? "set" : "unset"),				\
		(S)->ip_version,					\
		pri_ip_bytes((S)->src.bytes),				\
		(S)->src.hport,						\
		(S)->ipproto,						\
		pri_ip_bytes((S)->dst.bytes),				\
		(S)->dst.hport

void pexpect_packet(const ip_packet *s, where_t where);
#define ppacket(S) pexpect_packet(S, HERE)

ip_packet packet_from_raw(where_t where,
			  /* AFI determines meaning of ... */
			  const struct ip_info *afi,
			  /* ... BYTES */
			  const struct ip_bytes *src_bytes,
			  const struct ip_bytes *dst_bytes,
			  /* PROTOCOL determines meaning of ... */
			  const struct ip_protocol *protocol,
			  /* ... PORTs */
			  const ip_port src_port,
			  const ip_port dst_port);

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

extern const ip_packet unset_packet;

bool packet_is_unset(const ip_packet *packet);			/* handles NULL */
const struct ip_info *packet_type(const ip_packet *packet);	/* handles NULL */
const struct ip_info *packet_info(const ip_packet packet);
const struct ip_protocol *packet_protocol(const ip_packet packet);

/* attributes */

ip_address packet_src_address(const ip_packet packet);
ip_address packet_dst_address(const ip_packet packet);

/* packet_src_endpoint() N/A as as src port can be zero */
ip_endpoint packet_dst_endpoint(const ip_packet packet);

ip_selector packet_src_selector(const ip_packet packet);
ip_selector packet_dst_selector(const ip_packet packet);

/*
 * Output.
 */

typedef struct {
	/* way over size? */
	char buf[sizeof(endpoint_buf) + sizeof("-->") + sizeof(protocol_buf) + sizeof(endpoint_buf) + 1/*canary*/];
} packet_buf;

size_t jam_packet(struct jambuf *buf, const ip_packet *packet);
const char *str_packet(const ip_packet *packet, packet_buf *buf);

#endif
