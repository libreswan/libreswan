/* up selector, for libreswan
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

#include "ip_packet.h"
#include "ip_info.h"
#include "ip_protocol.h"

const ip_packet unset_packet;

ip_packet packet_from_raw(where_t where,
			  /* INFO determines meaning of BYTES */
			  const struct ip_info *afi,
			  const struct ip_bytes *src_bytes,
			  const struct ip_bytes *dst_bytes,
			  /* PROTOCOL determines meaning of PORTs */
			  const struct ip_protocol *protocol,
			  ip_port src_port, ip_port dst_port)
{
	if (PBAD_WHERE(&global_logger, where, ip_bytes_is_zero(src_bytes)) ||
	    PBAD_WHERE(&global_logger, where, ip_bytes_is_zero(dst_bytes))) {
		return unset_packet;
	}

	ip_packet packet = {
		.ip.is_set = true,
		.ip.version = afi->ip.version,
		.ipproto = protocol->ipproto,
		.src = {
			.bytes = *src_bytes,
			.hport = src_port.hport, /* can be zero */
		},
		.dst = {
			.bytes = *dst_bytes,
			.hport = dst_port.hport,
		},
	};

	/*
	 * For packets such as UDP and TCP, port 0 is reserved.
	 * Hence, BSD kernels:
	 *
	 * - reject a connect(2) call with UDP port 0.
	 *
	 * - acquire ignores the packet, or turns it into "any"
	 *
	 * However, on Linux ...
	 *
	 * - the kernel allows connect(UDP,0)!  For instance using
	 *   commands such as:
	 *
	 *     nc -u -w 1 ADDR 0
	 *     socat -t0 - UDP:ADDR:0
	 *
	 * - ACQUIRE exposes the packet
	 *
	 *   AA: [UDP] dport 0 is valid in an ACQUIRE selector: it
	 *   happens for IP fragments, which have no L4 header to take
	 *   a port from, and also when pinging a hostname that
	 *   resolves to more than one address.  The iputils ping sets
	 *   dport to 1025 for its route-probe connect(), however, on
	 *   Linux glibc appears to replace that with zero when the
	 *   hostname resolves to more than one address, e.g. both an
	 *   A and AAAA record. glibc leaves 1025 when pinging a
	 *   single IP address.
	 */
	if (protocol->zero_port_is_any && dst_port.hport == 0) {
#ifdef __linux__
		enum stream stream = RC_LOG;
#else
		enum stream stream = PEXPECT_STREAM;
#endif
		llog(stream, &global_logger,
		     "packet with port 0: "PRI_PACKET, pri_packet(&packet));
	}

	return packet;
}

bool packet_is_unset(const ip_packet *packet)
{
	return ip_is_unset(packet);
}

const struct ip_info *packet_type(const ip_packet *packet)
{
	/* may return NULL */
	return ip_type(packet);
}

const struct ip_info *packet_info(const ip_packet packet)
{
	/* may return NULL */
	return ip_info(packet);
}

const struct ip_protocol *packet_protocol(const ip_packet packet)
{
	if (!packet.ip.is_set) {
		return NULL;
	}

	/* may return NULL */
	return protocol_from_ipproto(packet.ipproto);
}

ip_address packet_src_address(const ip_packet packet)
{
	const struct ip_info *afi = packet_info(packet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address;
	}

	return address_from_raw(HERE, afi, packet.src.bytes);
}

ip_address packet_dst_address(const ip_packet packet)
{
	const struct ip_info *afi = packet_info(packet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address;
	}

	return address_from_raw(HERE, afi, packet.dst.bytes);
}

ip_endpoint packet_dst_endpoint(const ip_packet packet)
{
	const struct ip_info *afi = packet_info(packet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_endpoint;
	}

	return endpoint_from_raw(HERE, afi,
				 packet.dst.bytes,
				 protocol_from_ipproto(packet.ipproto),
				 ip_hport(packet.dst.hport));
}

ip_selector packet_src_selector(const ip_packet packet)
{
	const struct ip_info *afi = packet_info(packet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_selector;
	}

	return selector_from_raw(HERE, afi,
				 packet.src.bytes,
				 packet.src.bytes,
				 protocol_from_ipproto(packet.ipproto),
				 ip_hport(packet.src.hport));
}

ip_selector packet_dst_selector(const ip_packet packet)
{
	const struct ip_info *afi = packet_info(packet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_selector;
	}

	return selector_from_raw(HERE, afi,
				 packet.dst.bytes,
				 packet.dst.bytes,
				 protocol_from_ipproto(packet.ipproto),
				 ip_hport(packet.dst.hport));
}

size_t jam_packet(struct jambuf *buf, const ip_packet *packet)
{
	const struct ip_info *afi;
	size_t s = jam_invalid_ip(buf, "packet", packet, &afi);
	if (s > 0) {
		return s;
	}

	const struct ip_protocol *protocol = protocol_from_ipproto(packet->ipproto);
	if (protocol == NULL) {
		return jam_string(buf, "<unknown-packet>");
	}

	if (packet->src.hport == 0 && protocol->zero_port_is_any) {
		/*
		 * SRC port can be zero aka wildcard aka ephemeral, it
		 * isn't know to pluto so denotes any and should be
		 * omitted.
		 *
		 * For IPv6, jam_wrapped() includes includes [] so
		 * output is consistent with endpoint.jam().
		 */
		s += afi->jam.address_wrapped(buf, afi, &packet->src.bytes);
	} else {
		s += afi->jam.address_wrapped(buf, afi, &packet->src.bytes);
		s += jam(buf, ":%u", packet->src.hport);
	}
	/* DST port is always valid */
	s += jam(buf, "-%s->", protocol->name);
	s += afi->jam.address_wrapped(buf, afi, &packet->dst.bytes);
	s += jam(buf, ":%u", packet->dst.hport);
	return s;
}

const char *str_packet(const ip_packet *packet, packet_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_packet(&buf, packet);
	return dst->buf;
}
