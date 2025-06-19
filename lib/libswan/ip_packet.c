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
	pexpect_packet(&packet, where);
	return packet;
}

bool packet_is_unset(const ip_packet *packet)
{
	if (packet == NULL) {
		return true;
	}
	return !packet->ip.is_set;
}

const struct ip_info *packet_type(const ip_packet *packet)
{
	if (packet == NULL) {
		return NULL;
	}

	/* may return NULL */
	return packet_info(*packet);
}

const struct ip_info *packet_info(const ip_packet packet)
{
	if (!packet.ip.is_set) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(packet.ip.version);
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
	const struct ip_info *afi = packet_type(packet);
	if (afi == NULL) {
		return jam_string(buf, "<unset-packet>");
	}

	const struct ip_protocol *protocol = protocol_from_ipproto(packet->ipproto);
	if (protocol == NULL) {
		return jam_string(buf, "<unknown-packet>");
	}

	size_t s = 0;
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

void pexpect_packet(const ip_packet *packet, where_t where)
{
	const struct ip_info *afi = packet_type(packet);
	if (afi == NULL) {
		llog_pexpect(&global_logger, where, "unset");
		return;
	}

	const struct ip_protocol *protocol = protocol_from_ipproto(packet->ipproto);
	if (protocol == NULL) {
		llog_pexpect(&global_logger, where,
			     "ipproto invalid in "PRI_PACKET, pri_packet(packet));
		return;
	}

	if (ip_bytes_is_zero(&packet->src.bytes)) {
		llog_pexpect(&global_logger, where,
			     "src.bytes invalid in "PRI_PACKET, pri_packet(packet));
		return;
	}

	if (ip_bytes_is_zero(&packet->dst.bytes)) {
		llog_pexpect(&global_logger, where,
			     "dst.bytes invalid in "PRI_PACKET, pri_packet(packet));
		return;
	}

	/*
	 * An acquire triggered by a packet with no specified source
	 * port will have a zero source port.
	 */
	if (protocol->zero_port_is_any && packet->dst.hport == 0) {
		llog_pexpect(&global_logger, where,
			     "dst.port invalid in "PRI_PACKET, pri_packet(packet));
		return;
	}

}
