/*
 * low-level ip_address ugliness
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2018  Andrew Cagney.
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <sys/socket.h>		/* for AF_INET/AF_INET6/AF_UNSPEC */

#include "jambuf.h"
#include "ip_address.h"
#include "lswlog.h"		/* for dbg() */
#include "ip_info.h"

const ip_address unset_address; /* all zeros */

ip_address address_from_raw(where_t where,
			    const struct ip_info *afi,
			    const struct ip_bytes bytes)
{
	ip_address a = {
		.ip.is_set = true,
		.ip.version = afi->ip.version,
		.bytes = bytes,
	};
	pexpect_address(&a, where);
	return a;
}

diag_t data_to_address(const void *data, size_t sizeof_data,
		       const struct ip_info *afi, ip_address *dst)
{
	*dst = unset_address;

	if (afi == NULL) {
		return diag("unknown address family");
	}

	/* accept longer! */
	if (sizeof_data < afi->ip_size) {
		return diag("%s address must be %zu bytes, not %zu",
			    afi->ip_name, afi->ip_size, sizeof_data);
	}

	struct ip_bytes bytes = unset_ip_bytes;
	memcpy(bytes.byte, data, afi->ip_size);
	*dst = address_from_raw(HERE, afi, bytes);
	return NULL;
}

ip_address address_from_in_addr(const struct in_addr *in)
{
	struct ip_bytes bytes = { .byte = { 0, }, };
	memcpy(bytes.byte, in, sizeof(*in));
	return address_from_raw(HERE, &ipv4_info, bytes);
}

ip_address address_from_in6_addr(const struct in6_addr *in6)
{
	struct ip_bytes bytes = { .byte = { 0, }, };
	memcpy(bytes.byte, in6, sizeof(*in6));
	return address_from_raw(HERE, &ipv6_info, bytes);
}

const struct ip_info *address_type(const ip_address *address)
{
	/* may return NULL */
	return ip_type(address);
}

const struct ip_info *address_info(const ip_address address)
{
	/* may return NULL */
	return ip_info(address);
}

shunk_t address_as_shunk(const ip_address *address)
{
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return null_shunk;
	}

	return shunk2(&address->bytes, afi->ip_size);
}

chunk_t address_as_chunk(ip_address *address)
{
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return empty_chunk;
	}

	return chunk2(&address->bytes, afi->ip_size);
}

size_t jam_address(struct jambuf *buf, const ip_address *address)
{
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return jam_string(buf, "<unset-address>");
	}

	return afi->jam.address(buf, afi, &address->bytes);
}

size_t jam_address_wrapped(struct jambuf *buf, const ip_address *address)
{
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return jam_string(buf, "<unset-address>");
	}

	return afi->jam.address_wrapped(buf, afi, &address->bytes);
}

size_t jam_address_sensitive(struct jambuf *buf, const ip_address *address)
{
	if (!log_ip) {
		return jam_string(buf, "<address>");
	}
	return jam_address(buf, address);
}

size_t jam_address_reversed(struct jambuf *buf, const ip_address *address)
{
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return jam(buf, "<invalid>");
	}

	shunk_t bytes = address_as_shunk(address);
	size_t s = 0;

	switch (afi->af) {
	case AF_INET:
		for (int i = bytes.len - 1; i >= 0; i--) {
			const uint8_t *byte = bytes.ptr;
			s += jam(buf, "%d.", byte[i]);
		}
		s += jam(buf, "IN-ADDR.ARPA.");
		break;
	case AF_INET6:
		for (int i = bytes.len - 1; i >= 0; i--) {
			const uint8_t *byte = bytes.ptr;
			s += jam(buf, "%x.%x.", byte[i] & 0xf, byte[i] >> 4);
		}
		s += jam(buf, "IP6.ARPA.");
		break;
	case AF_UNSPEC:
		s += jam(buf, "<unspecified>");
		break;
	default:
		bad_case(afi->af);
		break;
	}
	return s;
}

const char *str_address(const ip_address *src,
			       address_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_address(&buf, src);
	return dst->buf;
}

const char *str_address_wrapped(const ip_address *src,
				address_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_address_wrapped(&buf, src);
	return dst->buf;
}

const char *str_address_sensitive(const ip_address *src,
				  address_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_address_sensitive(&buf, src);
	return dst->buf;
}

const char *str_address_reversed(const ip_address *src,
				 address_reversed_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_address_reversed(&buf, src);
	return dst->buf;
}

bool address_is_unset(const ip_address *address)
{
	return ip_is_unset(address);
}

bool address_is_specified(const ip_address address)
{
	const struct ip_info *afi = address_info(address);
	if (afi == NULL) {
		return false;
	}

	/* exclude any address */
	if (address_eq_address(address, afi->address.unspec)) {
		return false;
	}

	return true;
}

bool address_eq_address(const ip_address l, const ip_address r)
{
	if (address_is_unset(&l) && address_is_unset(&r)) {
		/* unset/NULL addresses are equal */
		return true;
	}
	if (address_is_unset(&l) || address_is_unset(&r)) {
		return false;
	}
	/* must compare individual fields */
	return (l.ip.version == r.ip.version &&
		thingeq(l.bytes, r.bytes));
}

bool address_is_loopback(const ip_address address)
{
	const struct ip_info *afi = address_info(address);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	return address_eq_address(address, afi->address.loopback);
}

void pexpect_address(const ip_address *a, where_t where)
{
	if (a == NULL) {
		return;
	}

	/* more strict than is_unset() */
	if (address_eq_address(*a, unset_address)) {
		return;
	}

	if (a->ip.is_set == false ||
	    a->ip.version == 0) {
		llog_pexpect(&global_logger, where, "invalid address: "PRI_ADDRESS, pri_address(a));
	}
}
