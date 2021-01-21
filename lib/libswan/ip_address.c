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

#include "jambuf.h"
#include "ip_address.h"
#include "lswlog.h"		/* for dbg() */
#include "ip_info.h"

const ip_address unset_address; /* all zeros */

ip_address strip_address(const ip_address *in, where_t where UNUSED)
{
	if (in->hport != 0 || in->ipproto != 0 || in->is_endpoint) {
		address_buf b;
		dbg("stripping address %s of is_endpoint=%d hport=%u ipproto=%u "PRI_WHERE,
		    str_address(in, &b), in->is_endpoint,
		    in->hport, in->ipproto, pri_where(where));
	}
	ip_address out = {
		.is_address = true,
		.version = in->version,
		.bytes = in->bytes,
	};
	paddress(&out);
	return out;
}

ip_address address_from_raw(const struct ip_info *afi, const struct ip_bytes *bytes)
{
	ip_address a = {
		.is_address = true,
		.version = afi->ip_version,
		.bytes = *bytes,
	};
	paddress(&a);
	return a;
}

ip_address address_from_in_addr(const struct in_addr *in)
{
	struct ip_bytes bytes = { .byte = { 0, }, };
	memcpy(bytes.byte, in, sizeof(*in));
	return address_from_raw(&ipv4_info, &bytes);
}

uint32_t ntohl_address(const ip_address *a)
{
	uint32_t u;
	shunk_t s = address_as_shunk(a);
	if (address_type(a) == &ipv4_info) {
		memcpy(&u, s.ptr, s.len);
	} else  {
		/* IPv6 take bits 96 - 128 to compute size */
		s.ptr += (s.len - sizeof(u));
		memcpy(&u, s.ptr, sizeof(u));
	}
	return ntohl(u);
}

ip_address address_from_in6_addr(const struct in6_addr *in6)
{
	struct ip_bytes bytes = { .byte = { 0, }, };
	memcpy(bytes.byte, in6, sizeof(*in6));
	return address_from_raw(&ipv6_info, &bytes);
}

const struct ip_info *address_type(const ip_address *address)
{
	if (address == NULL) {
		return NULL;
	}
	return ip_version_info(address->version);
}

/*
 * simplified interface to addrtot()
 *
 * Caller should allocate a buffer to hold the result as long
 * as the resulting string is needed.  Usually just long enough
 * to output.
 */

const char *ipstr(const ip_address *src, ipstr_buf *b)
{
	return str_address(src, b);
}

const char *sensitive_ipstr(const ip_address *src, ipstr_buf *b)
{
	return str_address_sensitive(src, b);
}

shunk_t address_as_shunk(const ip_address *address)
{
	if (address == NULL) {
		return null_shunk;
	}
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return null_shunk;
	}
	return shunk2(&address->bytes, afi->ip_size);
}

chunk_t address_as_chunk(ip_address *address)
{
	if (address == NULL) {
		return empty_chunk;
	}
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return empty_chunk;
	}
	return chunk2(&address->bytes, afi->ip_size);
}

static size_t format_address_cooked(struct jambuf *buf, bool sensitive,
				    const ip_address *address)
{
	/*
	 * A NULL address can't be sensitive.
	 */
	if (address == NULL) {
		return jam(buf, "<none>");
	}

	if (sensitive) {
		return jam(buf, "<ip-address>");
	}

	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return jam(buf, "<invalid>");
	}

	return afi->jam_address(buf, afi, &address->bytes);
}

size_t jam_address(struct jambuf *buf, const ip_address *address)
{
	return format_address_cooked(buf, false, address);
}

size_t jam_address_sensitive(struct jambuf *buf, const ip_address *address)
{
	return format_address_cooked(buf, !log_ip, address);
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

ip_address address_any(const struct ip_info *info)
{
	passert(info != NULL);
	if (info == NULL) {
		/*
		 * XXX: Loudly reject AF_UNSPEC, but don't crash.
		 * Callers know the protocol of the "any" (IPv[46]
		 * term) or "unspecified" (alternative IPv6 term)
		 * address required.
		 *
		 * If there's a need for a function that also allows
		 * AF_UNSPEC, then call that function
		 * address_unspecified().
		 */
		log_pexpect(HERE, "AF_UNSPEC unexpected");
		return unset_address;
	} else {
		return info->any_address;
	}
}

bool address_is_unset(const ip_address *address)
{
	return thingeq(*address, unset_address);
}

bool address_is_specified(const ip_address *address)
{
	if (address == NULL) {
		return false;
	}
	if (address_is_unset(address)) {
		return false;
	}
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return false;
	}
	/* check all bytes; not just .ip_size */
	if (thingeq(address->bytes, afi->any_address.bytes)) {
		/* any address (but we know it is zero) */
		return false;
	}
	return true;
}

bool address_eq(const ip_address *l, const ip_address *r)
{
	const struct ip_info *lt = address_type(l);
	const struct ip_info *rt = address_type(r);
	if (lt == NULL || rt == NULL) {
		/* AF_UNSPEC/NULL are never equal; think NaN */
		return false;
	}
	if (lt != rt) {
		return false;
	}
	shunk_t ls = address_as_shunk(l);
	shunk_t rs = address_as_shunk(r);
	return hunk_eq(ls, rs);
}

bool address_is_loopback(const ip_address *address)
{
	const struct ip_info *type = address_type(address);
	if (type == NULL) {
		return false;
	}
	return address_eq(address, &type->loopback_address);
}

bool address_is_any(const ip_address *address)
{
	const struct ip_info *type = address_type(address);
	if (type == NULL) {
		return false;
	}
	return address_eq(address, &type->any_address);
}

/*
 * mashup() notes:
 * - mashup operates on network-order IP addresses
 */

struct ip_blit {
	uint8_t and;
	uint8_t or;
};

const struct ip_blit clear_bits = { .and = 0x00, .or = 0x00, };
const struct ip_blit set_bits = { .and = 0x00/*don't care*/, .or = 0xff, };
const struct ip_blit keep_bits = { .and = 0xff, .or = 0x00, };

ip_address address_from_blit(const struct ip_info *afi,
			     struct ip_bytes bytes,
			     const struct ip_blit *routing_prefix,
			     const struct ip_blit *host_identifier,
			     unsigned nr_prefix_bits)
{
	if (!pexpect(nr_prefix_bits <= afi->mask_cnt)) {
		return unset_address;	/* "can't happen" */
	}

	uint8_t *p = bytes.byte;

	/*
	 * Split the byte array into:
	 *
	 *    leading | xbyte:xbit | trailing
	 *
	 * where LEADING only contains ROUTING_PREFIX bits, TRAILING
	 * only contains HOST_ID bits, and XBYTE is the cross over and
	 * contains the first HOST_ID bit at big (aka PPC) endian
	 * position XBIT.
	 */
	size_t xbyte = nr_prefix_bits / BITS_PER_BYTE;
	unsigned xbit = nr_prefix_bits % BITS_PER_BYTE;

	/* leading bytes only contain the ROUTING_PREFIX */
	for (unsigned b = 0; b < xbyte; b++) {
		p[b] &= routing_prefix->and;
		p[b] |= routing_prefix->or;
	}

	/*
	 * Handle the cross over byte:
	 *
	 *    & {ROUTING_PREFIX,HOST_ID}->and | {ROUTING_PREFIX,HOST_ID}->or
	 *
	 * the hmask's shift is a little counter intuitive - it clears
	 * the first (most significant) XBITs.
	 *
	 * tricky logic:
	 * - if xbyte == raw.len we must not access p[xbyte]
	 */
	if (xbyte < afi->ip_size) {
		uint8_t hmask = 0xFF >> xbit; /* clear MSBs */
		uint8_t pmask = ~hmask; /* set MSBs */
		p[xbyte] &= (routing_prefix->and & pmask) | (host_identifier->and & hmask);
		p[xbyte] |= (routing_prefix->or & pmask) | (host_identifier->or & hmask);
	}

	/* trailing bytes only contain the HOST_ID */
	for (unsigned b = xbyte + 1; b < afi->ip_size; b++) {
		p[b] &= host_identifier->and;
		p[b] |= host_identifier->or;
	}

	return address_from_raw(afi, &bytes);
}

void pexpect_address(const ip_address *a, const char *s, where_t where)
{
	if (a != NULL && a->version != 0) {
		/* i.e., is-set */
		if (a->is_address == false ||
		    a->is_endpoint == true ||
		    a->hport != 0 ||
		    a->ipproto != 0) {
			address_buf b;
			dbg("EXPECTATION FAILED: %s is not an address; "PRI_ADDRESS" "PRI_WHERE,
			    s, pri_address(a, &b),
			    pri_where(where));
		}
	}
}
