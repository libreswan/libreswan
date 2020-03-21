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
#include "lswlog.h"		/* for libreswan_log() */
#include "ip_info.h"

ip_address address_from_shunk(const struct ip_info *afi, const shunk_t bytes)
{
	passert(afi != NULL);
	ip_address address = {
		.version = afi->ip_version,
	};
	passert(afi->ip_size == bytes.len);
	memcpy(address.bytes, bytes.ptr, bytes.len);
	return address;
}

ip_address address_from_in_addr(const struct in_addr *in)
{
	return address_from_shunk(&ipv4_info, THING_AS_SHUNK(*in));
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
	return address_from_shunk(&ipv6_info, THING_AS_SHUNK(*in6));
}

const struct ip_info *address_type(const ip_address *address)
{
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
	return shunk2(address->bytes, afi->ip_size);
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
	return chunk2(address->bytes, afi->ip_size);
}

/*
 * Implement https://tools.ietf.org/html/rfc5952
 */

static void jam_raw_ipv4_address(jambuf_t *buf, shunk_t a, char sepc)
{
	const char seps[2] = { sepc == 0 ? '.' : sepc, 0, };
	const char *sep = "";
	for (size_t i = 0; i < a.len; i++) {
		const uint8_t *bytes = a.ptr;
		jam(buf, "%s%"PRIu8, sep, bytes[i]);
		sep = seps;
	}
}

static void jam_raw_ipv6_address(jambuf_t *buf, shunk_t a, char sepc,
				 shunk_t skip)
{
	const char seps[2] = { sepc == 0 ? ':' : sepc, 0, };
	const void *ptr = a.ptr;
	const char *sep = "";
	const void *last = a.ptr + a.len - 2;
	while (ptr <= last) {
		if (ptr == skip.ptr) {
			/* skip zero run */
			jam(buf, "%s%s", seps, seps);
			sep = "";
			ptr += skip.len;
		} else {
			/*
			 * suppress leading zeros in two-byte
			 * big-endian hex value, need to cast away
			 * ptr's sign
			 */
			const uint8_t *p = (const uint8_t*)ptr;
			unsigned ia = (p[0] << 8) + p[1];
			jam(buf, "%s%x", sep, ia);
			sep = seps;
			ptr += 2;
		}
	}
}

void jam_address_raw(jambuf_t *buf, const ip_address *address, char sepc)
{
	if (address == NULL) {
		jam(buf, "<none>");
		return;
	}
	shunk_t a = address_as_shunk(address);
	int type = addrtypeof(address);
	switch (type) {
	case AF_INET: /* N.N.N.N */
		jam_raw_ipv4_address(buf, a, sepc);
		break;
	case AF_INET6: /* N:N:...:N */
		jam_raw_ipv6_address(buf, a, sepc, null_shunk);
		break;
	case AF_UNSPEC:
		jam(buf, "<unspecified>");
		break;
	default:
		jam(buf, "<invalid>");
		break;
	}
}

/*
 * Find longest run of zero pairs that should be suppressed (need at
 * least two).
 */
static shunk_t zeros_to_skip(shunk_t a)
{
	shunk_t zero = null_shunk;
	const char *ptr = a.ptr;
	const char *last = a.ptr + a.len - 2;
	while (ptr <= last) {
		unsigned l = 0;
		for (l = 0; ptr + l <= last; l += 2) {
			/* ptr is probably signed */
			if (ptr[l+0] != 0 || ptr[l+1] != 0) {
				break;
			}
		}
		if (l > 2 && l > zero.len) {
			zero = shunk2(ptr, l);
			ptr += l;
		} else {
			ptr += 2;
		}
	}
	return zero;
}

static void format_address_cooked(jambuf_t *buf, bool sensitive,
				  const ip_address *address)
{
	/*
	 * A NULL address can't be sensitive.
	 */
	if (address == NULL) {
		jam(buf, "<none>");
		return;
	}
	if (sensitive) {
		jam(buf, "<ip-address>");
		return;
	}
	shunk_t a = address_as_shunk(address);
	int type = addrtypeof(address);
	switch (type) {
	case AF_INET: /* N.N.N.N */
		jam_raw_ipv4_address(buf, a, 0);
		break;
	case AF_INET6: /* N:N:...:N */
		jam_raw_ipv6_address(buf, a, 0, zeros_to_skip(a));
		break;
	case AF_UNSPEC:
		jam(buf, "<unspecified>");
		break;
	default:
		jam(buf, "<invalid>");
		break;
	}
}

void jam_address(jambuf_t *buf, const ip_address *address)
{
	format_address_cooked(buf, false, address);
}

void jam_address_sensitive(jambuf_t *buf, const ip_address *address)
{
	format_address_cooked(buf, !log_ip, address);
}

void jam_address_reversed(jambuf_t *buf, const ip_address *address)
{
	shunk_t bytes = address_as_shunk(address);
	int type = addrtypeof(address);
	switch (type) {
	case AF_INET:
	{
		for (int i = bytes.len - 1; i >= 0; i--) {
			const uint8_t *byte = bytes.ptr;
			jam(buf, "%d.", byte[i]);
		}
		jam(buf, "IN-ADDR.ARPA.");
		break;
	}
	case AF_INET6:
	{
		for (int i = bytes.len - 1; i >= 0; i--) {
			const uint8_t *byte = bytes.ptr;
			jam(buf, "%x.%x.", byte[i] & 0xf, byte[i] >> 4);
		}
		jam(buf, "IP6.ARPA.");
		break;
	}
	case AF_UNSPEC:
		jam(buf, "<unspecified>");
		break;
	default:
		jam(buf, "<invalid>");
		break;
	}
}

const char *str_address_raw(const ip_address *src, char sep,
			    address_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_address_raw(&buf, src, sep);
	return dst->buf;
}

const char *str_address(const ip_address *src,
			       address_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_address(&buf, src);
	return dst->buf;
}

const char *str_address_sensitive(const ip_address *src,
				  address_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_address_sensitive(&buf, src);
	return dst->buf;
}

const char *str_address_reversed(const ip_address *src,
				 address_reversed_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_address_reversed(&buf, src);
	return dst->buf;
}

const ip_address address_invalid = {
	.version = 0,
};

ip_address address_any(const struct ip_info *info)
{
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
		PEXPECT_LOG("AF_UNSPEC unexpected");
		return address_invalid;
	} else {
		return info->any_address;
	}
}

bool address_is_any(const ip_address *address)
{
	const struct ip_info *type = address_type(address);
	if (type == NULL) {
		return false;
	} else {
		shunk_t addr = address_as_shunk(address);
		shunk_t any = address_as_shunk(&type->any_address);
		return hunk_eq(addr, any);
	}
}

bool address_is_specified(const ip_address *address)
{
	const struct ip_info *type = address_type(address);
	if (type == NULL) {
		return false;
	} else {
		shunk_t addr = address_as_shunk(address);
		shunk_t any = address_as_shunk(&type->any_address);
		return !hunk_eq(addr, any);
	}
}

bool address_is_loopback(const ip_address *address)
{
	const struct ip_info *type = address_type(address);
	if (type == NULL) {
		return false;
	} else {
		shunk_t addr = address_as_shunk(address);
		shunk_t loopback = address_as_shunk(&type->loopback_address);
		return hunk_eq(addr, loopback);
	}
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

ip_address address_blit(ip_address address,
			const struct ip_blit *routing_prefix,
			const struct ip_blit *host_id,
			unsigned nr_mask_bits)
{
	/* strip port; copy type */
	chunk_t raw = address_as_chunk(&address);

	if (!pexpect(nr_mask_bits <= raw.len * 8)) {
		return address_invalid;	/* "can't happen" */
	}

	uint8_t *p = raw.ptr; /* cast void* */

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
	size_t xbyte = nr_mask_bits / BITS_PER_BYTE;
	unsigned xbit = nr_mask_bits % BITS_PER_BYTE;

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
	if (xbyte < raw.len) {
		uint8_t hmask = 0xFF >> xbit; /* clear MSBs */
		uint8_t pmask = ~hmask; /* set MSBs */
		p[xbyte] &= (routing_prefix->and & pmask) | (host_id->and & hmask);
		p[xbyte] |= (routing_prefix->or & pmask) | (host_id->or & hmask);
	}

	/* trailing bytes only contain the HOST_ID */
	for (unsigned b = xbyte + 1; b < raw.len; b++) {
		p[b] &= host_id->and;
		p[b] |= host_id->or;
	}

	return address;
}
