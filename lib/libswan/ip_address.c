/*
 * low-level ip_address ugliness
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2018  Andrew Cagney.
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

#include "internal.h"
#include "libreswan.h"
#include "ip_address.h"
#include "lswlog.h"

/*
 * portof - get the port field of an ip_address in network order.
 *
 * Return -1 if ip_address isn't valid.
 */

int nportof(const ip_address * src)
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return src->u.v4.sin_port;

	case AF_INET6:
		return src->u.v6.sin6_port;

	default:
		return -1;
	}
}

int hportof(const ip_address *src)
{
	int nport = nportof(src);
	if (nport >= 0) {
		return ntohs(nport);
	} else {
		return -1;
	}
}

/*
 * setportof - set the network ordered port field of an ip_address
 */

ip_address nsetportof(int port /* network order */, ip_address dst)
{
	switch (dst.u.v4.sin_family) {
	case AF_INET:
		dst.u.v4.sin_port = port;
		break;
	case AF_INET6:
		dst.u.v6.sin6_port = port;
		break;
	default:
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("Will not set port on bogus address 0.0.0.0");
	}
	return dst;
}

ip_address hsetportof(int port /* host byte order */, ip_address dst)
{
	return nsetportof(htons(port), dst);
}

/*
 * sockaddrof - get a pointer to the sockaddr hiding inside an ip_address
 */
struct sockaddr *sockaddrof(const ip_address *src)
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return (struct sockaddr *)&src->u.v4;

	case AF_INET6:
		return (struct sockaddr *)&src->u.v6;

	default:
		return NULL;	/* "can't happen" */
	}
}

/*
 * sockaddrlenof - get length of the sockaddr hiding inside an ip_address
 *
 * Return 0 on error.
 */
size_t sockaddrlenof(const ip_address * src)
{
	switch (src->u.v4.sin_family) {
	case AF_INET:
		return sizeof(src->u.v4);

	case AF_INET6:
		return sizeof(src->u.v6);

	default:
		return 0;
	}
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
	return str_address_cooked(src, b);
}

const char *sensitive_ipstr(const ip_address *src, ipstr_buf *b)
{
	return str_address_sensitive(src, b);
}

chunk_t same_ip_address_as_chunk(const ip_address *address)
{
	if (address == NULL) {
		return EMPTY_CHUNK;
	}
	switch (address->u.v4.sin_family) {
	case AF_INET:
		return CHUNKO(address->u.v4.sin_addr.s_addr); /* strip const */
	case AF_INET6:
		return CHUNKO(address->u.v6.sin6_addr); /* strip const */
	default:
		return EMPTY_CHUNK;
	}
}

/*
 * Implement https://tools.ietf.org/html/rfc5952
 */

static void fmt_raw_ipv4_address(struct lswlog *buf, chunk_t a, char sepc)
{
	const char seps[2] = { sepc == 0 ? '.' : sepc, 0, };
	const char *sep = "";
	for (size_t i = 0; i < a.len; i++) {
		lswlogf(buf, "%s%"PRIu8, sep, a.ptr[i]);
		sep = seps;
	}
}

static void fmt_raw_ipv6_address(struct lswlog *buf, chunk_t a, char sepc,
				 chunk_t skip)
{
	const char seps[2] = { sepc == 0 ? ':' : sepc, 0, };
	const uint8_t *ptr = a.ptr;
	const char *sep = "";
	const uint8_t *last = a.ptr + a.len - 2;
	while (ptr <= last) {
		if (ptr == skip.ptr) {
			/* skip zero run */
			lswlogf(buf, "%s%s", seps, seps);
			sep = "";
			ptr += skip.len;
		} else {
			/* suppress zeros */
			unsigned ia = (ptr[0] << 8) + ptr[1];
			lswlogf(buf, "%s%x", sep, ia);
			sep = seps;
			ptr += 2;
		}
	}
}

void fmt_address_raw(struct lswlog *buf, const ip_address *address, char sepc)
{
	chunk_t a = same_ip_address_as_chunk(address);
	if (a.len == 0) {
		lswlogs(buf, "<invalid-length>");
		return;
	}
	int type = addrtypeof(address);
	switch (type) {
	case AF_INET: /* N.N.N.N */
		fmt_raw_ipv4_address(buf, a, sepc);
		break;
	case AF_INET6: /* N:N:...:N */
		fmt_raw_ipv6_address(buf, a, sepc, EMPTY_CHUNK);
		break;
	case 0:
		lswlogf(buf, "<invalid-address>");
		break;
	default:
		lswlogf(buf, "<invalid-type-%d>", type);
		break;
	}
}

/*
 * Find longest run of zero pairs that should be suppressed (need at
 * least two).
 */
static chunk_t zeros_to_skip(chunk_t a)
{
	chunk_t zero = EMPTY_CHUNK;
	uint8_t *ptr = a.ptr;
	uint8_t *last = a.ptr + a.len - 2;
	while (ptr <= last) {
		unsigned l = 0;
		for (l = 0; ptr + l <= last; l += 2) {
			unsigned ia = (ptr[l+0] << 8) + ptr[l+1];
			if (ia != 0) {
				break;
			}
		}
		if (l > 2 && l > zero.len) {
			zero.ptr = ptr;
			zero.len = l;
			ptr += l;
		} else {
			ptr += 2;
		}
	}
	return zero;
}

void fmt_address_cooked(struct lswlog *buf, const ip_address *address)
{
	chunk_t a = same_ip_address_as_chunk(address);
	if (a.len == 0) {
		lswlogs(buf, "<invalid-length>");
		return;
	}
	int type = addrtypeof(address);
	switch (type) {
	case AF_INET: /* N.N.N.N */
		fmt_raw_ipv4_address(buf, a, 0);
		break;
	case AF_INET6: /* N:N:...:N */
		fmt_raw_ipv6_address(buf, a, 0, zeros_to_skip(a));
		break;
	case 0:
		lswlogf(buf, "<invalid-address>");
		break;
	default:
		lswlogf(buf, "<invalid-type-%d>", type);
		break;
	}
}

void fmt_address_sensitive(struct lswlog *buf, const ip_address *address)
{
	if (log_ip) {
		fmt_address_cooked(buf, address);
	} else {
		lswlogs(buf, "<ip-address>");
	}
}

void fmt_address_reversed(struct lswlog *buf, const ip_address *address)
{
	chunk_t bytes = same_ip_address_as_chunk(address);
	int type = addrtypeof(address);
	switch (type) {
	case AF_INET:
		for (int i = bytes.len - 1; i >= 0; i--) {
			uint8_t byte = bytes.ptr[i];
			fmt(buf, "%d.", byte);
		}
		fmt(buf, "IN-ADDR.ARPA.");
		break;
	case AF_INET6:
		for (int i = bytes.len - 1; i >= 0; i--) {
			uint8_t byte = bytes.ptr[i];
			fmt(buf, "%x.%x.", byte & 0xf, byte >> 4);
		}
		fmt(buf, "IP6.ARPA.");
		break;
	case 0:
		fmt(buf, "<invalid-address>");
		break;
	default:
		fmt(buf, "<invalid-type-%d>", type);
		break;
	}
}

const char *str_address_raw(const ip_address *src, char sep,
			    ip_address_buf *dst)
{
	fmtbuf_t buf = ARRAY_AS_FMTBUF(dst->buf);
	fmt_address_raw(&buf, src, sep);
	return dst->buf;
}

const char *str_address_cooked(const ip_address *src,
			       ip_address_buf *dst)
{
	fmtbuf_t buf = ARRAY_AS_FMTBUF(dst->buf);
	fmt_address_cooked(&buf, src);
	return dst->buf;
}

const char *str_address_sensitive(const ip_address *src,
			       ip_address_buf *dst)
{
	fmtbuf_t buf = ARRAY_AS_FMTBUF(dst->buf);
	fmt_address_sensitive(&buf, src);
	return dst->buf;
}

const char *str_address_reversed(const ip_address *src,
				 address_reversed_buf *dst)
{
	fmtbuf_t buf = ARRAY_AS_FMTBUF(dst->buf);
	fmt_address_reversed(&buf, src);
	return dst->buf;
}
