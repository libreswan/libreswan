/* AF Information, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include "ietf_constants.h"
#include "ip_info.h"
#include "passert.h"
#include "lswlog.h"		/* for bad_case() */

/*
 * Implement https://tools.ietf.org/html/rfc5952
 */

static size_t jam_ipv4_address(struct jambuf *buf, const struct ip_info *afi, const struct ip_bytes *bytes)
{
	const char *sep = "";
	size_t s = 0;
	for (size_t i = 0; i < afi->ip_size; i++) {
		s += jam(buf, "%s%"PRIu8, sep, bytes->byte[i]);
		sep = ".";
	}
	return s;
}

/*
 * Find longest run of zero pairs that should be suppressed (need at
 * least two).
 */
static shunk_t zeros_to_skip(const struct ip_info *afi, const struct ip_bytes *bytes)
{
	shunk_t zero = null_shunk;
	const uint8_t *ptr = bytes->byte;
	/* stop at or before last pair; ensure ptr[1] safe */
	const uint8_t *last = ptr + afi->ip_size - 2;
	while (ptr <= last) {
		/*
		 * Set L to the the number of paired zero bytes
		 * starting at PTR (could be zero).
		 */
		unsigned l = 0;
		for (l = 0; ptr + l <= last; l += 2) {
			/* need both bytes zero */
			if (ptr[l+0] != 0 || ptr[l+1] != 0) {
				break;
			}
		}
		/*
		 * Save longer run, but only when more than one pair.
		 */
		if (l > 2 && l > zero.len) {
			zero = shunk2(ptr, l);
			ptr += l;
		} else {
			ptr += 2;
		}
	}
	return zero;
}

static size_t jam_ipv6_address(struct jambuf *buf, const struct ip_info *afi, const struct ip_bytes *bytes)
{
	size_t s = 0;
	shunk_t zeros = zeros_to_skip(afi, bytes);
	const char *sep = "";
	const uint8_t *ptr = bytes->byte;
	/* stop at or before last pair; ensure ptr[1] safe */
	const uint8_t *last = ptr + afi->ip_size - 2;
	while (ptr <= last) {
		if (ptr == zeros.ptr) {
			/* skip zero run */
			s += jam(buf, "::");
			sep = "";
			ptr += zeros.len;
		} else {
			/* print pair of bytes in hex, suppress leading zeros */
			unsigned ia = (ptr[0] << 8) + ptr[1];
			s += jam(buf, "%s%x", sep, ia);
			sep = ":";
			ptr += 2;
		}
	}
	return s;
}

/*
 * Construct well known addresses.
 */

#define IPv4_FF { { 255, 255, 255, 255, }, }

const struct ip_info ipv4_info = {

	.ip_version = IPv4,
	.ip_size = sizeof(struct in_addr),
	.ip_name = "IPv4",
	.mask_cnt = 32,

	/* ip_address - .address.any matches grep */
	.address.any = { .is_set = true, .version = IPv4, }, /* 0.0.0.0 */
	.address.loopback = { .is_set = true, .version = IPv4, .bytes = { { 127, 0, 0, 1, }, }, },

	/* ip_subnet - .subnet.any matches grep */
	.subnet.zero = { .is_set = true, .version = IPv4, .maskbits = 32, }, /* 0.0.0.0/32 */
	.subnet.all = { .is_set = true, .version = IPv4, .maskbits = 0, }, /* 0.0.0.0/0 */

	/* ip_range - .range.any matches grep */
	.range.zero = { .is_set = true, .version = IPv4, },
	.range.all = { .is_set = true, .version = IPv4, .end = IPv4_FF, },

	/* ip_selector - .selector.any matches grep */
	.selector.zero = { .is_set = true, .version = IPv4, .maskbits = 32, }, /* 0.0.0.0/0 */
	.selector.all = { .is_set = true, .version = IPv4, .maskbits = 0, }, /* 0.0.0.0/0 */

	/* ike */
	.ikev1_max_fragment_size = ISAKMP_V1_FRAG_MAXLEN_IPv4,
	.ikev2_max_fragment_size = ISAKMP_V2_FRAG_MAXLEN_IPv4,

	/* sockaddr */
	.af = AF_INET,
	.af_name = "AF_INET",
	.sockaddr_size = sizeof(struct sockaddr_in),

	/* id */
	.id_ip_addr = ID_IPV4_ADDR,
	.id_ip_addr_subnet = ID_IPV4_ADDR_SUBNET,
	.id_ip_addr_range = ID_IPV4_ADDR_RANGE,

	/* output */
	.jam_address = jam_ipv4_address,
};

#define IPv6_FF { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }, }

const struct ip_info ipv6_info = {

	.ip_version = IPv6,
	.ip_size = sizeof(struct in6_addr),
	.ip_name = "IPv6",
	.mask_cnt = 128,

	/* ip_address - .address.any matches grep */
	.address.any = { .is_set = true, .version = IPv6, }, /* :: */
	.address.loopback = { .is_set = true, .version = IPv6, .bytes = { { [15] = 1, }, }, }, /* ::1 */

	/* ip_subnet - .subnet.any matches grep */
	.subnet.zero = { .is_set = true, .version = IPv6, .maskbits = 128, }, /* ::/128 */
	.subnet.all = { .is_set = true, .version = IPv6, .maskbits = 0, }, /* ::/0 */

	/* ip_range - .range.any matches grep */
	.range.zero = { .is_set = true, .version = IPv6, },
	.range.all = { .is_set = true, .version = IPv6, .end = IPv6_FF, },

	/* ip_selector - .selector.any matches grep */
	.selector.zero = { .is_set = true, .version = IPv6, .maskbits = 128, }, /* ::/0 */
	.selector.all = { .is_set = true, .version = IPv6, .maskbits = 0, }, /* ::/0 */

	/* ike */
	.ikev1_max_fragment_size = ISAKMP_V1_FRAG_MAXLEN_IPv6,
	.ikev2_max_fragment_size = ISAKMP_V2_FRAG_MAXLEN_IPv6,

	/* sockaddr */
	.af = AF_INET6,
	.af_name = "AF_INET6",
	.sockaddr_size = sizeof(struct sockaddr_in6),

	/* id */
	.id_ip_addr = ID_IPV6_ADDR,
	.id_ip_addr_subnet = ID_IPV6_ADDR_SUBNET,
	.id_ip_addr_range = ID_IPV6_ADDR_RANGE,

	/* output */
	.jam_address = jam_ipv6_address,
};

const struct ip_info *aftoinfo(int af)
{
	switch (af) {
	case AF_INET:
		return &ipv4_info;
	case AF_INET6:
		return &ipv6_info;
	case AF_UNSPEC:
		return NULL;
	default:
		bad_case(af);
	}
}

const struct ip_info *ip_version_info(unsigned version)
{
	static const struct ip_info *ip_types[] = {
		[0] = NULL,
		[IPv4] = &ipv4_info,
		[IPv6] = &ipv6_info,
	};
	passert(version < elemsof(ip_types));
	return ip_types[version];
}
