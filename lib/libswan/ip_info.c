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
			/* print pair of bytes in hex, supress leading zeros */
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

#define IPv4_ADDRESS .is_address = true, .version = 4
#define IPv6_ADDRESS .is_address = true, .version = 6

#define IPv4_ENDPOINT .is_endpoint = true, .version = 4
#define IPv6_ENDPOINT .is_endpoint = true, .version = 6

const struct ip_info ipv4_info = {

	.ip_version = 4,
	.ip_size = sizeof(struct in_addr),
	.ip_name = "IPv4",

	/* ip_address */
	.any_address = { IPv4_ADDRESS, }, /* 0.0.0.0 */
	.loopback_address = { IPv4_ADDRESS, .bytes = { { 127, 0, 0, 1, }, }, },

	/* ip_endpoint */
	.any_endpoint = { IPv4_ENDPOINT, }, /* 0.0.0.0:0 */

	/* ip_subnet */
	.mask_cnt = 32,
	.no_addresses = { .addr = { IPv4_ENDPOINT, }, .maskbits = 32, }, /* 0.0.0.0/32 */
	.all_addresses = { .addr = { IPv4_ENDPOINT, }, .maskbits = 0, }, /* 0.0.0.0/0 */

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

const struct ip_info ipv6_info = {

	.ip_version = 6,
	.ip_size = sizeof(struct in6_addr),
	.ip_name = "IPv6",

	/* ip_address */
	.any_address = { IPv6_ADDRESS, }, /* :: */
	.loopback_address = { IPv6_ADDRESS, .bytes = { { [15] = 1, }, }, }, /* ::1 */

	/* ip_endpoint */
	.any_endpoint = { IPv6_ENDPOINT, }, /* [::]:0 */

	/* ip_subnet */
	.mask_cnt = 128,
	.no_addresses = { .addr = { IPv6_ENDPOINT, }, .maskbits = 128, }, /* ::/128 */
	.all_addresses = { .addr = { IPv6_ENDPOINT, }, .maskbits = 0, }, /* ::/0 */

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
		[4] = &ipv4_info,
		[6] = &ipv6_info,
	};
	passert(version < elemsof(ip_types));
	return ip_types[version];
}
