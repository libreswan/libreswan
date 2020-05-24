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
 * Construct well known addresses.
 */

#define ANY_IPv4_ADDRESS { .is_address = true, .version = 4, }
#define ANY_IPv6_ADDRESS { .is_address = true, .version = 6, }

#ifdef ENDPOINT_TYPE
#define ANY_IPv4_ENDPOINT { .address = ANY_IPv4_ADDRESS, .hport = 0, }
#define ANY_IPv6_ENDPOINT { .address = ANY_IPv6_ADDRESS, .hport = 0, }
#else
#define ANY_IPv4_ENDPOINT { .is_endpoint = true, .version = 4, }
#define ANY_IPv6_ENDPOINT { .is_endpoint = true, .version = 6, }
#endif

const struct ip_info ipv4_info = {
	/* ip_address */
	.ip_version = 4,
	.ip_size = sizeof(struct in_addr),
	.ip_name = "IPv4",
	.any_address = ANY_IPv4_ADDRESS, /* 0.0.0.0 */
	.loopback_address = {
		.version = 4,
		.bytes = { .byte = { 127, 0, 0, 1, }, },
	}, /* 127.0.0.1 */

	/* ip_endpoint */
	.any_endpoint = ANY_IPv4_ENDPOINT, /* 0.0.0.0:0 */

	/* ip_subnet */
	.mask_cnt = 32,
	.no_addresses = { .addr = ANY_IPv4_ENDPOINT, .maskbits = 32, }, /* 0.0.0.0/32 */
	.all_addresses = { .addr = ANY_IPv4_ENDPOINT, .maskbits = 0, }, /* 0.0.0.0/32 */
	/* ike */
	.ikev1_max_fragment_size = ISAKMP_V1_FRAG_MAXLEN_IPv4,
	.ikev2_max_fragment_size = ISAKMP_V2_FRAG_MAXLEN_IPv4,

	/* sockaddr */
	.af = AF_INET,
	.af_name = "AF_INET",
	.sockaddr_size = sizeof(struct sockaddr_in),

	/* id */
	.id_addr = ID_IPV4_ADDR,
	.id_subnet = ID_IPV4_ADDR_SUBNET,
	.id_range = ID_IPV4_ADDR_RANGE,
};

const struct ip_info ipv6_info = {

	/* ip_address */
	.ip_version = 6,
	.ip_size = sizeof(struct in6_addr),
	.ip_name = "IPv6",
	.any_address = ANY_IPv6_ADDRESS, /* :: */
	.loopback_address = { .version = 6, .bytes = { { [15] = 1, }, }, }, /* ::1 */

	/* ip_endpoint */
	.any_endpoint = ANY_IPv6_ENDPOINT, /* [::]:0 */

	/* ip_subnet */
	.mask_cnt = 128,
	.no_addresses = { .addr = ANY_IPv6_ENDPOINT, .maskbits = 128, }, /* ::/128 */
	.all_addresses = { .addr = ANY_IPv6_ENDPOINT, .maskbits = 0, }, /* ::/0 */

	/* ike */
	.ikev1_max_fragment_size = ISAKMP_V1_FRAG_MAXLEN_IPv6,
	.ikev2_max_fragment_size = ISAKMP_V2_FRAG_MAXLEN_IPv6,

	/* sockaddr */
	.af = AF_INET6,
	.af_name = "AF_INET6",
	.sockaddr_size = sizeof(struct sockaddr_in6),

	/* id */
	.id_addr = ID_IPV6_ADDR,
	.id_subnet = ID_IPV6_ADDR_SUBNET,
	.id_range = ID_IPV6_ADDR_RANGE,
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
