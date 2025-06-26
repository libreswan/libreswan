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

#include <sys/socket.h>		/* for AF_INET/AF_INET6/AF_UNSPEC */

#include "ietf_constants.h"
#include "ip_info.h"
#include "passert.h"
#include "lswlog.h"		/* for bad_case() */

const struct ip_info unspec_ip_info = {
	.af = AF_UNSPEC,
};

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

static size_t jam_ipv6_address_wrapped(struct jambuf *buf, const struct ip_info *afi, const struct ip_bytes *bytes)
{
	size_t s = 0;
	s += jam_string(buf, "[");
	s += jam_ipv6_address(buf, afi, bytes);
	s += jam_string(buf, "]");
	return s;
}

static ip_address address_from_ipv4_sockaddr(const ip_sockaddr sa)
{
	passert(sa.sa.sa.sa_family == AF_INET);
	return address_from_in_addr(&sa.sa.sin.sin_addr);
}

static ip_address address_from_ipv6_sockaddr(const ip_sockaddr sa)
{
	passert(sa.sa.sa.sa_family == AF_INET6);
	return address_from_in6_addr(&sa.sa.sin6.sin6_addr);
}

static ip_port port_from_ipv4_sockaddr(const ip_sockaddr sa)
{
	passert(sa.sa.sa.sa_family == AF_INET);
	return ip_nport(sa.sa.sin.sin_port);
}

static ip_port port_from_ipv6_sockaddr(const ip_sockaddr sa)
{
	passert(sa.sa.sa.sa_family == AF_INET6);
	return ip_nport(sa.sa.sin6.sin6_port);
}

/*
 * Construct well known addresses.
 */

#define IPv4_FF { { 255, 255, 255, 255, }, }

const struct ip_info ip_families[IP_INDEX_ROOF] = {

	[IPv4_INDEX] = {

		.ip.version = IPv4,
		.ip_index = IPv4_INDEX,
		.ip_size = sizeof(struct in_addr),

		.n_name = "4",
		.ip_name = "IPv4",
		.inet_name = "inet",
		.mask_cnt = 32,

		/* formatting */
		.jam.address = jam_ipv4_address,
		.jam.address_wrapped = jam_ipv4_address,

		/*
		 * Known values.
		 *
		 * Use .address.unset, and not .address-{...}, when
		 * initializing so that `grep -e address.unset` finds
		 * it.
		 */
		.address.unspec = { .ip.is_set = true, .ip.version = IPv4, }, /* 0.0.0.0 */
		.address.loopback = { .ip.is_set = true, .ip.version = IPv4, .bytes = { { 127, 0, 0, 1, }, }, },
		/* none/zero */
		.range.zero = { .ip.is_set = true, .ip.version = IPv4, },
		.selector.zero = { .ip.is_set = true, .ip.version = IPv4, }, /* 0.0.0.0/0 */
		.subnet.zero = { .ip.is_set = true, .ip.version = IPv4, .maskbits = 32, }, /* 0.0.0.0/32 */
		/* all addresses */
		.range.all = { .ip.is_set = true, .ip.version = IPv4, .hi = IPv4_FF, }, /* 0.0.0.0-255.255.255.255 */
		.selector.all = { .ip.is_set = true, .ip.version = IPv4, .hi = IPv4_FF, }, /* 0.0.0.0-255.255.255.255 */
		.subnet.all = { .ip.is_set = true, .ip.version = IPv4, .maskbits = 0, }, /* 0.0.0.0/0 */
		/* unset, yet IP version is known */
		.address.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv4, },
		.endpoint.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv4, },
		.range.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv4, },
		.selector.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv4, },
		.subnet.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv4, },

		/* ike */
		.ikev1_max_fragment_size = ISAKMP_V1_FRAG_MAXLEN_IPv4,
		.ikev2_max_fragment_size = ISAKMP_V2_FRAG_MAXLEN_IPv4,

		/* socket() */
		.socket = {
			.domain = PF_INET,
			.domain_name = "PF_INET",
		},

		/* sockaddr */
		.af = AF_INET,
		.af_name = "AF_INET",
		.sockaddr_size = sizeof(struct sockaddr_in),
		.address_from_sockaddr = address_from_ipv4_sockaddr,
		.port_from_sockaddr = port_from_ipv4_sockaddr,

		/* IKEv2 Traffic Selector */
		.ikev2_ts_addr_range_type = IKEv2_TS_IPV4_ADDR_RANGE,
		.ikev2_internal_address = IKEv2_INTERNAL_IP4_ADDRESS,
		.ikev2_internal_dns = IKEv2_INTERNAL_IP4_DNS,

		/* id */
		.id_ip_addr = ID_IPV4_ADDR,
		.id_ip_addr_subnet = ID_IPV4_ADDR_SUBNET,
		.id_ip_addr_range = ID_IPV4_ADDR_RANGE,
	},

#define IPv6_FF { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }, }

	[IPv6_INDEX] = {

		.ip.version = IPv6,
		.ip_index = IPv6_INDEX,
		.ip_size = sizeof(struct in6_addr),

		.n_name = "6",
		.ip_name = "IPv6",
		.inet_name = "inet6",
		.mask_cnt = 128,

		/* formatting */
		.jam.address = jam_ipv6_address,
		.jam.address_wrapped = jam_ipv6_address_wrapped,


		/*
		 * Known values.
		 *
		 * Use the syntax .address.unset, and not
		 * .address-{...}, when initializing so that `grep -e
		 * address.unset` finds it.
		 */
		.address.unspec = { .ip.is_set = true, .ip.version = IPv6, }, /* :: */
		.address.loopback = { .ip.is_set = true, .ip.version = IPv6, .bytes = { { [15] = 1, }, }, }, /* ::1 */
		/* none/zero */
		.range.zero = { .ip.is_set = true, .ip.version = IPv6, },
		.selector.zero = { .ip.is_set = true, .ip.version = IPv6, }, /* ::/0 */
		.subnet.zero = { .ip.is_set = true, .ip.version = IPv6, .maskbits = 128, }, /* ::/128 */
		/* all addresses */
		.range.all = { .ip.is_set = true, .ip.version = IPv6, .hi = IPv6_FF, }, /* ::-ffff:..:ffff */
		.selector.all = { .ip.is_set = true, .ip.version = IPv6, .hi = IPv6_FF, }, /* ::-ffff:..:ffff */
		.subnet.all = { .ip.is_set = true, .ip.version = IPv6, .maskbits = 0, }, /* ::/0 */
		/* unset, yet IP version is known */
		.address.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv6, },
		.endpoint.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv6, },
		.range.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv6, },
		.subnet.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv6, },
		.selector.unset = { .ip.is_set = false/*YES-FALSE*/, .ip.version = IPv6, },

		/* ike */
		.ikev1_max_fragment_size = ISAKMP_V1_FRAG_MAXLEN_IPv6,
		.ikev2_max_fragment_size = ISAKMP_V2_FRAG_MAXLEN_IPv6,

		/* socket() */
		.socket = {
			.domain = PF_INET6,
			.domain_name = "PF_INET6",
		},

		/* sockaddr */
		.af = AF_INET6,
		.af_name = "AF_INET6",
		.sockaddr_size = sizeof(struct sockaddr_in6),
		.address_from_sockaddr = address_from_ipv6_sockaddr,
		.port_from_sockaddr = port_from_ipv6_sockaddr,

		/* IKEv2 Traffic Selector */
		.ikev2_ts_addr_range_type = IKEv2_TS_IPV6_ADDR_RANGE,
		.ikev2_internal_address = IKEv2_INTERNAL_IP6_ADDRESS,
		.ikev2_internal_dns = IKEv2_INTERNAL_IP6_DNS,

		/* id */
		.id_ip_addr = ID_IPV6_ADDR,
		.id_ip_addr_subnet = ID_IPV6_ADDR_SUBNET,
		.id_ip_addr_range = ID_IPV6_ADDR_RANGE,
	},
};

const struct ip_info *aftoinfo(int af)
{
	switch (af) {
	case AF_INET:
		return &ipv4_info;
	case AF_INET6:
		return &ipv6_info;
	case AF_UNSPEC:
#if 0
		return &unspec_info;
#else
		return NULL;
#endif
	default:
		return NULL;
	}
}

const struct ip_info *ip_version_info(enum ip_version version)
{
	static const struct ip_info *ip_types[] = {
		[0] = NULL,
		[IPv4] = &ipv4_info,
		[IPv6] = &ipv6_info,
	};
	passert(version < elemsof(ip_types));
	return ip_types[version];
}

/*
 * Values for addrfamily={ipv4,ipv6}
 */

const struct ip_info *ttoinfo(const char *name)
{
	struct {
		const char *name;
		const struct ip_info *afi;
	} names[] = {
		{ "ipv4",  &ipv4_info, },
		{ "ipv6",  &ipv6_info, },
		/* aliases - undocumented on purpose */
		{ "v4",    &ipv4_info, },
		{ "inet",  &ipv4_info, },
		{ "v6",    &ipv6_info, },
		{ "inet6", &ipv6_info, },
	};
	FOR_EACH_ELEMENT(n, names) {
		if (strcaseeq(n->name, name)) {
			return n->afi;
		}
	}
	return NULL;
};
