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
#include "libreswan/passert.h"
#include "lswlog.h"		/* for bad_case() */

/*
 * Construct well known addresses.
 *
 * Perhaps one day this will all be made static const.  However, to do
 * that this code would need to assume ip_address internals, and
 * likely also hardwire the contents of those constants.
 *
 * The current code uses address_from_in*_addr() since that knows how
 * to initialize secret sockaddr fields such as BSD's size.
 */

static ip_address any_address_ipv4;
static ip_address any_address_ipv6;

static ip_address loopback_address_ipv4;
static ip_address loopback_address_ipv6;

static ip_subnet no_addresses_ipv4;
static ip_subnet no_addresses_ipv6;

static ip_subnet all_addresses_ipv4;
static ip_subnet all_addresses_ipv6;

void init_ip_info(void)
{
	struct in_addr in_any = { htonl(INADDR_ANY), };
	any_address_ipv4 = address_from_in_addr(&in_any);

	struct in6_addr in6_any = IN6ADDR_ANY_INIT;
	any_address_ipv6 = address_from_in6_addr(&in6_any);

	struct in_addr in_loopback = { htonl(INADDR_LOOPBACK), };
	loopback_address_ipv4 = address_from_in_addr(&in_loopback);

	struct in6_addr in6_loopback = IN6ADDR_LOOPBACK_INIT;
	loopback_address_ipv6 = address_from_in6_addr(&in6_loopback);

	no_addresses_ipv4 = subnet(&any_address_ipv4, ipv4_info.mask_cnt, 0);
	no_addresses_ipv6 = subnet(&any_address_ipv6, ipv6_info.mask_cnt, 0);

	all_addresses_ipv4 = subnet(&any_address_ipv4, 0, 0);
	all_addresses_ipv6 = subnet(&any_address_ipv6, 0, 0);
}

const struct ip_info ipv4_info = {
	.af = AF_INET,
	.af_name = "AF_INET",
	.ip_version = 4,
	.ip_size = sizeof(struct in_addr),
	.sockaddr_size = sizeof(struct sockaddr_in),
	.mask_cnt = 32,
	.id_addr = ID_IPV4_ADDR,
	.id_subnet = ID_IPV4_ADDR_SUBNET,
	.id_range = ID_IPV4_ADDR_RANGE,
	/* */
	.any_address = &any_address_ipv4,
	.loopback_address = &loopback_address_ipv4,
	.no_addresses = &no_addresses_ipv4,
	.all_addresses = &all_addresses_ipv4,
};

const struct ip_info ipv6_info = {
	.af = AF_INET6,
	.af_name = "AF_INET6",
	.ip_version = 6,
	.ip_size = sizeof(struct in6_addr),
	.sockaddr_size = sizeof(struct sockaddr_in6),
	.mask_cnt = 128,
	.id_addr = ID_IPV6_ADDR,
	.id_subnet = ID_IPV6_ADDR_SUBNET,
	.id_range = ID_IPV6_ADDR_RANGE,
	/* */
	.any_address = &any_address_ipv6,
	.loopback_address = &loopback_address_ipv6,
	.no_addresses = &no_addresses_ipv6,
	.all_addresses = &all_addresses_ipv6,
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
