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
#include "af_info.h"
#include "libreswan/passert.h"

static ip_address ipv4_any, ipv6_any;
static ip_subnet ipv4_wildcard, ipv6_wildcard;
static ip_subnet ipv4_all, ipv6_all;

const struct af_info af_inet4_info = {
	AF_INET,
	"AF_INET",
	sizeof(struct in_addr),
	sizeof(struct sockaddr_in),
	32,
	ID_IPV4_ADDR, ID_IPV4_ADDR_SUBNET, ID_IPV4_ADDR_RANGE,
	&ipv4_any, &ipv4_wildcard, &ipv4_all,
};

const struct af_info af_inet6_info = {
	AF_INET6,
	"AF_INET6",
	sizeof(struct in6_addr),
	sizeof(struct sockaddr_in6),
	128,
	ID_IPV6_ADDR, ID_IPV6_ADDR_SUBNET, ID_IPV6_ADDR_RANGE,
	&ipv6_any, &ipv6_wildcard, &ipv6_all,
};

const struct af_info *aftoinfo(int af)
{
	switch (af) {
	case AF_INET:
		return &af_inet4_info;

	case AF_INET6:
		return &af_inet6_info;

	default:
		return NULL;
	}
}

void init_af_info(void)
{
	happy(anyaddr(AF_INET, &ipv4_any));
	happy(anyaddr(AF_INET6, &ipv6_any));

	happy(addrtosubnet(&ipv4_any, &ipv4_wildcard));
	happy(addrtosubnet(&ipv6_any, &ipv6_wildcard));

	happy(initsubnet(&ipv4_any, 0, '0', &ipv4_all));
	happy(initsubnet(&ipv6_any, 0, '0', &ipv6_all));
}
