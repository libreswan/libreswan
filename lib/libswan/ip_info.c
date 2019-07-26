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

static ip_subnet ipv4_wildcard, ipv6_wildcard;
static ip_subnet ipv4_all, ipv6_all;

const struct ip_info ipv4_info = {
	.af = AF_INET,
	.af_name = "AF_INET",
	.version = 4,
	.ia_sz = sizeof(struct in_addr),
	.sa_sz = sizeof(struct sockaddr_in),
	.mask_cnt = 32,
	.id_addr = ID_IPV4_ADDR,
	.id_subnet = ID_IPV4_ADDR_SUBNET,
	.id_range = ID_IPV4_ADDR_RANGE,
	.none = &ipv4_wildcard,
	.all = &ipv4_all,
};

const struct ip_info ipv6_info = {
	.af = AF_INET6,
	.af_name = "AF_INET6",
	.version = 6,
	.ia_sz = sizeof(struct in6_addr),
	.sa_sz = sizeof(struct sockaddr_in6),
	.mask_cnt = 128,
	.id_addr = ID_IPV6_ADDR,
	.id_subnet = ID_IPV6_ADDR_SUBNET,
	.id_range = ID_IPV6_ADDR_RANGE,
	.none = &ipv6_wildcard,
	.all = &ipv6_all,
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

void init_ip_info(void)
{
	ip_address ipv4_any = address_any(AF_INET);
	ip_address ipv6_any = address_any(AF_INET6);

	happy(addrtosubnet(&ipv4_any, &ipv4_wildcard));
	happy(addrtosubnet(&ipv6_any, &ipv6_wildcard));

	happy(initsubnet(&ipv4_any, 0, '0', &ipv4_all));
	happy(initsubnet(&ipv6_any, 0, '0', &ipv6_all));
}
