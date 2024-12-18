/*
 * convert from text form of subnet specification to binary
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include <string.h>

#include "ip_subnet.h"
#include "ip_info.h" 	/* ipv6_info */
#include "lswlog.h"	/* for dbg() */
#include "ip_protocol.h"

#ifndef DEFAULTSUBNET
#define DEFAULTSUBNET "%default"
#endif

/*
 * ttosubnet - convert text "addr/mask" to address and mask
 * Mask can be integer bit count.
 */

err_t ttosubnet_num(shunk_t src, const struct ip_info *afi, /* could be NULL */
		    ip_subnet *dst, ip_address *nonzero_host)
{
	*dst = unset_subnet;
	*nonzero_host = unset_address;
	err_t oops;

	/*
	 * Match %default, can't work when AFI=NULL.
	 *
	 * you cannot use af==AF_UNSPEC and src=0/0,
	 * makes no sense as will it be AF_INET
	 */
	if (hunk_strcaseeq(src, DEFAULTSUBNET)) {
		if (afi == NULL) {
			return "unknown address family with " DEFAULTSUBNET " subnet not allowed.";
		}
		*dst = afi->subnet.all; /* 0.0.0.0/0 or ::/0 */
		return NULL;
	}

	/* split the input into ADDR [ "/" MASK ] */
	char slash = '\0';
	shunk_t addr = shunk_token(&src, &slash, "/");
	shunk_t mask = src;

	/* parse ADDR */
	ip_address address;
	oops = ttoaddress_num(addr, afi, &address);
	if (oops != NULL) {
		return oops;
	}

	if (afi == NULL) {
		afi = address_info(address);
	}
	passert(afi != NULL);

	/* parse [ "/" MASK ] */

	uintmax_t prefix_len = afi->mask_cnt;
	if (slash == '/') {
		/* eat entire MASK */
		oops = shunk_to_uintmax(mask, NULL, 10, &prefix_len);
		if (oops != NULL || prefix_len > afi->mask_cnt) {
			if (afi == &ipv4_info) {
				/*1.2.3.0/255.255.255.0?*/
				ip_address masktmp;
				oops = ttoaddress_num(mask, afi, &masktmp);
				if (oops != NULL) {
					return oops;
				}

				int i = masktocount(&masktmp);
				if (i < 0) {
					return "non-contiguous or otherwise erroneous mask";
				}
				prefix_len = i;
			} else {
				return "masks are not permitted for IPv6 addresses";
			}
		}
	}

	/* check host-part is zero */

	struct ip_bytes routing_prefix = ip_bytes_blit(afi, address.bytes,
						       &keep_routing_prefix,
						       &clear_host_identifier,
						       prefix_len);
	if (ip_bytes_cmp(afi->ip_version, routing_prefix,
			 afi->ip_version, address.bytes) != 0) {
		*nonzero_host = address;
	}

	*dst = subnet_from_raw(HERE, afi, routing_prefix, prefix_len);
	return NULL;
}
