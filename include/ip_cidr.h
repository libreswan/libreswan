/* ip cidr (prefix/host-id), for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#ifndef IP_CIDR_H
#define IP_CIDR_H

/*
 * NETWORK_PREFIX/HOST_IDENTIFIER
 *
 * Unlike ip_subnet, this allows a non-zero host_identifier.
 */

#include "ip_address.h"		/* for ip_bytes */

struct jambuf;

typedef struct {
	enum ip_version version;
	struct ip_bytes bytes;
	unsigned prefix_bits;
} ip_cidr;

extern const ip_cidr unset_cidr;

bool cidr_is_unset(const ip_cidr *cidr);		/* handles NULL */
const struct ip_info *cidr_type(const ip_cidr *cidr);	/* handles NULL */

ip_address cidr_address(const ip_cidr cidr);

/* convert CIDR address/mask; does not judge the result */
err_t numeric_to_cidr(shunk_t src, const struct ip_info *afi, ip_cidr *cidr);

/*
 * return why, if CDIR isn't useful.
 *
 * "specified"? wikipedia refers to ::/0 as "Default route (no
 * specific route)" and ::/128 as "Unspecified address". While these
 * addresses are valid, they don't specifically specify anything...
 */

err_t cidr_specified(const ip_cidr cidr);
bool cidr_is_specified(const ip_cidr cidr);

typedef struct {
	char buf[sizeof(address_buf) + 4/*/128*/];
} cidr_buf;

size_t jam_cidr(struct jambuf *buf, const ip_cidr *cidr);
const char *str_cidr(const ip_cidr *cidr, cidr_buf*buf);

#endif
