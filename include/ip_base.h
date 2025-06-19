/* ip base type, for libreswan
 *
 * Copyright (C) 2025  Andrew Cagney
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

#ifndef IP_BASE_H
#define IP_BASE_H

#include <stdbool.h>
#include <stddef.h>

/* base class */

#include "ip_version.h"

struct ip_info;
struct jambuf;

struct ip_base {
	bool is_set;
#define ip_is_set(IP) ((IP) != NULL && (IP)->ip.is_set)
#define ip_is_unset(IP) ((IP) == NULL || !(IP)->ip.is_set)

	enum ip_version version:8; /* 0, IPv4(4), IPv6(6) */
};

/*
 * Handle invalid IPs (NULL, unset, bogus AFI).  Returns >0 (the bytes
 * written) when the IP isn't valid.  Sets AFI when IP is valid
 */

#define jam_invalid_ip(BUF, WHAT, IP, AFI)				\
	jam_ip_invalid(BUF, WHAT, ((IP) == NULL ? NULL : &(IP)->ip), AFI)

size_t jam_ip_invalid(struct jambuf *buf, const char *what,
		      const struct ip_base *ip, const struct ip_info **afi);

#endif
