/* address range, for libreswan
 *
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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

#ifndef IP_RANGE_H
#define IP_RANGE_H

#include "err.h"
#include "ip_address.h"
#include "ip_subnet.h"

typedef struct {
	ip_address start;
	ip_address end;
	bool is_subnet; /* hint for jam_range */
} ip_range;

/* caller knows best */
ip_range range2(const ip_address *start, const ip_address *end);

ip_range range_from_subnet(const ip_subnet subnet);

err_t addresses_to_range(const ip_address start, const ip_address end,
			 ip_range *dst) MUST_USE_RESULT;

err_t range_to_subnet(const ip_range range, ip_subnet *subnet) MUST_USE_RESULT;

err_t ttorange(const char *src, const struct ip_info *afi, ip_range *dst) MUST_USE_RESULT;

/*
 * Formatting
 */

typedef struct {
	char buf[sizeof(address_buf) + 1/*"-"*/ + sizeof(address_buf)];
} range_buf;

size_t jam_range(struct jambuf *buf, const ip_range *range);
const char *str_range(const ip_range *range, range_buf *buf);

/*
 * Magic values.
 *
 * XXX: While the headers call the all-zero address "ANY" (INADDR_ANY,
 * IN6ADDR_ANY_INIT), the headers also refer to the IPv6 value as
 * unspecified (for instance IN6_IS_ADDR_UNSPECIFIED()) leaving the
 * term "unspecified" underspecified.
 *
 * Consequently an AF_UNSPEC address (i.e., uninitialized or unset),
 * is identified by *_unset().
 */

extern const ip_range unset_range;
bool range_is_unset(const ip_range *r);

const struct ip_info *range_type(const ip_range *r);

bool range_is_specified(const ip_range r);

bool range_eq(const ip_range l, const ip_range r);
bool address_in_range(const ip_address address, const ip_range range);
bool range_in(const ip_range inner, const ip_range outer);
bool range_overlap(const ip_range l, const ip_range r);

/*
 * Calculate the number of significant bits in the size of the range.
 * floor(log2(|high-low| + 1)).
 *
 * If RANGE is CIDR then this returns the number of HOST IDENTIFIER
 * bits, otherwize it returns something slightly higher.
 */

int range_host_bits(const ip_range range);
bool range_size(const ip_range r, uint32_t *size);

/*
 * operations
 */

ip_address range_start(const ip_range range); /* floor */
ip_address range_end(const ip_range range); /* ceiling */

#endif
