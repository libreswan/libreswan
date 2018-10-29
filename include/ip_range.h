/*
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

typedef struct {
	ip_address start;
	ip_address end;
} ip_range;

extern err_t ttorange(const char *src, size_t srclen, int af, ip_range *dst,
		bool non_zero);
extern size_t rangetot(const ip_range *src, char format, char *dst, size_t dstlen);
#define RANGETOT_BUF     (ADDRTOT_BUF * 2 + 1)

/*
 * Calculate the number of significant bits in the size of the range.
 * floor(lg(|high-low| + 1))
 *
 * ??? this really should use ip_range rather than a pair of ip_address values
 */
int iprange_bits(ip_address low, ip_address high);

#endif
