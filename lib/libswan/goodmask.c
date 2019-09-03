/*
 * minor utilities for subnet-mask manipulation
 * Copyright (C) 1998, 1999  Henry Spencer.
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
#include "libreswan.h"

#ifndef ABITS
#define ABITS   32      /* bits in an IPv4 address */
#endif

/* This file does not use sysdep.h, otherwise this should go into
 * ports/darwin/include/sysdep.h
 */
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

/*
   - bitstomask - return a mask with this many high bits on
 */
struct in_addr bitstomask(n)
int n;
{
	struct in_addr result;

	if (n > 0 && n <= ABITS)
		result.s_addr = htonl(~((1UL << (ABITS - n)) - 1));
	else if (n == 0)
		result.s_addr = 0;
	else
		result.s_addr = 0;      /* best error report we can do */
	return result;
}

/*
   - bitstomask6 - return a mask with this many high bits on
 */
struct in6_addr bitstomask6(n)
int n;
{
	struct in6_addr result;

	if (n > 0 && n <= 32) {
		result.s6_addr32[0] = htonl(~((1UL << (32 - n)) - 1));
		result.s6_addr32[1] = 0;
		result.s6_addr32[2] = 0;
		result.s6_addr32[3] = 0;
	} else if (n > 32 && n <= 64) {
		result.s6_addr32[0] = 0xffffffffUL;
		result.s6_addr32[1] = htonl(~((1UL << (64 - n)) - 1));
		result.s6_addr32[2] = 0;
		result.s6_addr32[3] = 0;
	} else if (n > 64 && n <= 96) {
		result.s6_addr32[0] = 0xffffffffUL;
		result.s6_addr32[1] = 0xffffffffUL;
		result.s6_addr32[2] = htonl(~((1UL << (96 - n)) - 1));
		result.s6_addr32[3] = 0;
	} else if (n > 96 && n <= 128) {
		result.s6_addr32[0] = 0xffffffff;
		result.s6_addr32[1] = 0xffffffff;
		result.s6_addr32[2] = 0xffffffff;
		result.s6_addr32[3] = htonl(~((1UL << (128 - n)) - 1));
	} else {
		result.s6_addr32[0] = 0;
		result.s6_addr32[0] = 0;
		result.s6_addr32[0] = 0;
		result.s6_addr32[0] = 0;
	}

	return result;
}
