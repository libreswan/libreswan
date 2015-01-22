/*
 * minor utilities for subnet-mask manipulation
 * Copyright (C) 1998, 1999  Henry Spencer.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
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
   - goodmask - is this a good (^1*0*$) subnet mask?
 * You are not expected to understand this.  See Henry S. Warren Jr,
 * "Functions realizable with word-parallel logical and two's-complement
 * addition instructions", CACM 20.6 (June 1977), p.439.
 */
int                             /* predicate */
goodmask(mask)
struct in_addr mask;
{
	unsigned long x = ntohl(mask.s_addr);
	/* clear rightmost contiguous string of 1-bits */
#       define  CRCS1B(x)       ((((x) | ((x) - 1)) + 1) & (x))
#       define  TOPBIT          (1UL << 31)

	/* either zero, or has one string of 1-bits which is left-justified */
	if (x == 0 || (CRCS1B(x) == 0 && (x & TOPBIT)))
		return 1;

	return 0;
}

/*
   - masktobits - how many bits in this mask?
 * The algorithm is essentially a binary search, but highly optimized
 * for this particular task.
 */
int                             /* -1 means !goodmask() */
masktobits(mask)
struct in_addr mask;
{
	unsigned long m = ntohl(mask.s_addr);
	int masklen;

	if (!goodmask(mask))
		return -1;

	if (m & 0x00000001UL)
		return 32;

	masklen = 0;
	if (m & (0x0000ffffUL << 1)) {      /* <<1 for 1-origin numbering */
		masklen |= 0x10;
		m <<= 16;
	}
	if (m & (0x00ff0000UL << 1)) {
		masklen |= 0x08;
		m <<= 8;
	}
	if (m & (0x0f000000UL << 1)) {
		masklen |= 0x04;
		m <<= 4;
	}
	if (m & (0x30000000UL << 1)) {
		masklen |= 0x02;
		m <<= 2;
	}
	if (m & (0x40000000UL << 1))
		masklen |= 0x01;

	return masklen;
}

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

int                             /* -1 means !goodmask() */
mask6tobits(mask)
struct in6_addr *mask;
{
	int i;
	int bits = 0;

	for (i = 0; i < 4; i++) {
		if (mask->s6_addr32[i] == 0xffffffffUL) {
			bits += 32;
			continue;
		}
		if (!goodmask(*((struct in_addr *) &mask->s6_addr32[i])))
			return -1;

		bits += masktobits(*((struct in_addr *) &mask->s6_addr32[i]));
		break;
	}
	return bits;
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
