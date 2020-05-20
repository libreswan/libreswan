/*
 * comparisons
 *
 * Copyright (C) 2000  Henry Spencer.
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

#include <string.h>		/* for memcmp() */
#include "ip_address.h"
#include "ip_said.h"
#include "ip_subnet.h"
#include "ip_info.h"
#include "passert.h"

static bool samenbits(const ip_address *a, const ip_address *b, int n);

/*
 * addrcmp - compare two addresses
 * Caution, the order of the tests is subtle:  doing type test before
 * size test can yield cases where a<b, b<c, but a>c.
 */
int	/* like memcmp */
addrcmp(const ip_address *a, const ip_address *b)
{
	const struct ip_info *at = address_type(a);
	const struct ip_info *bt = address_type(b);
	if (at == NULL && bt == NULL) {
		/* XXX: see old code */
		return 0;
	} else if (at == NULL) {
		/* AF_UNSPEC<AF_*/
		return -1;
	} else if (bt == NULL) {
		/* AF<AF_UNSPEC*/
		return 1;
	} else if (at != bt) {
		return (at->af < bt->af) ? -1 : 1;
	} else {
		shunk_t as = address_as_shunk(a);
		shunk_t bs = address_as_shunk(b);
		passert(as.len == bs.len);
		int c = memcmp(as.ptr, bs.ptr, as.len);
		if (c != 0)
			return (c < 0) ? -1 : 1;
		return 0;
	}
}

/*
 * sameaddr - are two addresses the same?
 */
bool sameaddr(const ip_address *a, const ip_address *b)
{
	return addrcmp(a, b) == 0;
}

/*
 * samesubnet - are two subnets the same?
 */
bool samesubnet(const ip_subnet * a, const ip_subnet *b)
{
	return sameaddr(&a->addr, &b->addr) &&	/* also does type check */
		a->maskbits == b->maskbits;
}

/*
 * subnetishost - is a subnet in fact a single host?
 */
bool subnetishost(const ip_subnet *a)
{
	const struct ip_info *afi = subnet_type(a);
	return a->maskbits == afi->mask_cnt;
}

/*
 * addrinsubnet - is this address in this subnet?
 */
bool addrinsubnet(const ip_address *a, const ip_subnet *s)
{
	return address_type(a) == subnet_type(s) &&
		samenbits(a, &s->addr, s->maskbits);
}

/*
 * subnetinsubnet - is one subnet within another?
 */
bool subnetinsubnet(const ip_subnet *a, const ip_subnet *b)
{
	return addrinsubnet(&a->addr, b) &&
		a->maskbits >= b->maskbits;	/* a is not bigger than b */
}

/*
 * samenbits - do two addresses have the same first n bits?
 */
static bool samenbits(const ip_address *a, const ip_address *b, int nbits)
{
	const struct ip_info *at = address_type(a);
	const struct ip_info *bt = address_type(b);
	if (at == NULL || bt == NULL) {
		return false;
	}
	if (at != bt) {
		return false;
	}

	shunk_t as = address_as_shunk(a);
	const uint8_t *ap = as.ptr; /* cast const void * */
	passert(as.len > 0);
	int n = as.len;

	shunk_t bs = address_as_shunk(b);
	const uint8_t *bp = bs.ptr; /* cast const void * */
	passert(as.len == bs.len);

	if (nbits > (int)n * 8)
		return false;	/* "can't happen" */

	for (; nbits >= 8 && *ap == *bp; nbits -= 8, ap++, bp++)
		continue;

	return nbits < 8 &&
		(*ap ^ *bp) >> (8 - nbits) == 0x00;
}
