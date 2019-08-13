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

static bool samenbits(const ip_address *a, const ip_address *b, int n);

/*
 * addrcmp - compare two addresses
 * Caution, the order of the tests is subtle:  doing type test before
 * size test can yield cases where a<b, b<c, but a>c.
 */
int	/* like memcmp */
addrcmp(const ip_address *a, const ip_address *b)
{
	int at = addrtypeof(a);
	int bt = addrtypeof(b);

	if (at != bt) {
		return (at < bt) ? -1 : 1;
	} else {
		const unsigned char *ap;
		const unsigned char *bp;
		size_t as = addrbytesptr_read(a, &ap);
		size_t bs = addrbytesptr_read(b, &bp);

		size_t n = (as < bs) ? as : bs;	/* min(as, bs) */

		int c = memcmp(ap, bp, n);

		if (c != 0)	/* bytes differ */
			return (c < 0) ? -1 : 1;

		if (as != bs)	/* comparison incomplete:  lexical order */
			return (as < bs) ? -1 : 1;

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
	return a->maskbits == (int)addrlenof(&a->addr) * 8;
}

/*
 * samesaid - are two SA IDs the same?
 */
bool samesaid(const ip_said *a, const ip_said *b)
{
	return a->spi == b->spi &&	/* test first, most likely to be different */
		sameaddr(&a->dst, &b->dst) &&
		a->proto == b->proto;
}

/*
 * sameaddrtype - do two addresses have the same type?
 */
bool sameaddrtype(const ip_address *a, const ip_address *b)
{
	return addrtypeof(a) == addrtypeof(b);
}

/*
 * samesubnettype - do two subnets have the same type?
 */
bool samesubnettype(const ip_subnet *a, const ip_subnet *b)
{
	return sameaddrtype(&a->addr, &b->addr);
}

/*
 * addrinsubnet - is this address in this subnet?
 */
bool addrinsubnet(const ip_address *a, const ip_subnet *s)
{
	return address_type(a) != subnet_type(s) &&
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
	if (addrtypeof(a) != addrtypeof(b))
		return false;	/* arbitrary */

	const unsigned char *ap;
	int n = addrbytesptr_read(a, &ap);
	if (n == 0)
		return false;	/* arbitrary */

	const unsigned char *bp;
	(void) addrbytesptr_read(b, &bp);
	if (nbits > (int)n * 8)
		return false;	/* "can't happen" */

	for (; nbits >= 8 && *ap == *bp; nbits -= 8, ap++, bp++)
		continue;

	return nbits < 8 &&
		(*ap ^ *bp) >> (8 - nbits) == 0x00;
}
