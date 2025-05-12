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

/*
 * addrcmp - compare two addresses
 * Caution, the order of the tests is subtle:  doing type test before
 * size test can yield cases where a<b, b<c, but a>c.
 *
 * computes "l-r"
 */
int	/* like memcmp */
addrcmp(const ip_address *l, const ip_address *r)
{
	if (address_is_unset(l) && address_is_unset(r)) {
		/* unset addresses equal */
		return 0;
	}
	if (address_is_unset(l)) {
		return -1;
	}
	if (address_is_unset(r)) {
		return 1;
	}

	return ip_bytes_cmp(l->ip_version, l->bytes,
			    r->ip_version, r->bytes);
}

/*
 * sameaddr - are two addresses the same?
 */
bool sameaddr(const ip_address *a, const ip_address *b)
{
	return addrcmp(a, b) == 0;
}
