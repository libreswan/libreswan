/*
 * express an address range as a subnet (if possible)
 *
 * Copyright (C) 2000, 2002  Henry Spencer.
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public
 * License for more details.
 */

#include "ip_subnet.h"
#include "passert.h"
#include "ip_info.h" 	/* ipv6_info */
#include "lswlog.h"	/* for dbg() */

/*
 * rangetosubnet - turn an address range into a subnet, if possible
 *
 * A range which is a valid subnet will have a network part which is the
 * same in the from value and the to value, followed by a host part which
 * is all 0 in the from value and all 1 in the to value.
 *
 * ??? this really should use ip_range rather than a pair of ip_address values
 */
err_t rangetosubnet(const ip_address *from, const ip_address *to, ip_subnet *dst)
{
	if (address_is_unset(from)) {
		/* XXX: should never happen? */
		return "FROM address unset";
	}

	if (address_is_unset(to)) {
		/* XXX: should never happen? */
		return "TO address unset";
	}

	if (address_type(from) != address_type(to)) {
		return "mismatched address types";
	}

	shunk_t fs = address_as_shunk(from);
	shunk_t ts = address_as_shunk(to);

	passert(fs.len > 0);
	passert(ts.len > 0);
	const uint8_t *f = fs.ptr; /* cast cast void * */;
	const uint8_t *t = ts.ptr; /* cast const void * */;

	passert(fs.len == ts.len);
	size_t n = fs.len;
	size_t i = 0;

	/*
	 * Determine the maskbits (the CIDR network part) by matching
	 * leading bits of FROM and TO.  Trailing bits (subnet address)
	 * must be either all 0 (from) or 1 (to).
	 */
	unsigned maskbits = 0;
	for (; i < n && f[i] == t[i]; i++) {
		maskbits += 8;
	}
	if (i < n && !(f[i] == 0x00 && t[i] == 0xff)) {	/* mid-byte bdry. */
		uint8_t fb = f[i];
		uint8_t tb = t[i];
		i++;
		uint8_t m = 0x80;
		/*
		 * clear each FB bit, and set each TB as it is matched
		 * so that, at the end FB==0x00 and TB=0xFF
		 */
		while ((fb & m) == (tb & m)) {
			fb &= ~m;
			tb |= m;
			m >>= 1;
			maskbits++;
		}
		if (fb != 0x00 || tb != 0xff) {
			return "not a valid subnet";
		}
	}
	for (; i < n; i++) {
		if (f[i] != 0x00 || t[i] != 0xff) {
			return "invalid subnet";
		}
	}

	*dst = subnet_from_address_maskbits(from, maskbits);
	return NULL;
}
