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

	const struct ip_info *afi = address_type(from);
	if (address_type(to) != afi) {
		return "mismatched address types";
	}

	/*
	 * Determine the prefix_bits (the CIDR network part) by
	 * matching leading bits of FROM and TO.  Trailing bits
	 * (subnet address) must be either all 0 (from) or 1 (to).
	 */
	int prefix_bits = bytes_prefix_bits(afi, from->bytes, to->bytes);
	if (prefix_bits < 0) {
		return "invalid subnet";
	}

	*dst = subnet_from_address_prefix_bits(from, prefix_bits);
	return NULL;
}
