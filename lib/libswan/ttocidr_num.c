/* ip cidr, for libreswan
 *
 * Copyright (C) 2019-2024 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2023 Brady Johnson <bradyjoh@redhat.com>
 * Copyright (C) 2021 Antony Antony <antony@phenome.org>
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

#include "passert.h"
#include "jambuf.h"
#include "lswlog.h"

#include "ip_cidr.h"
#include "ip_info.h"

err_t ttocidr_num(shunk_t src, const struct ip_info *afi, ip_cidr *cidr)
{
	*cidr = unset_cidr;
	err_t err;

	/* split CIDR into ADDRESS [ "/" MASK ]. */
	char slash = '\0';
	shunk_t address = shunk_token(&src, &slash, "/");
	shunk_t mask = src;

	/* parse ADDRESS */
	ip_address addr;
	err = ttoaddress_num(address, afi/*possibly NULL */, &addr);
	if (err != NULL) {
		return err;
	}

	/* Fix AFI, now that it is known */
	afi = address_info(addr);
	passert(afi != NULL);

	/* parse [ "/" MASK ] */

	uintmax_t prefix_len = afi->mask_cnt;
	if (slash == '/') {
		/* don't use bound - error is confusing */
		err = shunk_to_uintmax(mask, NULL, 0, &prefix_len);
		if (err != NULL) {
			/* not a number */
			return err;
		}
		if (prefix_len > (uintmax_t)afi->mask_cnt) {
			return "mask is too big";
		}
	}

	/* combine */
	*cidr = cidr_from_raw(HERE, afi, addr.bytes, prefix_len);
	return NULL;
}
