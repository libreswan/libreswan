/* lset_t names for libreswan
 *
 * Copyright (C) 2017, Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "lset_names.h"
#include "lswlog.h"

void lset_names_check(const struct lset_names *names)
{
	const struct lelem_name *lelem;
	for (lelem = names->lelems;
	     lelem < names->lelems + names->roof;
	     lelem++) {
		unsigned bit = lelem - names->lelems;
		if (lelem->flag == NULL) {
			PASSERT_FAIL("bit %d .flag is NULL", bit);
		}
		if (lelem->name == NULL) {
			PASSERT_FAIL("bit %d .name is NULL", bit);
		}
		if (lelem->lelem != LELEM(bit)) {
			PASSERT_FAIL("bit %d (%s) .lelem is wrong",
				     bit, lelem->name);
		}
	}
	/* lelem points at [ROOF] */
	struct lelem_name sentinel = SENTINEL_LELEM_NAME;
	passert(memeq(&sentinel, lelem, sizeof(sentinel)));
}
