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

size_t lswlog_lset_flags(struct lswlog *buf,
			 const struct lset_names *lset_names,
			 lset_t lset)
{
	if (lset == LEMPTY) {
		return lswlogs(buf, "none");
	}
	/*
	 * Similar to bitnames(), handle possibility of elements with
	 * no names, but unlike bitnames() print the bit number, not
	 * its hex mask.
	 */
	size_t size = 0;
	const char *sep = "";
	unsigned bit = 0;
	do {
		if (lset & LELEM(bit)) {
			size += lswlogs(buf, sep);
			sep = "+";
			if (bit < lset_names->roof) {
				const char *name = strip_prefix(lset_names->lelems[bit].flag,
								lset_names->strip);
				size += lswlogs(buf, name);
			} else {
				size += lswlogf(buf, "%u", bit);
			}
			lset &= ~LELEM(bit);
		}
		bit++;
	} while (lset != LEMPTY);
	return size;
}
