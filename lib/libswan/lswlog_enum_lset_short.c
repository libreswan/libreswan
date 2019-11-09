/*
 * logging, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "lswlog.h"

size_t lswlog_enum_lset_short(struct lswlog *buf, enum_names *en,
			      const char *separator, lset_t val)
{
	unsigned int e;

	/* if nothing gets filled in, default to "none" rather than "" */
	if (val == LEMPTY) {
		return lswlogs(buf, "none");
	}

	size_t size = 0;
	const char *sep = "";
	for (e = 0; val != 0; e++) {
		lset_t bit = LELEM(e);

		if (val & bit) {
			size += lswlogs(buf, sep);
			sep = separator;
			size += lswlog_enum_short(buf, en, e);
			val -= bit;
		}
	}
	return size;
}
