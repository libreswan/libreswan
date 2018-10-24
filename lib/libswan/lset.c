/* lset_t routines, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include "lset.h"

#include "lswlog.h"	/* for passert() */

/*
 * NOT RE-ENTRANT!
 */
const char *bitnamesof(const char *const table[], lset_t val)
{
	static char bitnamesbuf[8192]; /* I hope that it is big enough! */

	return bitnamesofb(table, val, bitnamesbuf, sizeof(bitnamesbuf));
}

/* test a set by seeing if all bits have names */
bool testset(const char *const table[], lset_t val)
{
	lset_t bit;
	const char *const *tp;

	for (tp = table, bit = 01; val != 0; bit <<= 1, tp++) {
		const char *n = *tp;

		if (n == NULL || ((val & bit) && *n == '\0'))
			return false;

		val &= ~bit;
	}
	return true;
}

/*
 * construct a string to name the bits on in a set
 *
 * Result of bitnamesof may be in STATIC buffer -- NOT RE-ENTRANT!
 * Note: prettypolicy depends on internal details of bitnamesofb.
 * binamesofb is re-entrant since the caller provides the buffer.
 */
const char *bitnamesofb(const char *const table[], lset_t val,
			char *b, size_t blen)
{
	char *const roof = b + blen;
	char *p = b;
	lset_t bit;
	const char *const *tp;

	passert(blen != 0); /* need room for NUL */

	/* if nothing gets filled in, default to "none" rather than "" */
	(void) jam_str(b, blen, "none");

	for (tp = table, bit = 01; val != 0; bit <<= 1) {
		if (val & bit) {
			const char *n = *tp;

			if (p != b)
				p = jam_str(p, (size_t)(roof - p), "+");

			if (n == NULL || *n == '\0') {
				/*
				 * No name for this bit, so use hex.
				 * if snprintf returns a different value from
				 * strlen, truncation happened
				 */
				(void)snprintf(p, (size_t)(roof - p),
					"0x%" PRIxLSET,
					bit);
				p += strlen(p);
			} else {
				p = jam_str(p, (size_t)(roof - p), n);
			}
			val -= bit;
		}
		/*
		 * Move on in the table, but not past end.
		 * This is a bit of a trick: while we are at stuck the end,
		 * the loop will print out the remaining bits in hex.
		 */
		if (*tp != NULL)
			tp++;
	}
	return b;
}
