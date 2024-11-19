/* ttobinary(), for libreswan
 *
 * Copyright (C) 2022 Antony Antony
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

#include <limits.h>

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for strncaseeq() */
#include "enum_names.h"

#include "binary-iec-60027-2.h"
#include "binaryscale-iec-60027-2.h"
#include "passert.h"
#include "lswalloc.h"
#include "ip_protocol.h"
#include "ip_encap.h"
#include "jambuf.h"

diag_t ttobinary(const char *t, uint64_t *r, bool prefix_B)
{
	*r = 0;
	shunk_t cursor = shunk1(t);
	const char *suffix = (prefix_B ? " Bytes" : "");

	uint64_t decimal, numerator, denominator;
	err_t err = shunk_to_decimal(cursor, &cursor, &decimal,
				     &numerator, &denominator);
	if (err != NULL) {
		return diag("bad binary%s value \"%s\": %s",
			    suffix,  t, err);
	}

	const struct binaryscale *scale = prefix_B ?
		ttobinarybytesscale(cursor) :
		ttobinaryscale(cursor);

	if (scale == NULL) {
		return diag("unrecognized binary%s multiplier \""PRI_SHUNK"\"",
			    suffix, pri_shunk(cursor));
	}

	if (UINTMAX_MAX / scale->b < decimal) {
		return diag("binary%s value \"%s\" overflows", suffix, t);
	}

	uintmax_t b = decimal * scale->b;

	if (numerator > 0 && denominator > 0) {
		if (denominator > scale->b) {
			return diag("binary%s value \"%s\" has sub-byte resolution", suffix, t);
		}
		/* fails on really small fractions? */
		b += (numerator * (scale->b / denominator));
	}

	*r = b;
	return NULL;
}
