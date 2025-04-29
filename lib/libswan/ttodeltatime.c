/* time conversion, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <stdio.h>

#include "diag.h"
#include "deltatime.h"
#include "timescale.h"
#include "passert.h"
#include "lswlog.h"

diag_t ttodeltatime(shunk_t t, deltatime_t *d, enum timescale default_timescale)
{
	*d = deltatime_zero;

	shunk_t cursor = t;

	/* parse:
	 *
	 *   [<DECIMAL>][<SCALE>]
	 *
	 * Probably allows messed up values such as "."
	 */

	/* [<DECIMAL>][.<FRACTION>] */
	uintmax_t decimal;
	uintmax_t numerator;
	uintmax_t denominator;
	err_t err = shunk_to_decimal(cursor, &cursor, &decimal,
				     &numerator, &denominator);

	if (err != NULL) {
		return diag("invalid duration \""PRI_SHUNK"\", %s",
			    pri_shunk(t), err);
	}

	/* [<SCALE>] */
	const struct scale *scale = ttotimescale(cursor, default_timescale);
	if (scale == NULL) {
		return diag("duration \""PRI_SHUNK"\" has an unrecognized multiplier \""PRI_SHUNK"\"",
			    pri_shunk(t), pri_shunk(cursor));
	}

	uintmax_t microseconds;
	err_t e = scale_decimal(scale, decimal, numerator, denominator, &microseconds);

	if (e != NULL) {
		return diag("invalid duration \""PRI_SHUNK"\", %s",
			    pri_shunk(t), e);
	}

	*d = deltatime_from_microseconds(microseconds);
	return NULL;
}
