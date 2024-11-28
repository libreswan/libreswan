/* scales, for libreswan
 *
 * Copyright (C) 2022-2024 Andrew Cagney <cagney@gnu.org>
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

#include <string.h>

#include "scale.h"
#include "lswcdefs.h"
#include "jambuf.h"
#include "lswlog.h"

const struct scale *ttoscale(shunk_t cursor, const struct scales *scales,
			     unsigned default_scale)
{
	if (cursor.len == 0) {
		/* default scaling */
		return &scales->scale.list[default_scale];
	}

	FOR_EACH_ITEM(scale, &scales->scale) {
		if (hunk_strcaseeq(cursor, scale->suffix)) {
			return scale;
		}
	}

	return NULL;
}

/*
 * This does not work for things like 30/60 seconds
 */

size_t jam_decimal(struct jambuf *buf, uintmax_t decimal,
		   uintmax_t numerator, uintmax_t denominator)
{
	size_t s = 0;
	const unsigned base = 10;

	s += jam(buf, "%ju", decimal);

	if (numerator == 0) {
		return s;
	}

	if (numerator >= denominator) {
		/* should not be called */
		s += jam(buf, ".%ju/%ju", numerator, denominator);
		return s;
	}

	/* strip trailing zeros */
	while (numerator % base == 0 &&
	       denominator % base == 0) {
		numerator /= base;
		denominator /= base;
	}

	/* determine precision */
	unsigned precision = 0;
	while (denominator % base == 0) {
		denominator /= base;
		precision += 1;
	}

	s += jam(buf, ".%0*ju", precision, numerator);
	return s;
}

err_t scale_decimal(const struct scale *scale, uintmax_t decimal,
		    uintmax_t numerator, uintmax_t denominator,
		    uintmax_t *value)
{
	ldbgf(DBG_TMI, &global_logger,
	      "%s() decimal=%ju numerator=%ju denominator=%ju "PRI_SCALE"\n",
	      __func__, decimal, numerator, denominator, pri_scale(scale));

	/*
	 * Check that scaling DECIMAL doesn't overflow.
	 */

	if (UINTMAX_MAX / scale->multiplier < decimal) {
		return "overflow";
	}

	*value = decimal * scale->multiplier;
	if (numerator > 0 && denominator > 0) {
		if (denominator > scale->multiplier) {
			return "underflow";
		}
		/* fails on really small fractions? */
		(*value) += (numerator * (scale->multiplier / denominator));
	}

	return NULL;
}
