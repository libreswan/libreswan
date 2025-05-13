/* scale, for libreswan
 *
 * Copyright (C) 2024  Andrew Cagney
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

#ifndef SCALE_H
#define SCALE_H

#include <stdint.h>	/* for uintmax_t */

#include "diag.h"
#include "shunk.h"

struct jambuf;

/*
 * Mixed number conversion.
 *
 * Parse DECIMAL.FRACTION into DECIMAL+NUMERATOR/DENOMINATOR where
 * DENOMINATOR is a multiple of 10.
 *
 * If CURSOR is NULL, having text following the numeric value is
 * considered an error (strtoul() silently ignores trailing junk when
 * END=NULL).
 *
 * If CURSOR is non-NULL, it is set to the text following the numeric
 * value.
 * For instance 3.45 breaks down into:
 *
 *    decimal(3) + numerator(45)/denominator(100)
 *
 * See wikipedia.
 */

struct mixed_decimal {
	uintmax_t decimal; /* wikipedia calls it WHOLE */
	uintmax_t numerator;
	uintmax_t denominator;
};

err_t tto_mixed_decimal(shunk_t input, shunk_t *cursor,
		       struct mixed_decimal *number);

size_t jam_mixed_decimal(struct jambuf *buf, struct mixed_decimal number);

/*
 * Conversion to/from <number><scale>.
 */

struct scale {
	const char *suffix;
	uintmax_t multiplier;
};

/* for debugging */
#define PRI_SCALE "1%s(%juu)"
#define pri_scale(TS) (TS)->suffix, (TS)->multiplier

struct scales {
	uintmax_t base;
	const char *name;
	unsigned default_scale;
	struct {
		const struct scale *list;
		unsigned len;
	} scale;
};

const struct scale *ttoscale(shunk_t cursor,
			     const struct scales *scales,
			     unsigned default_scale);

err_t scale_mixed_decimal(const struct scale *scale,
			 struct mixed_decimal number,
			 uintmax_t *value);

diag_t tto_scaled_uintmax(shunk_t cursor, uintmax_t *value, const struct scales *scales);

#endif
