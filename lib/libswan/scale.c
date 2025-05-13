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

err_t tto_mixed_decimal(shunk_t input, shunk_t *cursor, struct mixed_decimal *number)
{
	zero(number);

	/* [<DECIMAL>] */
	bool have_decimal = false;
	if (is_digit(input)) {
		err_t err = shunk_to_uintmax(input, &input, 10/*base*/, &number->decimal);
		if (err != NULL) {
			return err;
		}
		have_decimal = true;
	}

	/* [.<FRACTION>] */
	if (is_char(input, '.')) {
		/* drop '.' */
		input = hunk_slice(input, 1, input.len);
		/* need to handle .01 */
		shunk_t tmp = input;
		/* reject ".???", allow "0." and ".0" */
		err_t err = shunk_to_uintmax(input, &input, 10/*base*/, &number->numerator);
		if (err != NULL && !have_decimal) {
			return "invalid decimal fraction";
		}
		number->denominator = 1;
		for (ptrdiff_t s = 0; s < input.ptr - tmp.ptr; s++) {
			number->denominator *= 10;
		}
	} else if (!have_decimal) {
		return "invalid decimal";
	}

	/* no cursor means no trailing input */
	if (cursor == NULL) {
		if (input.len > 0) {
			return "unexpected input at end";
		}
		return NULL;
	}

	*cursor = input;
	return NULL;
}

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

size_t jam_mixed_decimal(struct jambuf *buf, struct mixed_decimal number)
{
	size_t s = 0;
	const unsigned base = 10;

	s += jam(buf, "%ju", number.decimal);

	if (number.numerator == 0) {
		return s;
	}

	if (number.numerator >= number.denominator) {
		/* should not be called */
		s += jam(buf, ".%ju/%ju", number.numerator, number.denominator);
		return s;
	}

	/* strip trailing zeros */
	while (number.numerator % base == 0 &&
	       number.denominator % base == 0) {
		number.numerator /= base;
		number.denominator /= base;
	}

	/* determine precision */
	unsigned precision = 0;
	while (number.denominator % base == 0) {
		number.denominator /= base;
		precision += 1;
	}

	s += jam(buf, ".%0*ju", precision, number.numerator);
	return s;
}

err_t scale_mixed_decimal(const struct scale *scale,
			  struct mixed_decimal number,
			  uintmax_t *value)
{
	ldbgf(DBG_TMI, &global_logger,
	      "%s() decimal=%ju numerator=%ju denominator=%ju "PRI_SCALE"\n",
	      __func__, number.decimal, number.numerator, number.denominator,
	      pri_scale(scale));

	/*
	 * Check that scaling NUMBER.DECIMAL doesn't overflow.
	 */

	if (UINTMAX_MAX / scale->multiplier < number.decimal) {
		return "overflow";
	}

	*value = number.decimal * scale->multiplier;
	if (number.numerator > 0 && number.denominator > 0) {
		if (number.denominator > scale->multiplier) {
			return "underflow";
		}
		/* fails on really small fractions? */
		(*value) += (number.numerator * (scale->multiplier / number.denominator));
	}

	return NULL;
}
