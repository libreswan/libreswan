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

#include "shunk.h"

struct jambuf;

struct scale {
	const char *suffix;
	uintmax_t multiplier;
};

/* for debugging */
#define PRI_SCALE "1%s(%juu)"
#define pri_scale(TS) (TS)->suffix, (TS)->multiplier

struct scales {
	uintmax_t base;
	struct {
		const struct scale *list;
		unsigned len;
	} scale;
};

const struct scale *ttoscale(shunk_t cursor, const struct scales *scales,
			     unsigned default_scale);

err_t scale_decimal(const struct scale *scale, uintmax_t decimal,
		    uintmax_t numerator, uintmax_t denominator,
		    uintmax_t *value);

size_t jam_decimal(struct jambuf *buf, uintmax_t decimal, uintmax_t numerator, uintmax_t denominator);

#endif
