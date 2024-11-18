/* time scale, for libreswan
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

#include "timescale.h"

#include "lswcdefs.h"
#include "constants.h"		/* for secs_per_* */

const struct timescale timescale_microseconds = { "us", .us = (uintmax_t)1, };
const struct timescale timescale_milliseconds = { "ms", .us = (uintmax_t)1 * 1000, };
const struct timescale timescale_seconds =      { "s",  .us = (uintmax_t)1 * 1000 * 1000, };
const struct timescale timescale_minutes =      { "m",  .us = (uintmax_t)1 * 1000 * 1000 * secs_per_minute, };
const struct timescale timescale_hours =        { "h",  .us = (uintmax_t)1 * 1000 * 1000 * secs_per_hour, };
const struct timescale timescale_days =         { "d",  .us = (uintmax_t)1 * 1000 * 1000 * secs_per_day, };
const struct timescale timescale_weeks =        { "w",  .us = (uintmax_t)1 * 1000 * 1000 * secs_per_day * 7, };

static const struct timescale *timescales[] = {
	&timescale_microseconds,
	&timescale_milliseconds,
	&timescale_seconds,
	&timescale_minutes,
	&timescale_hours,
	&timescale_days,
	&timescale_weeks,
};

const struct timescale *ttotimescale(shunk_t cursor, const struct timescale *default_scale)
{
	if (cursor.len == 0) {
		/* default scaling */
		return default_scale;
	}

	FOR_EACH_ELEMENT(scale, timescales) {
		if (hunk_strcaseeq(cursor, (*scale)->suffix)) {
			return *scale;
		}
	}

	return NULL;
}
