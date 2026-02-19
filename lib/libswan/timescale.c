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

#include "scale.h"

#include "lswcdefs.h"
#include "constants.h"		/* for secs_per_* */
#include "passert.h"

static const struct scale scales[] = {
	/* milliseconds, and microseconds are in-human */
	[TIMESCALE_MICROSECONDS] = { (uintmax_t)1,                                  "us", NULL, NULL, },
	[TIMESCALE_MILLISECONDS] = { (uintmax_t)1 * 1000,                           "ms", NULL, NULL, },
	[TIMESCALE_SECONDS]      = { (uintmax_t)1 * 1000 * 1000,                    "s", "second", "seconds", },
	[TIMESCALE_MINUTES]      = { (uintmax_t)1 * 1000 * 1000 * secs_per_minute,  "m", "minute", "minutes", },
	[TIMESCALE_HOURS]        = { (uintmax_t)1 * 1000 * 1000 * secs_per_hour,    "h", "hour", "hours", },
	[TIMESCALE_DAYS]         = { (uintmax_t)1 * 1000 * 1000 * secs_per_day,     "d", "day", "days", },
	[TIMESCALE_WEEKS]        = { (uintmax_t)1 * 1000 * 1000 * secs_per_day * 7, "w", "week", "weeks", },
};

const struct scales timescales = {
	.name = "duration",
	.default_scale = TIMESCALE_SECONDS,
	LIST_REF(scales),
};

const struct scale *ttotimescale(shunk_t cursor, enum timescale default_timescale)
{
	if (cursor.len == 0) {
		return &timescales.list[default_timescale];
	}
	return ttoscale(cursor, &timescales);
}

const struct scale *timescale(enum timescale scale)
{
	passert(scale < elemsof(scales));
	return &scales[scale];
}
