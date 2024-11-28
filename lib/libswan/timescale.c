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
	[TIMESCALE_MICROSECONDS] = { "us", (uintmax_t)1, },
	[TIMESCALE_MILLISECONDS] = { "ms", (uintmax_t)1 * 1000, },
	[TIMESCALE_SECONDS]      = { "s",  (uintmax_t)1 * 1000 * 1000, },
	[TIMESCALE_MINUTES]      = { "m",  (uintmax_t)1 * 1000 * 1000 * secs_per_minute, },
	[TIMESCALE_HOURS]        = { "h",  (uintmax_t)1 * 1000 * 1000 * secs_per_hour, },
	[TIMESCALE_DAYS]         = { "d",  (uintmax_t)1 * 1000 * 1000 * secs_per_day, },
	[TIMESCALE_WEEKS]        = { "w",  (uintmax_t)1 * 1000 * 1000 * secs_per_day * 7, },
};

const struct scales timescales = {
	.base = 10,
	.scale = { ARRAY_REF(scales) },
};

const struct scale *ttotimescale(shunk_t cursor, enum timescale default_timescale)
{
	return ttoscale(cursor, &timescales, default_timescale);
}

const struct scale *timescale(enum timescale scale)
{
	passert(scale < elemsof(scales));
	return &scales[scale];
}
