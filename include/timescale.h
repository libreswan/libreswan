/* scale time, for libreswan
 *
 * Copyright (C) 2022  Andrew Cagney
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

#ifndef TIMESCALE_H
#define TIMESCALE_H    /* seen it, no need to see it again */

#include <stdint.h>	/* for uintmax_t */

#include "shunk.h"

struct timescale {
	const char *suffix;
	uintmax_t us;
};

extern const struct timescale timescale_microseconds;
extern const struct timescale timescale_milliseconds;
extern const struct timescale timescale_seconds;
extern const struct timescale timescale_minutes;
extern const struct timescale timescale_hours;
extern const struct timescale timescale_days;
extern const struct timescale timescale_weeks;

#define PRI_TIMESCALE "1%s(%juus)"
#define pri_timescale(TS) (TS).suffix, (TS).us

const struct timescale *ttotimescale(shunk_t s, const struct timescale *default_scale);

#endif
