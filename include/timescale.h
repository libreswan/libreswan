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

#include "shunk.h"
#include "scale.h"

enum timescale {
	TIMESCALE_MICROSECONDS,
	TIMESCALE_MILLISECONDS,
	TIMESCALE_SECONDS,
	TIMESCALE_MINUTES,
	TIMESCALE_HOURS,
	TIMESCALE_DAYS,
	TIMESCALE_WEEKS,
};

const struct scale *timescale(enum timescale);

#define PRI_TIMESCALE "1%s(%juus)"
#define pri_timescale(TS) timescale(TS)->suffix, timescale(TS)->multiplier

const struct scale *ttotimescale(shunk_t s, enum timescale default_scale);

#endif
