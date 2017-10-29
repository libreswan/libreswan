/* time objects and functions, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#include <stdbool.h>

#include "lswtime.h"

/* delta time (interval) operations */

deltatime_t deltatime(time_t secs)
{
	deltatime_t d = { secs };
	return d;
}

unsigned long deltamillisecs(deltatime_t d)
{
	return d.delta_secs * 1000;
}

time_t deltasecs(deltatime_t d) {
	return d.delta_secs;
}

deltatime_t deltatimescale(int num, int denom, deltatime_t d)
{
	/* ??? should check for overflow */
	return deltatime(deltasecs(d) * num / denom);
}

bool deltaless(deltatime_t a, deltatime_t b)
{
	return deltasecs(a) < deltasecs(b);
}

bool deltaless_tv_tv(const struct timeval a, const struct timeval b)
{
	return a.tv_sec < b.tv_sec ||
		( a.tv_sec == b.tv_sec && a.tv_usec < b.tv_usec);
}

bool deltaless_tv_dt(const struct timeval a, const deltatime_t b)
{
	return a.tv_sec < deltasecs(b);
}

/* real time operations */

realtime_t realtimesum(realtime_t t, deltatime_t d)
{
	realtime_t s = { t.real_secs + d.delta_secs };
	return s;
}

bool is_realtime_epoch(realtime_t t)
{
	return t.real_secs == 0; /* by definition */
}

bool realbefore(realtime_t a, realtime_t b)
{
	return a.real_secs < b.real_secs;
}

deltatime_t realtimediff(realtime_t a, realtime_t b)
{
	deltatime_t d = { a.real_secs - b.real_secs };
	return d;
}

realtime_t realnow(void)
{
	realtime_t t;

	time(&t.real_secs);
	return t;
}

/* monotonic time operations */

monotime_t monotimesum(monotime_t t, deltatime_t d)
{
	monotime_t s = { t.mono_secs + d.delta_secs };
	return s;
}

bool monobefore(monotime_t a, monotime_t b)
{
	return a.mono_secs < b.mono_secs;
}

deltatime_t monotimediff(monotime_t a, monotime_t b)
{
	deltatime_t d = { a.mono_secs - b.mono_secs };

	return d;
}
