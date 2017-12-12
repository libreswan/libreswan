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

#include "constants.h"
#include "realtime.h"

const realtime_t realtime_epoch = REALTIME_EPOCH;

realtime_t realtime(time_t time)
{
	return (realtime_t) { { time, 0, }, };
}

realtime_t realtimesum(realtime_t t, deltatime_t d)
{
	struct timeval dv = deltatimeval(d);
	realtime_t s;
	timeradd(&t.rt, &dv, &s.rt);
	return s;
}

bool is_realtime_epoch(realtime_t t)
{
	return !timerisset(&t.rt);
}

bool realbefore(realtime_t a, realtime_t b)
{
	return timercmp(&a.rt, &b.rt, <);
}

deltatime_t realtimediff(realtime_t a, realtime_t b)
{
	struct timeval d;
	timersub(&a.rt, &b.rt, &d);
	return deltatime_ms((intmax_t)d.tv_sec * 1000 + d.tv_usec / 1000);
}

realtime_t realnow(void)
{
	realtime_t t;
	gettimeofday(&t.rt, NULL);
	return t;
}

struct realtm local_realtime(realtime_t t)
{
	struct realtm tm;
	zero(&tm);
	localtime_r(&t.rt.tv_sec, &tm.tm);
	/* 1 000 000 microseconds to a second. */
	tm.microsec = t.rt.tv_usec;
	return tm;
}

struct realtm utc_realtime(realtime_t t)
{
	struct realtm tm;
	zero(&tm);
	gmtime_r(&t.rt.tv_sec, &tm.tm);
	/* 1 000 000 microseconds to a second. */
	tm.microsec = t.rt.tv_usec;
	return tm;
}
