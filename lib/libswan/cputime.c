/* thread/wall timing, for libreswan
 *
 * Copyright (C) 2019, 2025 Andrew Cagney <cagney@gnu.org>
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

#include "cputime.h"

#include "monotime.h"
#include "passert.h"

static struct timespec thread_clock(void)
{
	static const clockid_t clock_id = CLOCK_THREAD_CPUTIME_ID;
	struct timespec now;
	int e = clock_gettime(clock_id, &now);
	passert(e == 0);
	return now;
}

static struct timespec wall_clock(void)
{
	struct timespec now;
	/* use the same clockid as monotime */
	int e = clock_gettime(monotime_clockid(), &now);
	passert(e == 0);
	return now;
}

static double seconds_sub(struct timespec stop, const struct timespec start)
{
	/* compute seconds */
	double seconds = (stop.tv_sec - start.tv_sec);
	/* adjust for nanoseconds */
	seconds += (double) stop.tv_nsec / 1000 / 1000 / 1000;
	seconds -= (double) start.tv_nsec / 1000 / 1000 / 1000;
	return seconds;
}

struct cpu_usage cputime_sub(cputime_t l, cputime_t r)
{
	struct cpu_usage s = {
		.thread_seconds = seconds_sub(l.thread_clock, r.thread_clock),
		.wall_seconds = seconds_sub(l.wall_clock, r.wall_clock),
	};
	return s;
}

cputime_t cputime_start(void)
{
	cputime_t start = {
		.thread_clock = thread_clock(),
		.wall_clock = wall_clock(),
	};
	return start;
}

struct cpu_usage cputime_stop(const cputime_t start)
{
	cputime_t stop = cputime_start();
	return cputime_sub(stop, start);
}

size_t jam_cpu_usage(struct jambuf *buf, struct cpu_usage usage)
{
	return jam(buf, "spent %.3g (%.3g) milliseconds",
		   usage.thread_seconds * 1000,
		   usage.wall_seconds * 1000);
}
