/* monotonic time, for libreswan
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier. <hugh@mimosa.com>
 * Copyright (C) 2014  D. Hugh Redelmeier. <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <time.h>	/* for clock_*() + clockid_t */
#include <errno.h>

#include "constants.h"	/* for memeq() which is clearly not a constant */
#include "jambuf.h" 
#include "lswlog.h"		/* for fatal_errno() */

#include "monotime.h"

monotime_t monotime(intmax_t seconds)
{
	return (monotime_t) { .mt = from_seconds(seconds), };
}

const monotime_t monotime_epoch = MONOTIME_EPOCH;

bool is_monotime_epoch(monotime_t t)
{
	return memeq(&t, &monotime_epoch, sizeof(monotime_t));
}

clockid_t monotime_clockid(void)
{
#ifdef CLOCK_BOOTTIME
	return CLOCK_BOOTTIME;	/* best */
#else
	return CLOCK_MONOTONIC;	/* second best */
#endif
}

monotime_t mononow(void)
{
	struct timespec t;
	int e = clock_gettime(monotime_clockid(), &t);
	if (e < 0) {
		/*
		 * This code assumes clock_gettime() always succeeds -
		 * if it were expected to fail then there'd either be
		 * a logger and/or a way to return the failure to the
		 * caller.
		 */
		fatal_errno(PLUTO_EXIT_KERNEL_FAIL, &global_logger, errno,
			    "clock_gettime(%d,...) in mononow() failed",
			    monotime_clockid());
	}
	/* OK */
	return (monotime_t) {
		.mt = {
			.tv_sec = t.tv_sec,
			.tv_usec = t.tv_nsec / 1000,
		},
	};
}

intmax_t monosecs(monotime_t m)
{
	return m.mt.tv_sec;
}

monotime_t monotime_max(monotime_t l, monotime_t r)
{
	if (monotime_cmp(l, >, r)) {
		return l;
	} else {
		return r;
	}
}

monotime_t monotime_min(monotime_t l, monotime_t r)
{
	if (monotime_cmp(l, <, r)) {
		return l;
	} else {
		return r;
	}
}

monotime_t monotime_add(monotime_t t, deltatime_t d)
{
	monotime_t s = MONOTIME_EPOCH;
	timeradd(&t.mt, &d.dt, &s.mt);
	return s;
}

monotime_t monotime_sub(monotime_t t, deltatime_t d)
{
	monotime_t s = MONOTIME_EPOCH;
	timersub(&t.mt, &d.dt, &s.mt);
	return s;
}

int monotime_sub_sign(monotime_t l, monotime_t r)
{
	return timeval_sub_sign(l.mt, r.mt);
}

deltatime_t monotimediff(monotime_t a, monotime_t b)
{
	return deltatime_timevals_diff(a.mt, b.mt);
}

size_t jam_monotime(struct jambuf *buf, monotime_t m)
{
	/* convert it to time-since-epoch and log that */
	return jam_deltatime(buf, monotimediff(m, monotime_epoch));
}

const char *str_monotime(monotime_t m, monotime_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_monotime(&jambuf, m);
	return buf->buf;
}
