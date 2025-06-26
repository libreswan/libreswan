/* time objects and functions, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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

#include <time.h>	/* for clock_*() + clockid_t */
#include <errno.h>

#include "constants.h"	/* for memeq() which is clearly not a constant */
#include "passert.h"
#include "jambuf.h"
#include "lswlog.h"		/* for fatal_errno() */

#include "realtime.h"

const realtime_t realtime_epoch = REALTIME_EPOCH;

realtime_t realtime(time_t seconds)
{
	return (realtime_t) { .rt = from_seconds(seconds), };
}

realtime_t realtime_add(realtime_t t, deltatime_t d)
{
	realtime_t s;
	timeradd(&t.rt, &d.dt, &s.rt);
	return s;
}

realtime_t realtime_sub(realtime_t t, deltatime_t d)
{
	realtime_t s;
	timersub(&t.rt, &d.dt, &s.rt);
	return s;
}

bool is_realtime_epoch(realtime_t t)
{
	return !timerisset(&t.rt);
}

int realtime_sub_sign(realtime_t l, realtime_t r)
{
	/* sign(l - r) */
	return timeval_sub_sign(l.rt, r.rt);
}

deltatime_t realtime_diff(realtime_t a, realtime_t b)
{
	return deltatime_timevals_diff(a.rt, b.rt);
}

clockid_t realtime_clockid(void)
{
	return CLOCK_REALTIME;
}

realtime_t realnow(void)
{
	struct timespec ts;
	int e = clock_gettime(realtime_clockid(), &ts);
	if (e < 0) {
		/*
		 * This code assumes clock_gettime() always succeeds -
		 * if it were expected to fail then there'd either be
		 * a logger and/or a way to return the failure to the
		 * caller.
		 */
		fatal(PLUTO_EXIT_KERNEL_FAIL, &global_logger, errno,
		      "clock_gettime(%d,...) call in realnow() failed",
		      realtime_clockid());
	}
	realtime_t t = {
		.rt = {
			.tv_sec = ts.tv_sec,
			.tv_usec = ts.tv_nsec / 1000,
		},
	};
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

/*
 *  Display a date either in local or UTC time
 */
size_t jam_realtime(struct jambuf *buf, const realtime_t rtm, bool utc)
{
	static const char *months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	size_t s = 0;
	if (is_realtime_epoch(rtm)) {
		s += jam(buf, "--- -- --:--:--%s----", (utc) ? " UTC " : " ");
	} else {
		struct realtm t = (utc ? utc_realtime : local_realtime)(rtm);
		s += jam(buf, "%s %02d %02d:%02d:%02d%s%04d",
			 months[t.tm.tm_mon], t.tm.tm_mday, t.tm.tm_hour,
			 t.tm.tm_min, t.tm.tm_sec,
			 (utc) ? " UTC " : " ", t.tm.tm_year + 1900);
	}
	return s;
}

const char *str_realtime(realtime_t r, bool utc, realtime_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_realtime(&jambuf, r, utc);
	return buf->buf;
}
