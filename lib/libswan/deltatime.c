/* time objects and functions, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include <inttypes.h>		/* for imaxabs() */
#include <limits.h>		/* for UINT_MAX */

#include "deltatime.h"
#include "timescale.h"
#include "lswlog.h"

const deltatime_t deltatime_zero = { .is_set = true, };
const deltatime_t one_day = DELTATIME_INIT(secs_per_day);
const deltatime_t one_hour = DELTATIME_INIT(secs_per_hour);
const deltatime_t one_minute = DELTATIME_INIT(secs_per_minute);
const deltatime_t one_second = DELTATIME_INIT(1);

/*
 * Rather than deal with the 'bias' in a -ve timeval, this code
 * converts everything into +ve timevals.
 */

static struct timeval negate_timeval(struct timeval tv)
{
	struct timeval zero = {0};
	struct timeval res;
	timersub(&zero, &tv, &res);
	return res;
}

deltatime_t deltatime(time_t seconds)
{
	return (deltatime_t) {
		.dt = from_seconds(seconds),
		.is_set = true,
	};
}

deltatime_t deltatime_from_milliseconds(intmax_t ms)
{
	return (deltatime_t) {
		.dt = from_milliseconds(ms),
		.is_set = true,
	};
}

deltatime_t deltatime_from_microseconds(intmax_t us)
{
	return (deltatime_t) {
		.dt = from_microseconds(us),
		.is_set = true,
	};
}

deltatime_t deltatime_timevals_diff(struct timeval a, struct timeval b)
{
	struct timeval res;
	timersub(&a, &b, &res);
	return deltatime_from_timeval(res);
}

int timeval_sub_sign(struct timeval l, struct timeval r)
{
	/* sign(l - r) */
	if (timercmp(&l, &r, <)) {
		return -1;
	}

	if (timercmp(&l, &r, >)) {
		return 1;
	}

	return 0;
}

int deltatime_sub_sign(deltatime_t l, deltatime_t r)
{
	return timeval_sub_sign(l.dt, r.dt);
}

deltatime_t deltatime_max(deltatime_t l, deltatime_t r)
{
	if (deltatime_cmp(l, >, r)) {
		return l;
	} else {
		return r;
	}
}

deltatime_t deltatime_min(deltatime_t l, deltatime_t r)
{
	if (deltatime_cmp(l, <, r)) {
		return l;
	} else {
		return r;
	}
}

deltatime_t deltatime_add(deltatime_t a, deltatime_t b)
{
	struct timeval res;
	timeradd(&a.dt, &b.dt, &res);
	return deltatime_from_timeval(res);
}

deltatime_t deltatime_sub(deltatime_t a, deltatime_t b)
{
	struct timeval res;
	timersub(&a.dt, &b.dt, &res);
	return deltatime_from_timeval(res);
}

deltatime_t deltatime_mulu(deltatime_t a, unsigned scalar)
{
	return deltatime_from_milliseconds(milliseconds_from_deltatime(a) * scalar);
}

deltatime_t deltatime_divu(deltatime_t a, unsigned scalar)
{
	return deltatime_from_milliseconds(milliseconds_from_deltatime(a) / scalar);
}

intmax_t microseconds_from_deltatime(deltatime_t d)
{
	return microseconds_from(d.dt);
}

intmax_t milliseconds_from_deltatime(deltatime_t d)
{
	return milliseconds_from(d.dt);
}

time_t seconds_from_deltatime(deltatime_t d)
{
	/* XXX: ignore .tv_usec's bias, don't round */
	return seconds_from(d.dt);
}

deltatime_t deltatime_scale(deltatime_t d, int num, int denom)
{
	/* ??? should check for overflow */
	return deltatime((deltasecs(d) * num) / denom);
}

struct timeval timeval_from_deltatime(deltatime_t d)
{
	return d.dt;
}

deltatime_t deltatime_from_timeval(struct timeval t)
{
	deltatime_t d = { .dt = t, .is_set = true, };
	return d;
}

/*
 * Try to be smart by only printing the precision necessary.  For
 * instance 1, 0.5, ...
 */

size_t jam_deltatime(struct jambuf *buf, deltatime_t d)
{
	size_t s = 0;
	if (d.dt.tv_sec < 0) {
		s += jam(buf, "-");
		d.dt = negate_timeval(d.dt);
	}
	jam_decimal(buf, d.dt.tv_sec, d.dt.tv_usec, 1000000/*us*/);
	return s;
}

const char *str_deltatime(deltatime_t d, deltatime_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_deltatime(&buf, d);
	return out->buf;
}

struct timeval from_seconds(time_t seconds)
{
	struct timeval tv = {
		.tv_sec = seconds,
	};
	return tv;
}

struct timeval from_milliseconds(intmax_t ms)
{
	/*
	 * C99 defines '%' thus:
	 *
	 * [...] the result of the % operator is the remainder. [...]
	 * If the quotient a/b is representable, the expression (a/b)*b
	 * + a%b shall equal a.
	 */
	intmax_t ams = imaxabs(ms);
	struct timeval tv = {
		.tv_sec = ams / 1000,
		.tv_usec = ams % 1000 * 1000,
	};
	if (ms < 0) {
		tv = negate_timeval(tv);
	}
	return tv;
}

struct timeval from_microseconds(intmax_t us)
{
	intmax_t ams = imaxabs(us);
	struct timeval tv = {
		.tv_sec = ams / 1000 / 1000,
		.tv_usec = ams % 1000000,
	};
	if (us < 0) {
		tv = negate_timeval(tv);
	}
	return tv;
}

time_t seconds_from(struct timeval v)
{
	return v.tv_sec;
}

intmax_t milliseconds_from(struct timeval v)
{
	return ((intmax_t) v.tv_sec) * 1000 + v.tv_usec / 1000;
}

intmax_t microseconds_from(struct timeval v)
{
	return ((intmax_t) v.tv_sec) * 1000 * 1000 + v.tv_usec;
}
