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

#include "deltatime.h"
#include "lswlog.h"

const deltatime_t deltatime_zero;

/*
 * Rather than deal with the 'bias' in a -ve timeval, this code
 * convers everything into +ve timevals.
 */

static struct timeval negate_timeval(struct timeval tv)
{
	struct timeval zero = {0};
	struct timeval res;
	timersub(&zero, &tv, &res);
	return res;
}

deltatime_t deltatime(time_t secs)
{
	return (deltatime_t) DELTATIME_INIT(secs);
}

struct timeval timeval_ms(intmax_t ms)
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

deltatime_t deltatime_ms(intmax_t milliseconds)
{
	return (deltatime_t) { .dt = timeval_ms(milliseconds), };
}

deltatime_t deltatime_timevals_diff(struct timeval a, struct timeval b)
{
	deltatime_t res;
	timersub(&a, &b, &res.dt);
	return res;
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

deltatime_t deltatime_max(deltatime_t a, deltatime_t b)
{
	if (timercmp(&a.dt, &b.dt, >)) {
		return a;
	} else {
		return b;
	}
}

deltatime_t deltatime_add(deltatime_t a, deltatime_t b)
{
	deltatime_t res;
	timeradd(&a.dt, &b.dt, &res.dt);
	return res;
}

deltatime_t deltatime_sub(deltatime_t a, deltatime_t b)
{
	deltatime_t res;
	timersub(&a.dt, &b.dt, &res.dt);
	return res;
}

deltatime_t deltatime_mulu(deltatime_t a, unsigned scalar)
{
	return deltatime_ms(deltamillisecs(a) * scalar);
}

deltatime_t deltatime_divu(deltatime_t a, unsigned scalar)
{
	return deltatime_ms(deltamillisecs(a) / scalar);
}

intmax_t deltamillisecs(deltatime_t d)
{
	return ((intmax_t) d.dt.tv_sec) * 1000 + d.dt.tv_usec / 1000;
}

intmax_t deltasecs(deltatime_t d)
{
	/* XXX: ignore .tv_usec's bias, don't round */
	return d.dt.tv_sec;
}

deltatime_t deltatimescale(int num, int denom, deltatime_t d)
{
	/* ??? should check for overflow */
	return deltatime(deltasecs(d) * num / denom);
}

struct timeval timeval_from_deltatime(deltatime_t d)
{
	return d.dt;
}

deltatime_t deltatime_from_timeval(struct timeval t)
{
	deltatime_t d = { t, };
	return d;
}

/*
 * Try to be smart by only printing the precision necessary.  For
 * instance 1, 0.5, ...
 */
static size_t frac(struct jambuf *buf, intmax_t usec)
{
	int precision = 6;
	while (usec % 10 == 0 && precision > 1) {
		precision--;
		usec = usec / 10;
	}
	return jam(buf, ".%0*jd", precision, usec);
}

size_t jam_deltatime(struct jambuf *buf, deltatime_t d)
{
	size_t s = 0;
	if (d.dt.tv_sec < 0) {
		s += jam(buf, "-");
		d.dt = negate_timeval(d.dt);
	}
	s += jam(buf, "%jd", (intmax_t)d.dt.tv_sec);
	if (d.dt.tv_usec != 0) {
		frac(buf, d.dt.tv_usec);
	}
	return s;
}

const char *str_deltatime(deltatime_t d, deltatime_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_deltatime(&buf, d);
	return out->buf;
}
