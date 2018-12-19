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

#include <inttypes.h>		/* for imaxabs() */

#include "deltatime.h"
#include "lswlog.h"

deltatime_t deltatime(time_t secs)
{
	return (deltatime_t) DELTATIME_INIT(secs);
}

deltatime_t deltatime_ms(intmax_t ms)
{
	return (deltatime_t) { ms };
}

int deltatime_cmp(deltatime_t a, deltatime_t b)
{
	/*
	 * return sign(a - b)
	 *
	 * Can't simply return d because it is larger than int;
	 * instead embrace the stack overflow:
	 *
	 * https://stackoverflow.com/questions/14579920/fast-sign-of-integer-in-c#14612943
	 */
	intmax_t d = a.ms - b.ms;
	return (d > 0) - (d < 0);
}

deltatime_t deltatime_max(deltatime_t a, deltatime_t b)
{
	if (deltatime_cmp(a, b) > 0) {
		return a;
	} else {
		return b;
	}
}

deltatime_t deltatime_add(deltatime_t a, deltatime_t b)
{
	return deltatime_ms(deltamillisecs(a) + deltamillisecs(b));
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
	return d.ms;
}

intmax_t deltasecs(deltatime_t d)
{
	return d.ms / 1000;
}

deltatime_t deltatimescale(int num, int denom, deltatime_t d)
{
	/* ??? should check for overflow */
	return deltatime(deltasecs(d) * num / denom);
}

bool deltaless(deltatime_t a, deltatime_t b)
{
	return deltatime_cmp(a, b) < 0;
}

bool deltaless_tv_dt(const struct timeval a, const deltatime_t b)
{
	return a.tv_sec < deltasecs(b);
}

struct timeval deltatimeval(deltatime_t d)
{
	/*
	 * C99 defines '%' thus:
	 *
	 * [...] the result of the % operator is the remainder. [...]
	 * If the quotient a/b is representable, the expression
	 * (a/b)*b + a%b shall equal a.
	 */
	intmax_t ms = deltamillisecs(d);
	struct timeval e = {
		.tv_sec = ms / 1000,
		.tv_usec = ms % 1000 * 1000,
	};
	return e;
}

/*
 * Try to be smart by only printing the precision necessary.  For
 * instance 1, 0.5, ...
 */

static uintmax_t abs_ms(intmax_t ms, const char **sign)
{
	if (ms == INTMAX_MIN) {
		/*
		 * imaxabs() is not defined when S or MS is the -ve
		 * MIN (on two's complement machines which is all that
		 * libreswan runs on).  This is arguably a "should
		 * never happen", so anything would be valid.
		 */
		*sign = "-";
		/* not cool but good enough */
		return (uintmax_t)INTMAX_MAX + 1;
	} else if (ms < 0) {
		*sign = "-";
		return imaxabs(ms);
	} else {
		/* don't update sign */
		return ms;
	}
}

/* fmt_deltatime() */
size_t lswlog_deltatime(struct lswlog *buf, deltatime_t d)
{
	const char *sign = "";
	uintmax_t ms = abs_ms(deltamillisecs(d), &sign);
	/* split ms -> s.ms */
	uintmax_t s = ms / 1000;
	ms = ms % 1000;
	if (ms == 0) {
		return lswlogf(buf, "%s%ju", sign, s);
	} else if (ms % 100 == 0) {
		return lswlogf(buf, "%s%ju.%01ju", sign, s, ms / 100);
	} else if (ms % 10 == 0) {
		return lswlogf(buf, "%s%ju.%02ju", sign, s, ms / 10);
	} else {
		return lswlogf(buf, "%s%ju.%03ju", sign, s, ms);
	}
}

const char *str_deltatime(deltatime_t d, deltatime_buf *out)
{
	LSWBUF_ARRAY(out->buf, sizeof(out->buf), buf) {
		lswlog_deltatime(buf, d);
	}
	return out->buf;
}
