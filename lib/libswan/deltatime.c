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

#include "deltatime.h"

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
