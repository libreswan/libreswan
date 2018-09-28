/* log deltatime, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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
 */

#include <inttypes.h>

#include "constants.h"
#include "deltatime.h"
#include "lswlog.h"

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
