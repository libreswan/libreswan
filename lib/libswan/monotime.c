/* monotonic time, for libreswan
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2014  D. Hugh Redelmeier.
 * Copyright (C) 2015  Paul Wouters
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

#include "constants.h"	/* for memeq() which is clearly not a constant */
#include "lswlog.h"	/* for libreswan_exit_log_errno() */

#include "monotime.h"

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
	if (e != 0) {
		libreswan_exit_log_errno(e, "clock_gettime(%d,...) in mononow() failed",
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

struct timespec monotime_as_timespec(monotime_t t)
{
	struct timespec ts =  {
		.tv_sec = t.mt.tv_sec,
		.tv_nsec = t.mt.tv_usec * 1000,
	};
	return ts;
}

intmax_t monosecs(monotime_t m)
{
	return m.mt.tv_sec;
}

monotime_t monotimesum(monotime_t t, deltatime_t d)
{
	intmax_t d_ms = deltamillisecs(d);
	struct timeval dt = { d_ms / 1000, d_ms % 1000 };
	monotime_t s = MONOTIME_EPOCH;
	timeradd(&t.mt, &dt, &s.mt);
	return s;
}

bool monobefore(monotime_t a, monotime_t b)
{
	return timercmp(&a.mt, &b.mt, <);
}

deltatime_t monotimediff(monotime_t a, monotime_t b)
{
	struct timeval d;
	timersub(&a.mt, &b.mt, &d);
	return deltatime_ms((intmax_t)d.tv_sec * 1000 + d.tv_usec / 1000);
}
