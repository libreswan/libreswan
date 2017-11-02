/* monotonic time, for libreswan
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2014  D. Hugh Redelmeier.
 * Copyright (C) 2015  Paul Wouters
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdbool.h>
#include <unistd.h>	/* for _POSIX_MONOTONIC_CLOCK */
#include <errno.h>

#include "monotime.h"
#include "lswlog.h"

/*
 * monotonic variant of time(2)
 *
 * NOT INTENDED TO BE REALTIME!
 *
 * NOTE: static initializer only happens at load time, so
 * delta/last_time are only set to 0 once, not each call.
 */

static monotime_t mononow_fallback(void) {
	monotime_t m;
	static time_t delta = 0,
		last_time = 0;
	time_t n = time(NULL);	/* third best */

	passert(n != (time_t)-1);
	if (last_time > n) {
		libreswan_log("time moved backwards %ld seconds",
			(long)(last_time - n));
		delta += last_time - n;
	}
	last_time = n;
	m.mono_secs = n + delta;
	return m;
}

monotime_t mononow(void)
{
#ifdef _POSIX_MONOTONIC_CLOCK
	struct timespec t;
	int r = clock_gettime(
#   ifdef CLOCK_BOOTTIME
		CLOCK_BOOTTIME	/* best */
#   else
		CLOCK_MONOTONIC	/* second best */
#   endif
		, &t);

	switch (r) {
	case 0:
	{
		/* OK */
		monotime_t m = { .mono_secs = t.tv_sec, };
		return m;
	}
	case EINVAL:
		libreswan_log("Invalid clock method for clock_gettime() - possibly compiled with mismatched kernel and glibc-headers ");
		break;
	case EPERM:
		libreswan_log("No permission for clock_gettime()");
		break;
	case EFAULT:
		libreswan_log("Invalid address space return by clock_gettime()");
		break;
	default:
		libreswan_log("unknown clock_gettime() error: %d", r);
		break;
	}
#   endif
	return mononow_fallback();
}

monotime_t monotimesum(monotime_t t, deltatime_t d)
{
	monotime_t s = { t.mono_secs + deltasecs(d) };
	return s;
}

bool monobefore(monotime_t a, monotime_t b)
{
	return a.mono_secs < b.mono_secs;
}

deltatime_t monotimediff(monotime_t a, monotime_t b)
{
	return deltatime(a.mono_secs - b.mono_secs);
}
