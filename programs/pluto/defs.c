/* misc. universal things
 * Header: "defs.h"
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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>	/* for _POSIX_MONOTONIC_CLOCK etc. */
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */

#include <errno.h>

bool all_zero(const unsigned char *m, size_t len)
{
	size_t i;

	for (i = 0; i != len; i++)
		if (m[i] != '\0')
			return FALSE;

	return TRUE;
}

/*
 * monotonic variant of time(2)
 *
 * NOT INTENDED TO BE REALTIME!
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
	monotime_t m;
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
		/* OK */
		break;
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
	if (r == 0) {
		return mononow_fallback();
	}

	m.mono_secs =  t.tv_sec;
	return m;
#else
	return mononow_fallback();
#   endif
}

/*
 * checks if the expiration date has been reached and
 * warns during the warning_interval of the imminent
 * expiry.
 * warning interval is in days.
 * strict == TRUE: expiry yields an error message
 * strict == FALSE: expiry yields a warning message
 *
 * Note: not re-entrant because the message may be in a static buffer (buf).
 */
const char *check_expiry(realtime_t expiration_date, time_t warning_interval,
			bool strict)
{
	time_t time_left;	/* a deltatime_t, unpacked */

	if (isundefinedrealtime(expiration_date))
		return "ok (expires never)";

	time_left = deltasecs(realtimediff(expiration_date, realnow()));

	if (time_left < 0)
		return strict ? "fatal (expired)" : "warning (expired)";

	if (time_left > warning_interval)
		return "ok";

	{
		static char buf[35]; /* temporary storage */
		const char *unit = "second";

		if (time_left > 2 * secs_per_day) {
			time_left /= secs_per_day;
			unit = "day";
		} else if (time_left > 2 * secs_per_hour) {
			time_left /= secs_per_hour;
			unit = "hour";
		} else if (time_left > 2 * secs_per_minute) {
			time_left /= secs_per_minute;
			unit = "minute";
		}
		snprintf(buf, sizeof(buf), "warning (expires in %ld %s%s)",
			time_left, unit, (time_left == 1) ? "" : "s");
		return buf;
	}
}
