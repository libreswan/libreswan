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
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */

bool all_zero(const unsigned char *m, size_t len)
{
	size_t i;

	for (i = 0; i != len; i++)
		if (m[i] != '\0')
			return FALSE;

	return TRUE;
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

	if (is_realtime_epoch(expiration_date))
		return "ok (expires never)";

	time_left = deltasecs(realtimediff(expiration_date, realnow()));

	if (time_left < 0)
		return strict ? "fatal (expired)" : "warning (expired)";

	if (time_left > warning_interval)
		return "ok";

	{
		/* STATIC!! */
		/* note: 20 is a guess at the maximum digits in an intmax_t */
		static char buf[sizeof("warning (expires in %jd minutes)") + 20];
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
		snprintf(buf, sizeof(buf), "warning (expires in %jd %s%s)",
			 (intmax_t) time_left, unit,
			 (time_left == 1) ? "" : "s");
		return buf;
	}
}
