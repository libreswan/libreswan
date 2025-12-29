/* time objects and functions, for libreswan
 *
 * Copyright (C) 2023  Andrew Cagney
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

#ifdef linux
#define _XOPEN_SOURCE		/* expose strptime() */
#endif

#include <sys/types.h>		/* for __need_clockid_t */
#include <time.h>
#include <string.h>

#include "lswcdefs.h"		/* FOR_EACH_ELEMENT() */
#include "realtime.h"

diag_t ttorealtime(const char *t, realtime_t *rt)
{
	/* manual says to pre-initialize */
	struct tm tm = {0};
	const char *end = strchr(t, '\0');

	/* try to parse it */
	const char *format[] = {
		"%Y-%m-%d %H:%M:%S",
		"%Y-%m-%d",
	};

	FOR_EACH_ELEMENT(f, format) {
		tm = (struct tm) {0};
		if (strptime(t, *f, &tm) == end) {
			/* convert to time_t */
			time_t time = mktime(&tm);
			if (time == (time_t)-1) {
				return diag("mktime(strptime(\"%s\",\"%s\")) failed", *f, t);
			}
			/* and convert that to realtime_t */
			*rt = realtime_from_seconds(time);
			return NULL;
		}
	}

	/* hack to accumulate all possible formats in error */
	diag_t d = diag("\"%s\"", format[0]);
	FOR_EACH_ELEMENT_FROM_1(f, format) {
		d = diag_diag(&d, "\"%s\", ", *f);
	}

	return diag_diag(&d, "strptime() failed, tried ");
}
