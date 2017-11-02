/*
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

#include <stdio.h>
#include <stdbool.h>

#include "realtime.h"

static const char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 *  Display a date either in local or UTC time
 */
char *realtimetoa(const realtime_t rtm, bool utc, char *b, size_t blen)
{
	if (is_realtime_epoch(rtm)) {
		snprintf(b, blen, "--- -- --:--:--%s----",
			(utc) ? " UTC " : " ");
	} else {
		struct realtm t = (utc ? utc_realtime : local_realtime)(rtm);

		snprintf(b, blen, "%s %02d %02d:%02d:%02d%s%04d",
			 months[t.tm.tm_mon], t.tm.tm_mday, t.tm.tm_hour,
			 t.tm.tm_min, t.tm.tm_sec,
			 (utc) ? " UTC " : " ", t.tm.tm_year + 1900);
	}
	return b;
}
