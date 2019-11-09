/*
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

#include "realtime.h"
#include "lswlog.h"

static const char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 *  Display a date either in local or UTC time
 */
void lswlog_realtime(struct lswlog *buf, const realtime_t rtm, bool utc)
{
	if (is_realtime_epoch(rtm)) {
		lswlogf(buf, "--- -- --:--:--%s----", (utc) ? " UTC " : " ");
	} else {
		struct realtm t = (utc ? utc_realtime : local_realtime)(rtm);

		lswlogf(buf, "%s %02d %02d:%02d:%02d%s%04d",
			months[t.tm.tm_mon], t.tm.tm_mday, t.tm.tm_hour,
			t.tm.tm_min, t.tm.tm_sec,
			(utc) ? " UTC " : " ", t.tm.tm_year + 1900);
	}
}
