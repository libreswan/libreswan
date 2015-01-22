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
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h> /* for bool */

//#include "sysdep.h"
//#include "constants.h"

/* Names of the months */
static const char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 *  Display a date either in local or UTC time
 */
char *realtimetoa(const realtime_t rtm, bool utc, char *b, size_t blen)
{
	if (isundefinedrealtime(rtm)) {
		snprintf(b, blen, "--- -- --:--:--%s----",
			(utc) ? " UTC " : " ");
	} else {
		struct tm tmbuf;
		struct tm *tm = (utc ? gmtime_r : localtime_r)(&rtm.real_secs, &tmbuf);

		snprintf(b, blen, "%s %02d %02d:%02d:%02d%s%04d",
			months[tm->tm_mon], tm->tm_mday, tm->tm_hour,
			tm->tm_min, tm->tm_sec,
			(utc) ? " UTC " : " ", tm->tm_year + 1900);
	}
	return b;
}
