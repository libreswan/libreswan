/* timer event handling
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswtime.h"
#include "lswlog.h"

/* monotonic version of time(3) */
time_t
now(void)
{
    static time_t delta = 0
	, last_time = 0;
    time_t n = time(NULL);

    passert(n != (time_t)-1);
    if (last_time > n)
    {
	libreswan_log("time moved backwards %ld seconds", (long)(last_time - n));
	delta += last_time - n;
    }
    last_time = n;
    return n + delta;
}

/* Names of the months */

static const char* months[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


/*
 *  Display a date either in local or UTC time
 */
char *
timetoa(const time_t *timep, bool utc, char *b, size_t blen)
{
    if (*timep == UNDEFINED_TIME) {
	snprintf(b, blen, "--- -- --:--:--%s----", (utc)?" UTC ":" ");
    } else {
	struct tm tmbuf;
	struct tm *tm = (utc? gmtime_r : localtime_r)(timep, &tmbuf);
	
	snprintf(b, blen, "%s %02d %02d:%02d:%02d%s%04d",
	    months[tm->tm_mon], tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,
	    (utc)?" UTC ":" ", tm->tm_year + 1900
	);
    }
    return b;
}

