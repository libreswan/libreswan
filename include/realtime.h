/* realtime objects and functions, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2017, 2018  Andrew Cagney
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
 *
 */

#ifndef REALTIME_H
#define REALTIME_H    /* seen it, no need to see it again */

#include <sys/time.h>		/* for struct timeval */
#include <time.h>		/* for time_t and struct tm */
#include <stdbool.h>		/* for bool */

#include "deltatime.h"		/* for deltatime_t */

struct jambuf;

/*
 * The time objects are wrapped so that dimensional analysis will be
 * enforced by the compiler.
 */

/*
 * realtime_t: absolute UTC time.  Might be discontinuous due to clock
 * adjustment.
 *
 * Use struct timeval as that has the supporting macros timeradd(3)
 * et.al. for performing arithmetic.
 *
 * According to the gettimeofday(2) man mage, struct timespec and
 * clock_gettime(2) are, techncially, a far better choice but they
 * lack pre-defined operators.
 */

typedef struct { struct timeval rt; } realtime_t;

#define REALTIME_EPOCH {{ 0, 0, }}

extern const realtime_t realtime_epoch;

realtime_t realtime(time_t seconds);
diag_t ttorealtime(const char *time, realtime_t *rt);

/*
 * Formatting.
 */

typedef struct {
	char buf[sizeof("--- -- --:--:-- UTC ----")+1/*canary*/];
} realtime_buf;

const char *str_realtime(realtime_t r, bool utc, realtime_buf *buf);
size_t jam_realtime(struct jambuf *buf, realtime_t r, bool utc);

/*
 * math
 */

realtime_t realtimesum(realtime_t t, deltatime_t d);
bool is_realtime_epoch(realtime_t t);

/* sign(a - b); see timercmp() for hacks origin */
int realtime_sub_sign(realtime_t l, realtime_t r);
#define realtime_cmp(L, OP, R) (realtime_sub_sign(L, R) OP 0)

deltatime_t realtimediff(realtime_t a, realtime_t b);
realtime_t realnow(void);

struct realtm {
	struct tm tm;
	long microsec; /* 1 000 000 per second */
};

struct realtm local_realtime(realtime_t t);
struct realtm utc_realtime(realtime_t t);

/* for pthread_cond_timedwait() */
clockid_t realtime_clockid(void);

#endif
