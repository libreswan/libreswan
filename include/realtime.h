/* time objects and functions, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef _REALTIME_H
#define _REALTIME_H    /* seen it, no need to see it again */

#include <sys/time.h>
#include <time.h>

#include "deltatime.h"

struct lswlog;

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

realtime_t realtime(time_t time);
realtime_t realtimesum(realtime_t t, deltatime_t d);
bool is_realtime_epoch(realtime_t t);
bool realbefore(realtime_t a, realtime_t b);
deltatime_t realtimediff(realtime_t a, realtime_t b);
realtime_t realnow(void);

void lswlog_realtime(struct lswlog *buf, realtime_t r, bool utc);

struct realtm {
	struct tm tm;
	long microsec; /* 1 000 000 per second */
};

struct realtm local_realtime(realtime_t t);
struct realtm utc_realtime(realtime_t t);

#endif

