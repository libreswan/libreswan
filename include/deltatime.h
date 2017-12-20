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

#ifndef _DELTATIME_H
#define _DELTATIME_H    /* seen it, no need to see it again */

#include <sys/time.h>
#include <time.h>
#include <inttypes.h>

struct lswlog;

/*
 * XXX: This value isn't typed so what is it really the max of?
 *
 * XXX: One use, the intent seems to be to set a bound on
 * --crlcheckinterval <seconds>.  Because deltatime_t, when converted
 * to milliseconds, needs to be representable as a intmax_t the below
 * is two big.
 */

#define TIME_T_MAX  ((time_t) ((1ull << (sizeof(time_t) * BITS_PER_BYTE - 1)) - 1))

/*
 * deltatime_t: relative time between events.  Presumed continuous.
 *
 * It seems that some compilers don't like the static constructor
 * DELTATIME() being strongly typed (that is using a cast like
 * (deltatime_t) {{...}}).  Get around this by providing both
 * DELTATIME() and deltatime(); and DELTATIME_MS() and deltatime_ms().
 * Sigh.
 */

typedef struct { intmax_t ms; } deltatime_t;

#define DELTATIME(S) { (intmax_t)((S) * 1000) }
deltatime_t deltatime(time_t secs);

#define DELTATIME_MS(MS) { (MS) }
deltatime_t deltatime_ms(intmax_t ms);

/* sign(a - b) */
int deltatime_cmp(deltatime_t a, deltatime_t b);

/* max(a, b) */
deltatime_t deltatime_max(deltatime_t a, deltatime_t b);

/* a+b */
deltatime_t deltatime_add(deltatime_t a, deltatime_t b);

/* a*s */
deltatime_t deltatime_mulu(deltatime_t a, unsigned scalar);

/* a/s */
deltatime_t deltatime_divu(deltatime_t a, unsigned scalar);

intmax_t deltamillisecs(deltatime_t d);
intmax_t deltasecs(deltatime_t d);
deltatime_t deltatimescale(int num, int denom, deltatime_t d);
bool deltaless(deltatime_t a, deltatime_t b);
bool deltaless_tv_dt(const struct timeval a, const deltatime_t b);

/* Convert to struct timeval. */
struct timeval deltatimeval(deltatime_t);

/* output as "smart" seconds */
size_t lswlog_deltatime(struct lswlog *buf, deltatime_t d);

#endif
