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

#ifndef _LSWTIME_H
#define _LSWTIME_H    /* seen it, no need to see it again */

#include <sys/time.h>
#include <time.h>
#include <inttypes.h>

/*
 * The time objects are wrapped so that dimensional analysis will be
 * enforced by the compiler.
 */

/*
 * XXX: This value isn't typed so what is it really the max of?
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
 *
 * C99 defines '%' used in DELATTIME_MS() thus:
 *
 * [...] the result of the % operator is the remainder. [...] If the
 * quotient a/b is representable, the expression (a/b)*b + a%b shall
 * equal a.
 */

typedef struct { struct timeval dt; } deltatime_t;

#define DELTATIME(S) {{ (time_t)(S), 0, }}
deltatime_t deltatime(time_t secs);
/* #define DELTATIME(S) {{ (time_t)(S), (long)(((S) - (intmax_t)(S)) * 1000000) }} */

#define DELTATIME_MS(MS) {{ (MS) / 1000, (MS) % 1000 * 1000 }}
deltatime_t deltatime_ms(intmax_t ms);

/* sign(a - b) */
int deltatime_cmp(deltatime_t a, deltatime_t b);

/* max(a, b) */
deltatime_t deltatime_max(deltatime_t a, deltatime_t b);

intmax_t deltamillisecs(deltatime_t d);
time_t deltasecs(deltatime_t d);
deltatime_t deltatimescale(int num, int denom, deltatime_t d);
bool deltaless(deltatime_t a, deltatime_t b);
bool deltaless_tv_dt(const struct timeval a, const deltatime_t b);

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

#define REALTIME_EPOCH ((realtime_t) { { 0, 0, }, })

realtime_t realtime(time_t time);
realtime_t realtimesum(realtime_t t, deltatime_t d);
bool is_realtime_epoch(realtime_t t);
bool realbefore(realtime_t a, realtime_t b);
deltatime_t realtimediff(realtime_t a, realtime_t b);
realtime_t realnow(void);
#define REALTIMETOA_BUF     30	/* size of realtimetoa string buffer */
char *realtimetoa(const realtime_t rtm, bool utc, char *buf, size_t blen);

struct realtm {
	struct tm tm;
	long microsec; /* 1 000 000 per second */
};

struct realtm local_realtime(realtime_t t);
struct realtm utc_realtime(realtime_t t);

#endif /* _LIBRESWAN_H */
