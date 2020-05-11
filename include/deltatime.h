/* time difference objects and functions, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef DELTATIME_H
#define DELTATIME_H    /* seen it, no need to see it again */

#include <time.h>		/* for time_t */
#include <sys/time.h>		/* for struct timeval */
#include <stdint.h>		/* for intmax_t */
#include <stdbool.h>		/* for bool */

#include "jambuf.h"

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
 * A struct initializer for an object of static storage duration
 * cannot include a compound literal (or a function call).
 * DELTATIME_INIT is suitable for a struct initializer.
 * It's optional in an initializer for an object of automatic storage duration.
 * Because it lacks the cast, this macro should not be used in other contexts.
 * Sigh.
 */

typedef struct { struct timeval dt; } deltatime_t;

#define DELTATIME_INIT(S) { .dt = { .tv_sec = (S), } }

deltatime_t deltatime(time_t secs);
deltatime_t deltatime_ms(intmax_t ms);

/* for monotime(a-b) and realtime(a-b) */
deltatime_t deltatime_timevals_diff(struct timeval l, struct timeval r);

/* sign(a - b); see timercmp() for hacks origin */
int deltatime_cmp_sign(deltatime_t a, deltatime_t b);
#define deltatime_cmp(A, OP, B) (deltatime_cmp_sign(A, B) OP 0)

/* max(a, b) */
deltatime_t deltatime_max(deltatime_t a, deltatime_t b);

/* a+b */
deltatime_t deltatime_add(deltatime_t a, deltatime_t b);

/* a-b */
deltatime_t deltatime_sub(deltatime_t a, deltatime_t b);

/* a*s */
deltatime_t deltatime_mulu(deltatime_t a, unsigned scalar);

/* a/s */
deltatime_t deltatime_divu(deltatime_t a, unsigned scalar);

intmax_t deltamillisecs(deltatime_t d);
intmax_t deltasecs(deltatime_t d);
deltatime_t deltatimescale(int num, int denom, deltatime_t d);

/* Convert to/from struct timeval - time used by libevent. */
struct timeval timeval_from_deltatime(deltatime_t);
deltatime_t deltatime_from_timeval(const struct timeval a);

/* output as "smart" seconds */

typedef struct {
	/* slightly over size */
	char buf[sizeof("-18446744073709551615.1000000")+1/*canary*/]; /* true length ???? */
} deltatime_buf;

const char *str_deltatime(deltatime_t d, deltatime_buf *buf);
size_t jam_deltatime(jambuf_t *buf, deltatime_t d);

#endif
