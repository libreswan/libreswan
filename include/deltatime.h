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

#include "diag.h"
#include "shunk.h"

struct jambuf;
enum timescale;

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

typedef struct {
	struct timeval dt;
	bool is_set;
} deltatime_t;

extern const deltatime_t deltatime_zero;
extern const deltatime_t one_day;
extern const deltatime_t one_hour;
extern const deltatime_t one_minute;
extern const deltatime_t one_second;

#define DELTATIME_INIT(S) { .dt = { .tv_sec = (S), }, .is_set = true, }

deltatime_t deltatime(time_t secs);
deltatime_t deltatime_from_milliseconds(intmax_t milliseconds);
deltatime_t deltatime_from_microseconds(intmax_t microseconds);

/* for monotime(a-b) and realtime(a-b) */
deltatime_t deltatime_timevals_diff(struct timeval l, struct timeval r);

/* sign(a - b); see timercmp() for hacks origin */
int deltatime_sub_sign(deltatime_t l, deltatime_t r);
#define deltatime_cmp(L, OP, R) (deltatime_sub_sign(L, R) OP 0)

/* max(a, b) | min(a, b) */
deltatime_t deltatime_max(deltatime_t a, deltatime_t b);
deltatime_t deltatime_min(deltatime_t a, deltatime_t b);

/* a+b */
deltatime_t deltatime_add(deltatime_t a, deltatime_t b);

/* a-b */
deltatime_t deltatime_sub(deltatime_t a, deltatime_t b);

/* a*s */
deltatime_t deltatime_mulu(deltatime_t a, unsigned scalar);

/* a/s */
deltatime_t deltatime_divu(deltatime_t a, unsigned scalar);

intmax_t microseconds_from_deltatime(deltatime_t d);
intmax_t milliseconds_from_deltatime(deltatime_t d);
time_t seconds_from_deltatime(deltatime_t d);
#define deltasecs seconds_from_deltatime
deltatime_t deltatime_scale(deltatime_t d, int num, int denom); /* D*NUM/DENOM */

/* Convert to/from struct timeval - time used by libevent. */
struct timeval timeval_from_deltatime(deltatime_t);
deltatime_t deltatime_from_timeval(const struct timeval a);

/* output as "smart" seconds */

typedef struct {
	/* slightly over size */
	char buf[sizeof("-18446744073709551615.1000000000")+1/*canary*/]; /* true length ???? */
} deltatime_buf;

const char *str_deltatime(deltatime_t d, deltatime_buf *buf);
size_t jam_deltatime(struct jambuf *buf, deltatime_t d);

diag_t ttodeltatime(const char *t, deltatime_t *d, enum timescale default_timescale);

/*
 * Primitives used to implement times; try to avoid timeval
 * explicitly.
 */

struct timeval from_seconds(time_t seconds);
struct timeval from_milliseconds(intmax_t milliseconds);
struct timeval from_microseconds(intmax_t microseconds);
intmax_t seconds_from(struct timeval);
intmax_t milliseconds_from(struct timeval);
intmax_t microseconds_from(struct timeval);

/* for *time_cmp(): sign(l-r) */
int timeval_sub_sign(struct timeval l, struct timeval r);

#endif
