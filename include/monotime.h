/* monotonic time object and functions, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2017-2018  Andrew Cagney
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

#ifndef MONOTIME_H
#define MONOTIME_H    /* seen it, no need to see it again */

#include <sys/time.h>		/* for struct timeval */
#include <stdbool.h>		/* for bool */

#include "deltatime.h"

/*
 * The time objects are wrapped so that dimensional analysis will be
 * enforced by the compiler.
 */

/*
 * monotime_t: absolute monotonic time.  No discontinuities (except
 * for machine sleep?)
 *
 * - various clocks can jump backwards on UNIX/LINUX; for instance
 *   when the machine's UTC clock is corrected
 *
 * - this causes all kinds of problems with timeouts observable in the
 *   Real World
 *
 * - this code detects backward jumps and compensates by refusing to
 *    go backwards
 *
 * - unfortunately there is no way to detect forward jumps
 *
 */

typedef struct { struct timeval mt; } monotime_t;

#define MONOTIME_EPOCH { { 0, 0 } }

extern const monotime_t monotime_epoch;

bool is_monotime_epoch(monotime_t t);

monotime_t mononow(void);
monotime_t monotimesum(monotime_t t, deltatime_t d);
bool monobefore(monotime_t a, monotime_t b);
deltatime_t monotimediff(monotime_t a, monotime_t b);
intmax_t monosecs(monotime_t m);

/* output as "smart" seconds */
size_t lswlog_monotime(struct lswlog *buf, monotime_t d);

/* for pthread_cond_timedwait() */
clockid_t monotime_clockid(void);
struct timespec monotime_as_timespec(monotime_t);

#endif
