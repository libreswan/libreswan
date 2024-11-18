/* monotonic time object and functions, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

monotime_t monotime(intmax_t seconds);

#define MONOTIME_EPOCH { { 0, 0 } }

extern const monotime_t monotime_epoch;

bool is_monotime_epoch(monotime_t t);

monotime_t mononow(void);
monotime_t monotime_max(monotime_t l, monotime_t r);
monotime_t monotime_min(monotime_t l, monotime_t r);
monotime_t monotime_add(monotime_t l, deltatime_t r);
monotime_t monotime_sub(monotime_t l, deltatime_t r);

/* sign(a - b); see timercmp() for hacks origin */
int monotime_sub_sign(monotime_t l, monotime_t r);
#define monotime_cmp(L, OP, R) (monotime_sub_sign(L, R) OP 0)

deltatime_t monotimediff(monotime_t a, monotime_t b);
intmax_t monosecs(monotime_t m);

/* for pthread_cond_timedwait() */
clockid_t monotime_clockid(void);

typedef struct {
	/* slightly over size */
	char buf[sizeof("-18446744073709551615.1000000")+1/*canary*/]; /* true length ???? */
} monotime_buf;

const char *str_monotime(monotime_t d, monotime_buf *buf);
size_t jam_monotime(struct jambuf *buf, monotime_t d);

#endif
