/* monotonic time object and functions, for libreswan
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

#ifndef _MONOTIME_H
#define _MONOTIME_H    /* seen it, no need to see it again */

#include <sys/time.h>
#include <time.h>

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
 * ??? On UNIX, 0 is a value that means 1970-01-01 00:00:00 +0000 (UTC).
 *
 * UNDEFINED_TIME is used as a mono time_t value in liveness_check().
 * 0 is PROBABLY safely distinct in this application.
 */

typedef struct { time_t mono_secs; } monotime_t;

#define UNDEFINED_TIME  ((time_t)0)	/* ??? what a kludge! */

monotime_t mononow(void);
monotime_t monotimesum(monotime_t t, deltatime_t d);
bool monobefore(monotime_t a, monotime_t b);
deltatime_t monotimediff(monotime_t a, monotime_t b);

#endif
