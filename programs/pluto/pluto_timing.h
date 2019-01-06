/* thread and state timing time object and functions, for libreswan
 *
 * Copyright (C) 2019  Andrew Cagney
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

#ifndef PLUTO_TIMING_H
#define PLUTO_TIMING_H    /* seen it, no need to see it again */

#include <stdbool.h>		/* for bool */
#include <time.h>		/* for struct timespec */

#include "lswcdefs.h"		/* for PRINTF_LIKE() */

struct state;

/*
 * Try to format all cpu usage messaages the same.  All delta-times
 * use double and are in seconds.
 */
#define PRI_CPU_USAGE "spent %.3g milliseconds"
#define pri_cpu_usage(S) (S * 1000)

/*
 * For when on a helper thread (or anything that doesn't have a
 * state).
 *
 * threadtime_t start = threadtime_start();
 * do something;
 * seconds_used = threadtime_stop(&start, serialno, "do something");
 */

typedef struct { struct timespec tt; } threadtime_t;
threadtime_t threadtime_start(void);
double threadtime_stop(const threadtime_t *start, long serialno, const char *fmt, ...) PRINTF_LIKE(3);

/*
 * For state timing:
 *
 * In theory:
 *
 *   p0 = statetime_start(st);
 *     p1 = statetime_start(st)
 *       do something
 *     statetime_start(&p1, "did something else");
 *     p1 = statetime_start(st)
 *       do something else;
 *     statetime_stop(&p1, "did something else");
 *   statetime_stop(&p0, "did several things");
 *
 * But several things bite:
 *
 * - "do something" might delete the state (complete_v2*() likes to
 *   delete it, and or zap mpd), so forced to use so_serial_t when
 *   performing statetime_update.
 *
 * - "do something" might create the state so need to poke around in
 *    state.c to find what the next serialno might be
 *
 * - should be layered on top of push/pop state, except that is a
 *   bigger mess!
 *
 * - the call statetime_start(NULL) returns the start time of the next
 *   (yet to be created) state.  When the state is created a second
 *   statetime_start(new) gets things kind of in sync.  Ewww!
 */

struct timing {
	double approx_seconds;
	int level;
	/*
	 * Track last time something was logged and level.  Used when
	 * checking for unaccounted time.
	 */
	struct {
		struct timespec time;
		int level;
	} last_log;
};

typedef struct {
	so_serial_t so;
	int level;
	struct timespec start;
} statetime_t;

statetime_t statetime_start(struct state *st);
void statetime_stop(const statetime_t *start, const char *fmt, ...) PRINTF_LIKE(2);

#endif
