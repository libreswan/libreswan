/* cpu wall/thread timing, for libreswan
 *
 * Copyright (C) 2019,2025 Andrew Cagney
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

#ifndef CPUTIME_H
#define CPUTIME_H    /* seen it, no need to see it again */

#include <time.h>		/* for struct timespec */

/*
 * Try to format all cpu usage messaages the same.  All delta-times
 * use double and are in seconds.
 */

typedef struct {
	struct timespec thread_clock;
	struct timespec wall_clock;
} cputime_t;

struct cpu_usage {
	double thread_seconds;
	double wall_seconds;
};

#define PRI_CPU_USAGE "spent %.3g (%.3g) milliseconds"
#define pri_cpu_usage(C) ((C).thread_seconds * 1000), ((C).wall_seconds * 1000)

#define cpu_usage_add(TOTAL, USAGE)					\
	{								\
		(TOTAL).thread_seconds += (USAGE).thread_seconds;	\
		(TOTAL).wall_seconds += (USAGE).wall_seconds;		\
	}

/*
 * For when on a helper thread (or anything that doesn't have a
 * state).
 *
 * threadtime_t start = threadtime_start();
 * do something;
 * threadtime_stop(&start, "do something");
 */

cputime_t cputime_start(void);
struct cpu_usage cputime_stop(cputime_t start);

struct cpu_usage cputime_sub(cputime_t l, cputime_t r);

#endif
