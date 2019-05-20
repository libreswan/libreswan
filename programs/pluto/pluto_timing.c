/* thread timing time object and functions, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"
#include "state.h"
#include "pluto_timing.h"
#include "lswlog.h"

#define INDENT " "
#define MISSING_FUDGE 0.001

static const clockid_t clock_id = CLOCK_THREAD_CPUTIME_ID;

static struct timespec now(void)
{
	struct timespec now;
	int e = clock_gettime(clock_id, &now);
	if (e != 0) {
		libreswan_exit_log_errno(e, "clock_gettime(%d,...) in mononow() failed in %s()",
					 clock_id, __func__);
	}
	return now;
}

static double seconds_sub(struct timespec stop, const struct timespec start)
{
	/* compute seconds */
	double seconds = (stop.tv_sec - start.tv_sec);
	/* adjust for nanoseconds */
	seconds += (double) stop.tv_nsec / 1000 / 1000 / 1000;
	seconds -= (double) start.tv_nsec / 1000 / 1000 / 1000;
	return seconds;
}

threadtime_t threadtime_start(void)
{
	threadtime_t start = { .tt = now(), };
	return start;
}

double threadtime_stop(const threadtime_t *start, long serialno, const char *fmt, ...)
{
	double seconds = seconds_sub(now(), start->tt);
	if (DBGP(DBG_CPU_USAGE)) {
		LSWLOG_DEBUG(buf) {
			if (serialno > 0) {
				/* on thread so in background */
				lswlogf(buf, "(#%lu) ", serialno);
			}
			lswlogf(buf, PRI_CPU_USAGE" in ",
				pri_cpu_usage(seconds));
			va_list ap;
			va_start(ap, fmt);
			lswlogvf(buf, fmt, ap);
			va_end(ap);
		}
	}
	return seconds;
}

static const statetime_t disabled_statetime = {
	.so = SOS_NOBODY,
	.level = -1,
};

statetime_t statetime_start(struct state *st)
{
	if (st == NULL) {
		/*
		 * Return something describing the next state.  A
		 * second statetime_start(new) call will patch things
		 * up.
		 */
		statetime_t start = {
			.so = next_so_serialno(),
			.level = 0,
			.start = now(),
		};
		return start;
	}
	if (st->st_timing.level > 0 && !DBGP(DBG_CPU_USAGE)) {
		/*
		 * When DBG_CPU_USAGE isn't enabled, only time the
		 * outer most leve.
		 */
		return disabled_statetime;
	}
	statetime_t start = {
		.so = st->st_serialno,
		.level = st->st_timing.level++,
		.start = now(),
	};
	if (DBGP(DBG_CPU_USAGE) && start.level > 0) {
		/*
		 * If there a large blob of time unaccounted for since
		 * the last and nested start() or stop() call, log it
		 * as a separate line item.
		 */
		double missing = seconds_sub(start.start, st->st_timing.last_log.time);
		if (missing > MISSING_FUDGE) {
			LSWLOG_DEBUG(buf) {
				for (int i = 0; i < start.level; i++) {
					lswlogs(buf, INDENT INDENT);
				}
				lswlogf(buf, "#%lu "PRI_CPU_USAGE"",
					st->st_serialno,
					pri_cpu_usage(missing));
			}
		}
	}
	st->st_timing.last_log.time = start.start;
	st->st_timing.last_log.level = start.level;
	return start;
}

void statetime_stop(const statetime_t *start, const char *fmt, ...)
{
	/*
	 * Check for disabled statetime, indicates that timing is
	 * disabled for this level.
	 */
	if (memeq(start, &disabled_statetime, sizeof(disabled_statetime))) {
		return;
	}
	pexpect(start->level == 0 || DBGP(DBG_CPU_USAGE));

	/* state disappeared? */
	struct state *st = state_with_serialno(start->so);
	if (st == NULL) {
		return;
	}

	struct timespec stop_time = now();

	/*
	 * If there a large blob of time unaccounted for since the
	 * last nested stop(), log it as a separate line item.
	 */
	if (DBGP(DBG_CPU_USAGE) &&
	    st->st_timing.last_log.level > start->level) {
		double missing = seconds_sub(stop_time, st->st_timing.last_log.time);
		if (missing > MISSING_FUDGE) {
			LSWLOG_DEBUG(buf) {
				/* missing is indented by 2 more */
				for (int i = 0; i < start->level; i++) {
					lswlogs(buf, INDENT INDENT);
				}
				lswlogs(buf, INDENT INDENT);
				lswlogf(buf, "#%lu "PRI_CPU_USAGE"",
					st->st_serialno,
					pri_cpu_usage(missing));
			}
		}
	}

	/* time since start */
	double seconds = seconds_sub(stop_time, start->start);
	if (DBGP(DBG_CPU_USAGE)) {
		LSWLOG_DEBUG(buf) {
			/* update is indented by 2 indents */
			for (int i = 0; i < start->level; i++) {
				lswlogs(buf, INDENT INDENT);
			}
			lswlogf(buf, "#%lu "PRI_CPU_USAGE" in ",
				st->st_serialno,
				pri_cpu_usage(seconds));
			va_list ap;
			va_start(ap, fmt);
			lswlogvf(buf, fmt, ap);
			va_end(ap);
		}
	}

	/* everything logged, update */
	st->st_timing.level = start->level;
	st->st_timing.last_log.time = stop_time;
	st->st_timing.last_log.level = start->level;
	if (start->level == 0) {
		/* bill total time */
		st->st_timing.approx_seconds += seconds;
	}
}
