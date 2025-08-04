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

#include <errno.h>

#include "defs.h"
#include "state.h"
#include "connections.h"
#include "pluto_timing.h"
#include "log.h"

#define INDENT " "
#define MISSING_FUDGE 0.001

static struct timespec thread_clock(void)
{
	static const clockid_t clock_id = CLOCK_THREAD_CPUTIME_ID;
	struct timespec now;
	int e = clock_gettime(clock_id, &now);
	passert(e == 0);
	return now;
}

static struct timespec wall_clock(void)
{
	struct timespec now;
	/* use the same clockid as monotime */
	int e = clock_gettime(monotime_clockid(), &now);
	passert(e == 0);
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

static struct cpu_usage threadtime_sub(threadtime_t l, threadtime_t r)
{
	struct cpu_usage s = {
		.thread_seconds = seconds_sub(l.thread_clock, r.thread_clock),
		.wall_seconds = seconds_sub(l.wall_clock, r.wall_clock),
	};
	return s;
}

threadtime_t threadtime_start(void)
{
	threadtime_t start = {
		.thread_clock = thread_clock(),
		.wall_clock = wall_clock(),
	};
	return start;
}

void threadtime_stop(const threadtime_t *start, so_serial_t serialno, const char *fmt, ...)
{
	struct logger *logger = &global_logger;

	if (LDBGP(DBG_CPU_USAGE, logger)) {
		struct cpu_usage usage = threadtime_sub(threadtime_start(), *start);
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			if (serialno > 0) {
				/* on thread so in background */
				jam_string(buf, "(");
				jam_so(buf, serialno);
				jam_string(buf, ") ");
			}
			jam(buf, PRI_CPU_USAGE" in ",
				pri_cpu_usage(usage));
			va_list ap;
			va_start(ap, fmt);
			jam_va_list(buf, fmt, ap);
			va_end(ap);
		}
	}
}

logtime_t logtime_start(struct logger *logger)
{
	logtime_t start = {
		.time = threadtime_start(),
		.logger = logger,
		.level = logger->timing_level++,
	};
	return start;
}

struct cpu_usage logtime_stop(const logtime_t *start, const char *fmt, ...)
{
	struct logger *logger = &global_logger;

	struct cpu_usage usage = threadtime_sub(threadtime_start(), start->time);
	if (LDBGP(DBG_CPU_USAGE, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			/* update is indented by 2 indents */
			for (int i = 0; i < start->level; i++) {
				jam_string(buf, INDENT INDENT);
			}
			jam_logger_prefix(buf, start->logger);
			jam(buf, PRI_CPU_USAGE" in ", pri_cpu_usage(usage));
			va_list ap;
			va_start(ap, fmt);
			jam_va_list(buf, fmt, ap);
			va_end(ap);
		}
	}
	start->logger->timing_level = start->level;
	return usage;
}

static const statetime_t disabled_statetime = {
	.so = SOS_NOBODY,
	.level = -1,
};

static void DBG_missing(const statetime_t *start, threadtime_t now,
			threadtime_t last_log)
{
	/*
	 * If there a large blob of time unaccounted for since LAST,
	 * log it as a separate line item.
	 */
	struct cpu_usage missing = threadtime_sub(now, last_log);
	if (missing.thread_seconds > MISSING_FUDGE) {
		LLOG_JAMBUF(DEBUG_STREAM, &global_logger, buf) {
			for (int i = 0; i < start->level; i++) {
				jam_string(buf, INDENT INDENT);
			}
			jam_so(buf, start->so);
			jam(buf, " "PRI_CPU_USAGE, pri_cpu_usage(missing));
		}
	}
}

static statetime_t start_statetime(struct state *st,
				   threadtime_t inception)
{
	statetime_t start = {
		.so = st->st_serialno,
		.level = st->st_timing.level++,
		.time = inception,
	};
	st->st_timing.last_log.time = start.time;
	st->st_timing.last_log.level = start.level;
	return start;
}

statetime_t statetime_start(struct state *st)
{
	struct logger *logger = &global_logger;

	if (st == NULL) {
		/*
		 * IKEv1 sometimes doesn't have a state to time, just
		 * ignore it.
		 */
		ldbg(&global_logger, "in %s() with no state", __func__);
		return disabled_statetime;
	}
	if (st->st_timing.level > 0 && !LDBGP(DBG_CPU_USAGE, logger)) {
		/*
		 * When DBG_CPU_USAGE isn't enabled, only time the
		 * outer most level.
		 */
		return disabled_statetime;
	}
	/* save last_log before start_statetime() updates it */
	threadtime_t last_log = st->st_timing.last_log.time;
	statetime_t start = start_statetime(st, threadtime_start());
	if (LDBGP(DBG_CPU_USAGE, logger) && start.level > 0) {
		/*
		 * If there a large blob of time unaccounted for since
		 * the last and nested start() or stop() call, log it
		 * as a separate line item.
		 */
		DBG_missing(&start, start.time, last_log);
	}
	return start;
}

statetime_t statetime_backdate(struct state *st, const threadtime_t *inception)
{
	struct logger *logger = &global_logger;

	if (st == NULL) {
		/*
		 * IKEv1 sometimes doesn't have a state to time, just
		 * ignore it.
		 */
		ldbg(&global_logger, "in %s() with no state", __func__);
		return disabled_statetime;
	}
	passert(inception != NULL);
	if (st->st_timing.level > 0) {
		pexpect(st->st_ike_version == IKEv1);
		ldbg(st->logger, "in %s() with non-zero timing level", __func__);
		st->st_timing.level = 0;
	}
	statetime_t start = start_statetime(st, *inception);
	/*
	 * If there's a large blob of time between this call and
	 * inception, log it.  Remember, start.time will be set to
	 * inception time so isn't useful.
	 */
	if (LDBGP(DBG_CPU_USAGE, logger)) {
		DBG_missing(&start, threadtime_start(), *inception);
	}
	return start;
}

void statetime_stop(const statetime_t *start, const char *fmt, ...)
{
	struct logger *logger = &global_logger;

	/*
	 * Check for disabled statetime, indicates that timing is
	 * disabled for this level.
	 */
	if (memeq(start, &disabled_statetime, sizeof(disabled_statetime))) {
		return;
	}
	pexpect(start->level == 0 || LDBGP(DBG_CPU_USAGE, logger));

	/* state disappeared? */
	struct state *st = state_by_serialno(start->so);
	if (st == NULL) {
		ldbg(&global_logger, "in %s() and could not find "PRI_SO"",
		     __func__, pri_so(start->so));
		return;
	}

	threadtime_t stop_time = threadtime_start();

	/*
	 * If there a large blob of time unaccounted for since the
	 * last nested stop(), log it as a separate line item.
	 */
	if (LDBGP(DBG_CPU_USAGE, logger) &&
	    st->st_timing.last_log.level > start->level) {
		DBG_missing(start, stop_time, st->st_timing.last_log.time);
	}

	/* time since start */
	struct cpu_usage usage = threadtime_sub(stop_time, start->time);
	if (LDBGP(DBG_CPU_USAGE, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, &global_logger, buf) {
			/* update is indented by 2 indents */
			for (int i = 0; i < start->level; i++) {
				jam_string(buf, INDENT INDENT);
			}
			jam_so(buf, st->st_serialno);
			jam(buf, " "PRI_CPU_USAGE" in ", pri_cpu_usage(usage));
			va_list ap;
			va_start(ap, fmt);
			jam_va_list(buf, fmt, ap);
			va_end(ap);
		}
	}

	/* everything logged, update */
	st->st_timing.level = start->level;
	st->st_timing.last_log.time = stop_time;
	st->st_timing.last_log.level = start->level;
	if (start->level == 0) {
		/* bill total time */
		cpu_usage_add(st->st_timing.main_usage, usage);
	}
}

monotime_t monotime_from_threadtime(const threadtime_t time)
{
	monotime_t m = {
		.mt = {
			.tv_sec = time.wall_clock.tv_sec,
			.tv_usec = time.wall_clock.tv_nsec / 1000,
		}
	};
	return m;
}
