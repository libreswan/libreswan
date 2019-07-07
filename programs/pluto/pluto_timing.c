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

static void DBG_missing(const statetime_t *start, struct timespec now, struct timespec last_log)
{
	/*
	 * If there a large blob of time unaccounted for since LAST,
	 * log it as a separate line item.
	 */
	double missing = seconds_sub(now, last_log);
	if (missing > MISSING_FUDGE) {
		LSWLOG_DEBUG(buf) {
			for (int i = 0; i < start->level; i++) {
				lswlogs(buf, INDENT INDENT);
			}
			lswlogf(buf, "#%lu "PRI_CPU_USAGE"",
				start->so, pri_cpu_usage(missing));
		}
	}
}

static statetime_t start_statetime(struct state *st, struct timespec now)
{
	statetime_t start = {
		.so = st->st_serialno,
		.level = st->st_timing.level++,
		.start = now,
	};
	st->st_timing.last_log.time = start.start;
	st->st_timing.last_log.level = start.level;
	return start;
}

statetime_t statetime_start(struct state *st)
{
	if (st == NULL) {
		/*
		 * IKEv1 sometimes doesn't have a state to time, just
		 * ignore it.
		 */
		dbg("in %s() with no state", __func__);
		return disabled_statetime;
	}
	if (st->st_timing.level > 0 && !DBGP(DBG_CPU_USAGE)) {
		/*
		 * When DBG_CPU_USAGE isn't enabled, only time the
		 * outer most leve.
		 */
		return disabled_statetime;
	}
	/* save last_log before start_statetime() updates it */
	struct timespec last_log = st->st_timing.last_log.time;
	statetime_t start = start_statetime(st, now());
	if (DBGP(DBG_CPU_USAGE) && start.level > 0) {
		/*
		 * If there a large blob of time unaccounted for since
		 * the last and nested start() or stop() call, log it
		 * as a separate line item.
		 */
		DBG_missing(&start, start.start, last_log);
	}
	return start;
}

statetime_t statetime_backdate(struct state *st, const threadtime_t *inception)
{
	if (st == NULL) {
		/*
		 * IKEv1 sometimes doesn't have a state to time, just
		 * ignore it.
		 */
		dbg("in %s() with no state", __func__);
		return disabled_statetime;
	}
	passert(inception != NULL);
	if (st->st_timing.level > 0) {
		pexpect(st->st_ike_version == IKEv1);
		dbg("in %s() with non-zero timing level", __func__);
		st->st_timing.level = 0;
	}
	statetime_t start = start_statetime(st, inception->tt);
	/*
	 * If there's a large blob of time before this call, log it.
	 */
	if (DBGP(DBG_CPU_USAGE)) {
		DBG_missing(&start, now(), inception->tt);
	}
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
		dbg("in %s() and could not find #%lu", __func__, start->so);
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
