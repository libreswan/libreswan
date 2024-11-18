/* test *time_t code, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#include <stdio.h>
#include <string.h>

#include "deltatime.h"
#include "timecheck.h"
#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for bool_str() */
#include "timescale.h"

struct test_op {
	intmax_t lms, rms;
	const char *str;
};

#define CHECK_DELTATIME_OP(OP)						\
	check_deltatime_op(test_deltatime_##OP,				\
			   elemsof(test_deltatime_##OP),		\
			   deltatime_##OP, #OP)

static void check_deltatime_op(const struct test_op *tests, size_t nr_tests,
			       deltatime_t (*op)(deltatime_t, deltatime_t),
			       const char *op_name)
{
	for (unsigned i = 0; i < nr_tests; i++) {
		const struct test_op *t = &tests[i];
		deltatime_t l = deltatime_from_milliseconds(t->lms);
		deltatime_t r = deltatime_from_milliseconds(t->rms);
		deltatime_buf buf;
		const char *str = str_deltatime(op(l, r), &buf);
		FILE *out = (strcmp(str, t->str) == 0) ? stdout : stderr;
		fprintf(out, "str_deltatime(deltatime_%s(%jdms, %jdms)) == %s",
			op_name, t->lms, t->rms, t->str);
		if (out == stderr) {
			fprintf(out, "; FAIL: returned %s", str);
			fails++;
		}
		fprintf(out, "\n");
	}
}

static void check_ttodeltatime(void)
{
	static const struct test_ttodeltatime {
		const char *str;
		intmax_t us;
		const struct timescale *scale;
		bool ok;
	} test_ttodeltatime[] = {
		/* scale */
		{ "1",   (uintmax_t)1,                      &timescale_microseconds, true, },
		{ "1",   (uintmax_t)1*1000,                 &timescale_milliseconds, true, },
		{ "1",   (uintmax_t)1*1000*1000,            &timescale_seconds, true, },
		{ "1",   (uintmax_t)1*1000*1000*60,         &timescale_minutes, true, },
		{ "1",   (uintmax_t)1*1000*1000*60*60,      &timescale_hours, true, },
		{ "1",   (uintmax_t)1*1000*1000*60*60*24,   &timescale_days, true, },
		{ "1",   (uintmax_t)1*1000*1000*60*60*24*7, &timescale_weeks, true, },

		/* suffix */
		{ "1us", (uintmax_t)1,                      &timescale_seconds, true, },
		{ "1ms", (uintmax_t)1*1000,                 &timescale_seconds, true, },
		{ "1s",  (uintmax_t)1*1000*1000,            &timescale_seconds, true, },
		{ "1m",  (uintmax_t)1*1000*1000*60,         &timescale_seconds, true, },
		{ "1h",  (uintmax_t)1*1000*1000*60*60,      &timescale_seconds, true, },
		{ "1d",  (uintmax_t)1*1000*1000*60*60*24,   &timescale_seconds, true, },
		{ "1w",  (uintmax_t)1*1000*1000*60*60*24*7, &timescale_seconds, true, },

		/* fractions */
		{ "1.234", (uintmax_t)1234*1000,            &timescale_seconds, true, },
		{ ".034",  (uintmax_t)  34*1000,            &timescale_seconds, true, },
		{ "2.",    (uintmax_t)2000*1000,            &timescale_seconds, true, },
		{ "0.1ms", (uintmax_t)      100,            &timescale_seconds, true, },
		{ "0.5m",  (uintmax_t)  30*1000*1000,       &timescale_seconds, true, },

		/* error */
		{ "",    (uintmax_t)0,                      &timescale_seconds, false, },
		{ "1x",  (uintmax_t)0,                      &timescale_milliseconds, false, },
		{ "x1",  (uintmax_t)0,                      &timescale_milliseconds, false, },
		{ "1mm", (uintmax_t)0,                      &timescale_milliseconds, false, },
		{ "1seconds", (uintmax_t)0,                 &timescale_milliseconds, false, },
		{ "1 s", (uintmax_t)0,                      &timescale_milliseconds, false, },
		{ "0x10", (uintmax_t)0,                     &timescale_seconds, false, },
		{ "0.1",  (uintmax_t)0,                     &timescale_microseconds, false, },
		{ "0.1x", (uintmax_t)0,                     &timescale_seconds, false, },
		{ ".ms",  (uintmax_t)0,                     &timescale_seconds, false, },
		{ ".",  (uintmax_t)0,                       &timescale_seconds, false, },
	};

	for (unsigned i = 0; i < elemsof(test_ttodeltatime); i++) {
		const struct test_ttodeltatime *t = &test_ttodeltatime[i];
		fprintf(stdout, "ttodeltatime(%s, "PRI_TIMESCALE") ok=%s\n",
			t->str, pri_timescale(*t->scale), bool_str(t->ok));
		deltatime_t d;
		diag_t diag = ttodeltatime(t->str, &d, t->scale);
		if (t->ok) {
			if (diag != NULL) {
				fprintf(stderr, "FAIL: ttodeltatime(%s, "PRI_TIMESCALE") unexpectedly returned: %s\n",
					t->str, pri_timescale(*t->scale), str_diag(diag));
				fails++;
				return;
			}
		} else if (diag == NULL) {
			fprintf(stderr, "FAIL: ttodeltatime(%s, "PRI_TIMESCALE") unexpectedly succeeded\n",
				t->str, pri_timescale(*t->scale));
			fails++;
			return;
		} else {
			pfree_diag(&diag);
		}
		intmax_t microseconds = microseconds_from_deltatime(d);
		if (microseconds != t->us) {
			fprintf(stderr, "FAIL: ttodeltatime(%s, "PRI_TIMESCALE") returned %jd, expecting %jd\n",
				t->str, pri_timescale(*t->scale), microseconds, t->us);
			fails++;
			return;
		}
	}

}

void check_deltatime(void)
{
	char what[1000];

	static const struct test_str_deltatime {
		intmax_t ms;
		const char *str;
	} test_str_deltatime[] = {
		{  1000, "1" },
		{ -1000, "-1" },
		{ - 100,  "-0.1" },
	};
	for (unsigned i = 0; i < elemsof(test_str_deltatime); i++) {
		const struct test_str_deltatime *t = &test_str_deltatime[i];
		deltatime_t d = deltatime_from_milliseconds(t->ms);
		deltatime_buf buf;
		const char *str = str_deltatime(d, &buf);
		snprintf(what, sizeof(what), "str_deltatime(%jdms) == %s", t->ms, t->str);
		if (strcmp(str, t->str) != 0) {
			fprintf(stderr, "FAIL: %s vs %s\n", what, str);
			fails++;
		} else {
			printf("%s\n", what);
		}
	}

	static const struct test_op test_deltatime_max[] = {
		{  1000,  100, "1" },
		{ -1000,    0, "0" },
		{ - 100, -200, "-0.1" },
	};
	CHECK_DELTATIME_OP(max);

	static const struct test_op test_deltatime_min[] = {
		{  1000,  100, "0.1" },
		{ -1000,    0, "-1" },
		{ - 100, -200, "-0.2" },
	};
	CHECK_DELTATIME_OP(min);

	static const struct test_op test_deltatime_add[] = {
		{  1000,  100, "1.1" },
		{ -1000,    0, "-1" },
		{ - 100, -200, "-0.3" },
	};
	CHECK_DELTATIME_OP(add);

	static const struct test_op test_deltatime_sub[] = {
		{  1000,  100, "0.9" },
		{ -1000,    0, "-1" },
		{ - 100, -200, "0.1" },
	};
	CHECK_DELTATIME_OP(sub);

	CHECK_TIME_CMP_SECONDS(deltatime);
	CHECK_TIME_CMP_MILLISECONDS(deltatime);

	check_ttodeltatime();

}
