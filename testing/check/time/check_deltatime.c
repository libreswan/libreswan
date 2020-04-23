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

#include "lswcdefs.h"		/* for elemsof() */
#include "deltatime.h"
#include "timecheck.h"
#include "constants.h"		/* for bool_str() */

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
		deltatime_t l = deltatime_ms(t->lms);
		deltatime_t r = deltatime_ms(t->rms);
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
		deltatime_t d = deltatime_ms(t->ms);
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

	static const struct test_deltatime_cmp {
		intmax_t lms, rms;
		bool lt, le, eq, ge, gt, ne;
	} test_deltaless[] = {
		{  1000,  100, false, false, false, true,  true,  true, },
		{ -1000,    0, true,  true,  false, false, false, true, },
		{     0,    0, false, true,  true,  true,  false, false, },
		{  -100, -200, false, false, false, true,  true,  true, },
	};
	for (unsigned i = 0; i < elemsof(test_deltaless); i++) {
		const struct test_deltatime_cmp *t = &test_deltaless[i];
		deltatime_t l = deltatime_ms(t->lms);
		deltatime_t r = deltatime_ms(t->rms);
#define CMP(OP, F)							\
		{							\
			bool op = deltatime_cmp(l, OP, r);		\
			snprintf(what, sizeof(what),			\
				 "deltatime_cmp(%jdms, %s, %jdms) == %s", \
				 t->lms, #OP, t->rms, bool_str(t->F));	\
			if (op != t->F) {				\
				fprintf(stderr, "FAIL: %s vs %s\n", what, bool_str(op)); \
				fails++;				\
			} else {					\
				printf("%s\n", what);			\
			}						\
		}
		CMP(<,  lt);
		CMP(<=, le);
		CMP(==, eq);
		CMP(>=, ge);
		CMP(>, gt);
		CMP(!=, ne);
	}
}
