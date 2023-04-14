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
#include "monotime.h"
#include "timecheck.h"
#include "constants.h"		/* for bool_str() !!!! */

/* monotime(monotime,deltatime) - mmd */

struct test_op {
	intmax_t l, r;
	intmax_t o;
};

#define CHECK_MMM_OP(OP)						\
	check_mmm_op(test_monotime_##OP,				\
		     elemsof(test_monotime_##OP),			\
		     monotime_##OP, #OP)

static void check_mmm_op(const struct test_op *tests,
			       size_t nr_tests,
			       monotime_t (*op)(monotime_t, monotime_t),
			       const char *op_name)
{
	for (unsigned i = 0; i < nr_tests; i++) {
		const struct test_op *t = &tests[i];
		monotime_t l = monotime(t->l);
		monotime_t r = monotime(t->r);
		intmax_t o = monosecs(op(l, r));
		FILE *out = (o == t->o) ? stdout : stderr;
		fprintf(out, "monosecs(monotime_%s(%jd, %jd)) == %jd",
			op_name, t->l, t->r, t->o);
		if (out == stderr) {
			fprintf(out, "; FAIL: returned %jd", o);
			fails++;
		}
		fprintf(out, "\n");
	}
}

#define CHECK_MMD_OP(OP)						\
	check_mmd_op(test_monotime_##OP,				\
		     elemsof(test_monotime_##OP),			\
		     monotime_##OP, #OP)

static void check_mmd_op(const struct test_op *tests,
			       size_t nr_tests,
			       monotime_t (*op)(monotime_t, deltatime_t),
			       const char *op_name)
{
	for (unsigned i = 0; i < nr_tests; i++) {
		const struct test_op *t = &tests[i];
		monotime_t l = monotime(t->l);
		deltatime_t r = deltatime(t->r);
		intmax_t o = monosecs(op(l, r));
		FILE *out = (o == t->o) ? stdout : stderr;
		fprintf(out, "monosecs(monotime_%s(%jd, %jd)) == %jd",
			op_name, t->l, t->r, t->o);
		if (out == stderr) {
			fprintf(out, "; FAIL: returned %jd", o);
			fails++;
		}
		fprintf(out, "\n");
	}
}

/* bool(monotime,deltatime) - bmm */

void check_monotime(void)
{
	char what[1000];

	static const struct test_monotimediff {
		intmax_t l, r;
		const char *diff;
	} test_monotimediff[] = {
		{ 1, 1, "0", },
		{ 2, 1, "1", },
		{ 1, 2, "-1", },
	};
	for (unsigned i = 0; i < elemsof(test_monotimediff); i++) {
		const struct test_monotimediff *t = &test_monotimediff[i];
		monotime_t l = monotime(t->l);
		monotime_t r = monotime(t->r);
		deltatime_t d = monotimediff(l, r);
		deltatime_buf buf;
		const char *str = str_deltatime(d, &buf);

		snprintf(what, sizeof(what), "monotime(%jd) - monotime(%jd) = %s", t->l, t->r, t->diff);
		if (strcmp(str, t->diff) != 0) {
			fprintf(stderr, "FAIL: %s vs %s\n", what, str);
			fails++;
		} else {
			printf("%s\n", what);
		}
	}

	CHECK_TIME_CMP(mono);

	static const struct test_op test_monotime_min[] = {
		{  1000,  100,  100 },
		{  1000,    0,    0 },
		{   200,  400,  200 },
	};
	CHECK_MMM_OP(min);

	static const struct test_op test_monotime_max[] = {
		{  1000,  100, 1000 },
		{  1000,    0, 1000 },
		{   200,  400,  400 },
	};
	CHECK_MMM_OP(max);

	static const struct test_op test_monotime_add[] = {
		{  1000,  100, 1100 },
		{  1000,    0, 1000 },
		{  1000, -200,  800 },
	};
	CHECK_MMD_OP(add);

	static const struct test_op test_monotime_sub[] = {
		{  1000,  100,  900 },
		{  1000,    0, 1000 },
		{  1000, -200, 1200 },
	};
	CHECK_MMD_OP(sub);

}
