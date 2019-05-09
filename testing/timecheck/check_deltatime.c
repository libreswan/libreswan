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

#include "constants.h"		/* for elemsof() */
#include "deltatime.h"

#include "timecheck.h"

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
			fail++;
		} else {
			printf("%s\n", what);
		}
	}

	static const struct test_deltatime_max {
		intmax_t lms, rms;
		const char *str;
	} test_deltatime_max[] = {
		{  1000,  100, "1" },
		{ -1000,    0, "0" },
		{ - 100, -200, "-0.1" },
	};
	for (unsigned i = 0; i < elemsof(test_deltatime_max); i++) {
		const struct test_deltatime_max *t = &test_deltatime_max[i];
		deltatime_t l = deltatime_ms(t->lms);
		deltatime_t r = deltatime_ms(t->rms);
		deltatime_buf buf;
		const char *str = str_deltatime(deltatime_max(l, r), &buf);
		snprintf(what, sizeof(what), "str_deltatime(deltatime_max(%jdms, %jdms)) == %s", t->lms, t->rms, t->str);
		if (strcmp(str, t->str) != 0) {
			fprintf(stderr, "FAIL: %s vs %s\n", what, str);
			fail++;
		} else {
			printf("%s\n", what);
		}
	}

	static const struct test_deltaless {
		intmax_t lms, rms;
		bool less;
	} test_deltaless[] = {
		{  1000,  100, false },
		{ -1000,    0, true },
		{  -100, -200, false },
	};
	for (unsigned i = 0; i < elemsof(test_deltaless); i++) {
		const struct test_deltaless *t = &test_deltaless[i];
		deltatime_t l = deltatime_ms(t->lms);
		deltatime_t r = deltatime_ms(t->rms);
		bool less = deltaless(l, r);
		snprintf(what, sizeof(what), "deltaless(%jdms, %jdms) == %s", t->lms, t->rms, t->less ? "true" : "false");
		if (less != t->less) {
			fprintf(stderr, "FAIL: %s vs %s\n", what, less ? "true" : "false");
			fail++;
		} else {
			printf("%s\n", what);
		}
	}
}
