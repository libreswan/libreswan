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

#include "realtime.h"
#include "timecheck.h"
#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for bool_str() */

void check_realtime(void)
{
	char what[1000];

	static const struct test_realtimediff {
		intmax_t l, r;
		const char *diff;
	} test_realtimediff[] = {
		{ 1, 1, "0", },
		{ 2, 1, "1", },
		{ 1, 2, "-1", },
	};
	for (unsigned i = 0; i < elemsof(test_realtimediff); i++) {
		const struct test_realtimediff *t = &test_realtimediff[i];
		realtime_t l = realtime(t->l);
		realtime_t r = realtime(t->r);
		deltatime_t d = realtime_diff(l, r);
		deltatime_buf buf;
		const char *str = str_deltatime(d, &buf);

		snprintf(what, sizeof(what), "realtime(%jd) - realtime(%jd) = %s", t->l, t->r, t->diff);
		if (strcmp(str, t->diff) != 0) {
			fprintf(stderr, "FAIL: %s vs %s\n", what, str);
			fails++;
		} else {
			printf("%s\n", what);
		}
	}

	CHECK_TIME_CMP_SECONDS(realtime, /*UTC?*/false);
}
