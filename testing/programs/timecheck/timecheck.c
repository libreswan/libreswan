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

#include "lswcdefs.h"	/* for UNUSED */

#include "lswalloc.h"		/* for leaks */
#include "lswtool.h"		/* for tool_init_log() */

#include "timecheck.h"

const struct time_cmp time_cmp[] = {
	/* Milliseconds */
	{ 1, 1, .eq = true, .le = true, .ge = true, },
	{ 1, 2, .ne = true, .le = true, .lt = true, },
	{ 2, 1, .ne = true, .ge = true, .gt = true, },
	/* Seconds */
	{ 1000, 1000, .eq = true, .le = true, .ge = true, },
	{ 1000, 2000, .ne = true, .le = true, .lt = true, },
	{ 2000, 1000, .ne = true, .ge = true, .gt = true, },
	/* mixed */
	{ 200, 1000, .ne = true, .le = true, .lt = true, },
	{ 1000, 200, .ne = true, .ge = true, .gt = true, },
	{ .sentinel = true, },
};

int fails = 0;

int main(int argc UNUSED, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	check_deltatime();
	check_monotime();
	check_realtime();

	if (report_leaks(logger)) {
		fails++;
	}


	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	}

	return 0;
}
