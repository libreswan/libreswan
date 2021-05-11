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

int fails = 0;

int main(int argc UNUSED, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_init_log(argv[0]);

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
