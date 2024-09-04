/* ip_address tests, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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
#include "constants.h"		/* for streq() */
#include "ip_port_range.h"

#include "ipcheck.h"

void ip_port_range_check(void)
{
	static const struct test {
		int line;
		unsigned lo, hi;
		const char *out;
	} tests[] = {
		{ LN, 4, 4, "4", },
		{ LN, 4, 8, "4-8", },
	};
	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("ports=%u-%u out=%s", t->lo, t->hi, t->out);

		ip_port lo = ip_hport(t->lo);
		ip_port hi = ip_hport(t->hi);
		ip_port_range pr = port_range_from_ports(lo, hi);

		port_range_buf prb;
		if (!streq(t->out, str_port_range(pr, &prb))) {
			FAIL("str_port_range() returned %s, expecting %s",
			     prb.buf, t->out);
		}
	}
}
