/* test subnets, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2018, 2019  Andrew Cagney
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
 */

#include <stdio.h>

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for streq() */
#include "ipcheck.h"
#include "ip_cidr.h"

static void check_numeric_to_cidr(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *out;
	} tests[] = {
		{ 4, "128.0.0.0/0", "128.0.0.0/0", },
		{ 6, "8000::/0", "8000::/0", },

		{ 4, "128.0.0.0/1", "128.0.0.0/1", },
		{ 6, "8000::/1", "8000::/1", },

		{ 4, "1.2.255.4/23", "1.2.255.4/23", },
		{ 4, "1.2.255.255/24", "1.2.255.255/24", },
		{ 4, "1.2.3.255/25", "1.2.3.255/25", },

		{ 6, "1:2:3:ffff::/63", "1:2:3:ffff::/63", },
		{ 6, "1:2:3:ffff:ffff::/64", "1:2:3:ffff:ffff::/64", },
		{ 6, "1:2:3:4:ffff::/65", "1:2:3:4:ffff::/65", },

		{ 4, "1.2.3.255/31", "1.2.3.255/31", },
		{ 4, "1.2.3.255/32", "1.2.3.255/32", },
		{ 6, "1:2:3:4:5:6:7:ffff/127", "1:2:3:4:5:6:7:ffff/127", },
		  { 6, "1:2:3:4:5:6:7:ffff/128", "1:2:3:4:5:6:7:ffff/128", },

		{ 4, "1.2.3.4", NULL, },
		{ 6, "1:2:3:4:5:6:7:8", NULL, },
		{ 4, "1.2.3.255/33", NULL, },
		{ 6, "1:2:3:4:5:6:7:ffff/129", NULL, },
	};

#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s %s "FMT,					\
	      t->in,							\
	      t->out != NULL ? t->out : "ERROR",			\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		OUT(stdout, "");

		ip_cidr cidr;
		err_t err = numeric_to_cidr(shunk1(t->in), IP_TYPE(t->family), &cidr);
		if (err != NULL) {
			if (t->out != NULL) {
				FAIL(OUT, "numeric_to_cidr() unexpectedly failed: %s", err);
			}
			continue;
		} else if (t->out == NULL) {
			FAIL(OUT, "numeric_to_cidr() unexpectedly succeeded");
		}

		CHECK_TYPE(OUT, cidr_type(&cidr));

		cidr_buf outb;
		const char *out = str_cidr(&cidr, &outb);
		if (!streq(out, t->out)) {
			FAIL(OUT, "str_cidr() returned '%s', expected '%s'",
			     out, t->out);
		}
#undef OUT
	}
}

void ip_cidr_check(void)
{
	check_numeric_to_cidr();
}
