/* ip_endpoint tests, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2018 Andrew Cagney
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

#include "stdio.h"

#include "constants.h"		/* for elemsof() */
#include "ip_endpoint.h"

#include "ipcheck.h"

static void check_str_endpoint(void)
{
	struct test {
		const char *input;
		const char *output;
	};
	static const struct test tests[] = {
		/* anything else? */
		{ "1.2.3.4",			"1.2.3.4:65535" },
		{ "255.255.255.255",		"255.255.255.255:65535" },
		{ "1:12:3:14:5:16:7:18",	"[1:12:3:14:5:16:7:18]:65535" },
		{ "11:22:33:44:55:66:77:88",	"[11:22:33:44:55:66:77:88]:65535" },
		/* treat special different ? */
		{ "0:0:0:0:0:0:0:1",		"[::1]:65535" },
		{ "0:0:0:0:0:0:0:0",		"[::]:65535" },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		IPRINT(stdout, "-> '%s'", t->output);

		/* convert it *to* internal format */
		ip_address a;
		err_t err = ttoaddr(t->input, strlen(t->input), AF_UNSPEC, &a);
		if (err != NULL) {
			IFAIL("%s", err);
			continue;
		}
		ip_endpoint e = endpoint(&a, 65535);

		/* now convert it back */
		ip_endpoint_buf buf;
		const char *out = str_endpoint(&e, &buf);
		if (out == NULL) {
			IFAIL("failed");
		} else if (!strcaseeq(t->output, out)) {
			IFAIL("returned '%s', expected '%s'",
			      out, t->output);
		}
	}
}

void ip_endpoint_check(void)
{
	check_str_endpoint();
}
