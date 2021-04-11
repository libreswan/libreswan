/* ip_said tests, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
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

#include "ip_said.h"
#include "ipcheck.h"

static void check_str_said(void)
{
	static const struct test {
		int line;
		char *in;
		char *out;	/* NULL means error expected */
		bool fudge;
	} tests[] = {
		{ LN, "esp257@1.2.3.0", "esp.101@1.2.3.0", false, },
		{ LN, "ah0x20@1.2.3.4", "ah.20@1.2.3.4", false, },
		{ LN, "tun20@1.2.3.4", "tun.14@1.2.3.4", false, },
		{ LN, "comp20@1.2.3.4", "comp.14@1.2.3.4", false, },
		{ LN, "esp257@::1", "esp:101@::1", false, },
		{ LN, "esp257@0bc:12de::1", "esp:101@bc:12de::1", false, },
		{ LN, "esp78@1049:1::8007:2040", "esp:4e@1049:1::8007:2040", false, },
		{ LN, "esp0x78@1049:1::8007:2040", "esp:78@1049:1::8007:2040", false, },
		{ LN, "ah78@1049:1::8007:2040", "ah:4e@1049:1::8007:2040", false, },
		{ LN, "ah0x78@1049:1::8007:2040", "ah:78@1049:1::8007:2040", false, },
		{ LN, "tun78@1049:1::8007:2040", "tun:4e@1049:1::8007:2040", false, },
		{ LN, "tun0x78@1049:1::8007:2040", "tun:78@1049:1::8007:2040", false, },
		{ LN, "duk99@3ffe:370:400:ff::9001:3001", NULL, false, },
		{ LN, "esp78x@1049:1::8007:2040", NULL, false, },
		{ LN, "esp0x78@1049:1:0xfff::8007:2040", NULL, false, },
		{ LN, "es78@1049:1::8007:2040", NULL, false, },
		{ LN, "", NULL, false, },
		{ LN, "_", NULL, false, },
		{ LN, "ah2.2", NULL, false, },
		{ LN, "goo2@1.2.3.4", NULL, false, },
		{ LN, "esp9@1.2.3.4", "esp.9@1.2.3.4", false, },
		{ LN, "espp9@1.2.3.4", NULL, false, },
		{ LN, "es9@1.2.3.4", NULL, false, },
		{ LN, "ah@1.2.3.4", NULL, false, },
		{ LN, "esp7x7@1.2.3.4", NULL, false, },
		{ LN, "esp77@1.0x02.0003.4", "esp.4d@1.2.3.4", false, },
		{ LN, "esp77@1.0x0g.3.4", NULL, false, },
		{ LN, PASSTHROUGHNAME, PASSTHROUGH4NAME, false, },
		{ LN, PASSTHROUGH6NAME, PASSTHROUGH6NAME, false, },
		{ LN, "%pass", "%pass", false, },
		{ LN, "int256@0.0.0.0", "%pass", false, },
		{ LN, "%drop", "%drop", false, },
		{ LN, "int257@0.0.0.0", "%drop", false, },
		{ LN, "%reject", "%reject", false, },
		{ LN, "int258@0.0.0.0", "%reject", false, },
		{ LN, "%hold", "%hold", false, },
		{ LN, "int259@0.0.0.0", "%hold", false, },
		{ LN, "%trap", "%trap", false, },
		{ LN, "int260@0.0.0.0", "%trap", false, },
		{ LN, "%trapsubnet", "%trapsubnet", false, },
		{ LN, "int261@0.0.0.0", "%trapsubnet", false, },
		/* was "int.106@0.0.0.0" */
		{ LN, "int262@0.0.0.0", "%unk-262", false, },
		{ LN, "esp9@1.2.3.4", "unk.9@1.2.3.4", .fudge = true, },
		{ LN, "unk77.9@1.2.3.4", NULL, false, },

		/* buffer size? */
		{ LN, "esp.3a7292a2@192.1.2.24", "esp.3a7292a2@192.1.2.24", false, },
		{ LN, "esp:3a7292a2@1000:2000:3000:4000:5000:6000:7000:8000", "esp:3a7292a2@1000:2000:3000:4000:5000:6000:7000:8000", false, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("'%s' fudge: %s", t->in, bool_str(t->fudge));

		/* convert it *to* internal format */
		ip_said sa;
		err_t err = ttosa(t->in, strlen(t->in), &sa);
		if (err != NULL) {
			if (t->out != NULL) {
				FAIL("ttosa(%s) unexpectedly failed: %s", t->in, err);
			} else {
				/* all is good */
				continue;
			}
		} else if (t->out == NULL) {
			FAIL("ttosa(%s) unexpectedly succeeded", t->in);
		}

		if (t->fudge) {
			sa.proto = NULL;
		}

		/* now convert it back */
		said_buf buf;
		const char *out = str_said(&sa, &buf);
		if (out == NULL) {
			FAIL("str_said() failed");
		} else if (!strcaseeq(t->out, out)) {
			FAIL("str_said() returned '%s', expected '%s'", out, t->out);
		}
	}
}

void ip_said_check(void)
{
	check_str_said();
}
