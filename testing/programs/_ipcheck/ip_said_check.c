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

static void check__ttosaid__str_said(void)
{
	static const struct test {
		int line;
		char *in;
		char *out;	/* NULL means error expected */
	} tests[] = {
		/* all known prefixes */
		{ LN, "icmp.1@1.2.3.0", "icmp.1@1.2.3.0", },
		{ LN, "tun.4@1.2.3.0", "tun.4@1.2.3.0", },
		{ LN, "tcp.6@1.2.3.0", "tcp.6@1.2.3.0", },
		{ LN, "udp.17@1.2.3.0", "udp.17@1.2.3.0", },
		{ LN, "esp.50@1.2.3.0", "esp.50@1.2.3.0", },
		{ LN, "ah.51@1.2.3.0", "ah.51@1.2.3.0", },
		{ LN, "comp.108@1.2.3.0", "comp.108@1.2.3.0", },
		/* number conversion */
		{ LN, "tun20@1.2.3.4", "tun.14@1.2.3.4", },
		{ LN, "esp257@1.2.3.0", "esp.101@1.2.3.0", },
		{ LN, "ah0x20@1.2.3.4", "ah.20@1.2.3.4", },
		{ LN, "comp20@1.2.3.4", "comp.14@1.2.3.4", },
		{ LN, "esp257@::1", "esp:101@::1", },
		{ LN, "esp257@0bc:12de::1", "esp:101@bc:12de::1", },
		{ LN, "esp78@1049:1::8007:2040", "esp:4e@1049:1::8007:2040", },
		{ LN, "esp0x78@1049:1::8007:2040", "esp:78@1049:1::8007:2040", },
		{ LN, "ah78@1049:1::8007:2040", "ah:4e@1049:1::8007:2040", },
		{ LN, "ah0x78@1049:1::8007:2040", "ah:78@1049:1::8007:2040", },
		{ LN, "tun78@1049:1::8007:2040", "tun:4e@1049:1::8007:2040", },
		{ LN, "tun0x78@1049:1::8007:2040", "tun:78@1049:1::8007:2040", },
		{ LN, "duk99@3ffe:370:400:ff::9001:3001", NULL, },
		{ LN, "esp78x@1049:1::8007:2040", NULL, },
		{ LN, "esp0x78@1049:1:0xfff::8007:2040", NULL, },
		{ LN, "es78@1049:1::8007:2040", NULL, },
		{ LN, "", NULL, },
		{ LN, "_", NULL, },
		{ LN, "ah2.2", NULL, },
		{ LN, "goo2@1.2.3.4", NULL, },
		{ LN, "esp9@1.2.3.4", "esp.9@1.2.3.4", },
		{ LN, "espp9@1.2.3.4", NULL, },
		{ LN, "es9@1.2.3.4", NULL, },
		{ LN, "ah@1.2.3.4", NULL, },
		{ LN, "esp7x7@1.2.3.4", NULL, },
		{ LN, "esp77@1.0x02.0003.4", "esp.4d@1.2.3.4", },
		{ LN, "esp77@1.0x0g.3.4", NULL, },
		{ LN, PASSTHROUGHNAME, PASSTHROUGH4NAME, },
		{ LN, PASSTHROUGH6NAME, PASSTHROUGH6NAME, },

		/* buffer size? */
		{ LN, "esp.3a7292a2@192.1.2.24", "esp.3a7292a2@192.1.2.24", },
		{ LN, "esp:3a7292a2@1000:2000:3000:4000:5000:6000:7000:8000", "esp:3a7292a2@1000:2000:3000:4000:5000:6000:7000:8000", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];

		/* convert it *to* internal format */
		ip_said sa;
		diag_t d = ttosaid(shunk1(t->in), &sa);
		if (d != NULL) {
			if (t->out != NULL) {
				DIAG_FAIL(&d, "ttosaid(%s) unexpectedly failed: ", t->in);
			} else {
				/* all is good */
				pfree_diag(&d);
				continue;
			}
		} else if (t->out == NULL) {
			FAIL("ttosa(%s) unexpectedly succeeded", t->in);
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
	check__ttosaid__str_said();
}
