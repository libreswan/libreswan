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
		char format;
		char *in;
		char *out;	/* NULL means error expected */
		bool fudge;
	} tests[] = {
		{ 0, "esp257@1.2.3.0", "esp.101@1.2.3.0" },
		{ 0, "ah0x20@1.2.3.4", "ah.20@1.2.3.4" },
		{ 0, "tun20@1.2.3.4", "tun.14@1.2.3.4" },
		{ 0, "comp20@1.2.3.4", "comp.14@1.2.3.4" },
		{ 0, "esp257@::1", "esp:101@::1" },
		{ 0, "esp257@0bc:12de::1", "esp:101@bc:12de::1" },
		{ 0, "esp78@1049:1::8007:2040", "esp:4e@1049:1::8007:2040" },
		{ 0, "esp0x78@1049:1::8007:2040", "esp:78@1049:1::8007:2040" },
		{ 0, "ah78@1049:1::8007:2040", "ah:4e@1049:1::8007:2040" },
		{ 0, "ah0x78@1049:1::8007:2040", "ah:78@1049:1::8007:2040" },
		{ 0, "tun78@1049:1::8007:2040", "tun:4e@1049:1::8007:2040" },
		{ 0, "tun0x78@1049:1::8007:2040", "tun:78@1049:1::8007:2040" },
		{ 0, "duk99@3ffe:370:400:ff::9001:3001", NULL },
		{ 0, "esp78x@1049:1::8007:2040", NULL },
		{ 0, "esp0x78@1049:1:0xfff::8007:2040", NULL },
		{ 0, "es78@1049:1::8007:2040", NULL },
		{ 0, "", NULL },
		{ 0, "_", NULL },
		{ 0, "ah2.2", NULL },
		{ 0, "goo2@1.2.3.4", NULL },
		{ 0, "esp9@1.2.3.4", "esp.9@1.2.3.4" },
		{ 0, "espp9@1.2.3.4", NULL },
		{ 0, "es9@1.2.3.4", NULL },
		{ 0, "ah@1.2.3.4", NULL },
		{ 0, "esp7x7@1.2.3.4", NULL },
		{ 0, "esp77@1.0x2.3.4", NULL },
		{ 0, PASSTHROUGHNAME, PASSTHROUGH4NAME },
		{ 0, PASSTHROUGH6NAME, PASSTHROUGH6NAME },
		{ 0, "%pass", "%pass" },
		{ 0, "int256@0.0.0.0", "%pass" },
		{ 0, "%drop", "%drop" },
		{ 0, "int257@0.0.0.0", "%drop" },
		{ 0, "%reject", "%reject" },
		{ 0, "int258@0.0.0.0", "%reject" },
		{ 0, "%hold", "%hold" },
		{ 0, "int259@0.0.0.0", "%hold" },
		{ 0, "%trap", "%trap" },
		{ 0, "int260@0.0.0.0", "%trap" },
		{ 0, "%trapsubnet", "%trapsubnet" },
		{ 0, "int261@0.0.0.0", "%trapsubnet" },
		/* was "int.106@0.0.0.0" */
		{ 0, "int262@0.0.0.0", "%unk-262" },
		{ 0, "esp9@1.2.3.4", "unk77.9@1.2.3.4", .fudge = true, },

		/* XXX: 'f' is never used!?! */
		{ 'f', "esp0xa9@1.2.3.4", "esp.000000a9@1.2.3.4" },
		/* XXX: 'x' is only used once and in some strange pfkey code */
		{ 'x', "esp0xa9@1.2.3.4", "esp0xa9@1.2.3.4" },

		/* buffer size? */
		{ 0, "esp.3a7292a2@192.1.2.24", "esp.3a7292a2@192.1.2.24" },
		{ 0, "esp:3a7292a2@1000:2000:3000:4000:5000:6000:7000:8000", "esp:3a7292a2@1000:2000:3000:4000:5000:6000:7000:8000", },
		{ 'x', "esp0x3a7292a2@192.1.2.24", "esp0x3a7292a2@192.1.2.24" },
		{ 'x', "esp0x3a7292a2@1000:2000:3000:4000:5000:6000:7000:8000", "esp0x3a7292a2@1000:2000:3000:4000:5000:6000:7000:8000", },
	};

#define PRINT_SA(FILE, FMT, ...)					\
	PRINT(FILE, " '%s' format: '%c' fudge: %s"FMT,			\
	      t->in, t->format != 0 ? t->format : '0',			\
	      bool_str(t->fudge),##__VA_ARGS__);

#define FAIL_SA(FMT, ...)						\
	{								\
		fails++;						\
		PRINT_SA(stderr, " "FMT" (%s() %s:%d)",##__VA_ARGS__,	\
			 __func__, __FILE__, __LINE__);			\
		continue;						\
	}

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_SA(stdout, "");

		/* convert it *to* internal format */
		ip_said sa;
		err_t err = ttosa(t->in, strlen(t->in), &sa);
		if (err != NULL) {
			if (t->out != NULL) {
				FAIL_SA("ttosa() unexpectedly failed: %s", err);
			} else {
				/* all is good */
				continue;
			}
		} else if (t->out == NULL) {
			FAIL_SA("ttosa() unexpectedly succeeded");
		}

		if (t->fudge) {
			sa.proto = 77;
		}

		/* now convert it back */
		said_buf buf;
		const char *out = str_said(&sa, t->format, &buf);
		if (out == NULL) {
			FAIL_SA("str_said() failed");
		} else if (!strcaseeq(t->out, out)) {
			FAIL_SA("str_said() returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

void ip_said_check(void)
{
	check_str_said();
}
