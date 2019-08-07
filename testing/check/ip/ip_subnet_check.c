/*
 * convert from text form of subnet specification to binary
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2018  Andrew Cagney
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
#include "ip_subnet.h"

static void check_str_subnet(void)
{
	static const struct test {
		int family;
		char *in;
		char *out;	/* NULL means error expected */
	} tests[] = {
		{ 4, "1.2.3.0/255.255.255.0", "1.2.3.0/24" },
		{ 4, "1.2.3.0/24", "1.2.3.0/24" },
#if 0
		{ 4, "1.2.3.0/24:10", "1.2.3.0/24:10" },
		{ 4, "1.2.3.0/24:-1", NULL },
		{ 4, "1.2.3.0/24:none", NULL },
		{ 4, "1.2.3.0/24:", NULL },
		{ 4, "1.2.3.0/24:0x10", "1.2.3.0/24:16" },
		{ 4, "1.2.3.0/24:0X10", "1.2.3.0/24:16" },
		{ 4, "1.2.3.0/24:010", "1.2.3.0/24:8" },
#endif
		{ 4, "1.2.3.1/255.255.255.240", "1.2.3.0/28" },
		{ 4, "1.2.3.1/32", "1.2.3.1/32" },
		{ 4, "1.2.3.1/0", "0.0.0.0/0" },
/*	{4, "1.2.3.1/255.255.127.0",	"1.2.3.0/255.255.127.0"}, */
		{ 4, "1.2.3.1/255.255.127.0", NULL },
		{ 4, "128.009.000.032/32", "128.9.0.32/32" },
		{ 4, "128.0x9.0.32/32", NULL },
		{ 4, "0x80090020/32", "128.9.0.32/32" },
		{ 4, "0x800x0020/32", NULL },
		{ 4, "128.9.0.32/0xffFF0000", "128.9.0.0/16" },
		{ 4, "128.9.0.32/0xff0000FF", NULL },
		{ 4, "128.9.0.32/0x0000ffFF", NULL },
		{ 4, "128.9.0.32/0x00ffFF0000", NULL },
		{ 4, "128.9.0.32/0xffFF", NULL },
		{ 4, "128.9.0.32.27/32", NULL },
		{ 4, "128.9.0k32/32", NULL },
		{ 4, "328.9.0.32/32", NULL },
		{ 4, "128.9..32/32", NULL },
		{ 4, "10/8", "10.0.0.0/8" },
		{ 4, "10.0/8", "10.0.0.0/8" },
		{ 4, "10.0.0/8", "10.0.0.0/8" },
		{ 4, "10.0.1/24", "10.0.1.0/24" },
		{ 4, "_", NULL },
		{ 4, "_/_", NULL },
		{ 4, "1.2.3.1", NULL },
		{ 4, "1.2.3.1/_", NULL },
		{ 4, "1.2.3.1/24._", NULL },
		{ 4, "1.2.3.1/99", NULL },
		{ 4, "localhost/32", NULL },
		{ 4, "%default", "0.0.0.0/0" },
		{ 6, "3049:1::8007:2040/0", "::/0" },
		{ 6, "3049:1::8007:2040/128", "3049:1::8007:2040/128" },
		{ 6, "3049:1::192.168.0.1/128", NULL },	/*"3049:1::c0a8:1/128",*/
		{ 6, "3049:1::8007::2040/128", NULL },
		{ 6, "3049:1::8007:2040/ffff:0", NULL },
		{ 6, "3049:1::8007:2040/64", "3049:1::/64" },
#if 0
		{ 6, "3049:1::8007:2040/64:53", "3049:1::/64:53" },
#endif
		{ 6, "3049:1::8007:2040/ffff:", NULL },
		{ 6, "3049:1::8007:2040/0000:ffff::0", NULL },
		{ 6, "3049:1::8007:2040/ff1f:0", NULL },
		{ 6, "3049:1::8007:x:2040/128", NULL },
		{ 6, "3049:1t::8007:2040/128", NULL },
		{ 6, "3049:1::80071:2040/128", NULL },
		{ 6, "::/21", "::/21" },
		{ 6, "::1/128", "::1/128" },
		{ 6, "1::/21", "1::/21" },
		{ 6, "1::2/128", "1::2/128" },
		{ 6, "1:0:0:0:0:0:0:2/128", "1::2/128" },
		{ 6, "1:0:0:0:3:0:0:2/128", "1::3:0:0:2/128" },
		{ 6, "1:0:0:3:0:0:0:2/128", "1:0:0:3::2/128" },
		{ 6, "1:0:3:0:0:0:0:2/128", "1:0:3::2/128" },
		{ 6, "abcd:ef01:2345:6789:0:00a:000:20/128",
		  "abcd:ef01:2345:6789:0:a:0:20/128" },
		{ 6, "3049:1::8007:2040/ffff:ffff:", NULL },
		{ 6, "3049:1::8007:2040/ffff:88:", NULL },
		{ 6, "3049:12::9000:3200/ffff:fff0", NULL },
		{ 6, "3049:12::9000:3200/28", "3049:10::/28" },
		{ 6, "3049:12::9000:3200/ff00:", NULL },
		{ 6, "3049:12::9000:3200/ffff:", NULL },
		{ 6, "3049:12::9000:3200/128_", NULL },
		{ 6, "3049:12::9000:3200/", NULL },
		{ 6, "%default", "::/0" },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> '%s'",
			 t->out ? t->out : "<error>");

		sa_family_t af = SA_FAMILY(t->family);

		ip_subnet s;
		oops = ttosubnet(t->in, 0, af, &s);
		if (oops != NULL && t->out == NULL) {
			/* Error was expected, do nothing */
			continue;
		} else if (oops != NULL && t->out != NULL) {
			/* Error occurred, but we didn't expect one  */
			FAIL_IN("ttosubnet failed: %s", oops);
		} else if (oops == NULL && t->out == NULL) {
			/* If no errors, but we expected one */
			FAIL_IN("ttosubnet succeeded unexpectedly");
		}

		subnet_buf buf;
		const char *out = str_subnet(&s, &buf);
		if (!streq(t->out, out)) {
			FAIL_IN("subnetporttot returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_subnet_mashup(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *mask;
		const char *floor;
		const char *ceiling;
	} tests[] = {
		{ 4, "1.2.3.4/1", "128.0.0.0", "0.0.0.0", "127.255.255.255", },
		{ 4, "1.2.3.4/23", "255.255.254.0", "1.2.2.0", "1.2.3.255", },
		{ 4, "1.2.3.4/24", "255.255.255.0", "1.2.3.0", "1.2.3.255", },
		{ 4, "1.2.3.4/25", "255.255.255.128", "1.2.3.0", "1.2.3.127", },
		{ 4, "1.2.3.4/31", "255.255.255.254", "1.2.3.4", "1.2.3.5", },
		{ 4, "1.2.3.4/32", "255.255.255.255", "1.2.3.4", "1.2.3.4", },
		{ 6, "1:2:3:4:5:6:7:8/1", "8000::", "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
		{ 6, "1:2:3:4:5:6:7:8/63", "ffff:ffff:ffff:fffe::", "1:2:3:4::", "1:2:3:5:ffff:ffff:ffff:ffff", },
		{ 6, "1:2:3:4:5:6:7:8/64", "ffff:ffff:ffff:ffff::", "1:2:3:4::", "1:2:3:4:ffff:ffff:ffff:ffff", },
		{ 6, "1:2:3:4:5:6:7:8/65", "ffff:ffff:ffff:ffff:8000::", "1:2:3:4::", "1:2:3:4:7fff:ffff:ffff:ffff" },
		{ 6, "1:2:3:4:5:6:7:8/127", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", },
		{ 6, "1:2:3:4:5:6:7:8/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> mask: %s floor: %s ceiling: %s",
			 t->mask, t->floor, t->ceiling);

		sa_family_t af = SA_FAMILY(t->family);

		ip_subnet s;
		err_t oops = ttosubnet(t->in, 0, af, &s);
		if (oops != NULL) {
			FAIL_IN("ttosubnet() failed: %s", oops);
		}

		address_buf buf;
		const char *out;

		ip_address mask = subnet_mask(&s);
		out = str_address(&mask, &buf);
		if (!streq(t->mask, out)) {
			FAIL_IN("subnet_mask() returned '%s', expected '%s'",
				out, t->mask);
		}

		ip_address floor = subnet_floor(&s);
		out = str_address(&floor, &buf);
		if (!streq(t->floor, out)) {
			FAIL_IN("subnet_floor() returned '%s', expected '%s'",
				out, t->floor);
		}

		ip_address ceiling = subnet_ceiling(&s);
		out = str_address(&ceiling, &buf);
		if (!streq(t->ceiling, out)) {
			FAIL_IN("subnet_ceiling() returned '%s', expected '%s'",
				out, t->ceiling);
		}
	}
}

void ip_subnet_check(void)
{
	check_str_subnet();
	check_subnet_mashup();
}
