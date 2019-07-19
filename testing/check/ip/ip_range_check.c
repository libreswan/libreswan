/* ip range tests, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2019  Andrew Cagney
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public
 * License for more details.
 */

#include <stdio.h>

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for streq() */
#include "ip_range.h"
#include "ip_subnet.h"
#include "ipcheck.h"

static void check_rangetosubnet(void)
{
	static const struct test {
		int family;
		const char *lo;
		const char *hi;
		const char *out;	/* NULL means error expected */
	} tests[] = {
		{ 4, "1.2.3.0", "1.2.3.255", "1.2.3.0/24" },
		{ 4, "1.2.3.0", "1.2.3.7", "1.2.3.0/29" },
		{ 4, "1.2.3.240", "1.2.3.255", "1.2.3.240/28" },
		{ 4, "0.0.0.0", "255.255.255.255", "0.0.0.0/0" },
		{ 4, "1.2.3.4", "1.2.3.4", "1.2.3.4/32" },
		{ 4, "1.2.3.0", "1.2.3.254", NULL },
		{ 4, "1.2.3.0", "1.2.3.126", NULL },
		{ 4, "1.2.3.0", "1.2.3.125", NULL },
		{ 4, "1.2.0.0", "1.2.255.255", "1.2.0.0/16" },
		{ 4, "1.2.0.0", "1.2.0.255", "1.2.0.0/24" },
		{ 4, "1.2.255.0", "1.2.255.255", "1.2.255.0/24" },
		{ 4, "1.2.255.0", "1.2.254.255", NULL },
		{ 4, "1.2.255.1", "1.2.255.255", NULL },
		{ 4, "1.2.0.1", "1.2.255.255", NULL },
		{ 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:ffff", "1:2:3:4:5:6:7:0/112" },
		{ 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:fff", "1:2:3:4:5:6:7:0/116" },
		{ 6, "1:2:3:4:5:6:7:f0", "1:2:3:4:5:6:7:ff", "1:2:3:4:5:6:7:f0/124" },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_LO2HI(stdout, "-> '%s'",
			    t->out ? t->out : "<error>");
		sa_family_t af = SA_FAMILY(t->family);
		const char *oops = NULL;

		ip_address lo;
		oops = ttoaddr(t->lo, 0, af, &lo);
		if (oops != NULL) {
			FAIL_LO2HI("ttoaddr(lo) failed: %s", oops);
			continue;
		}
		ip_address hi;
		oops = ttoaddr(t->hi, 0, af, &hi);
		if (oops != NULL) {
			FAIL_LO2HI("ttoaddr(hi) failed: %s", oops);
			continue;
		}
		ip_subnet subnet;
		oops = rangetosubnet(&lo, &hi, &subnet);
		if (oops != NULL && t->out == NULL) {
			/* okay, error expected */
		} else if (oops != NULL) {
			FAIL_LO2HI("rangetosubnet() failed: %s", oops);
			continue;
		} else if (t->out == NULL) {
			FAIL_LO2HI("rangetosubnet() succeeded unexpectedly");
			continue;
		} else {
			subnet_buf buf;
			const char *out = str_subnet(&subnet, &buf);
			if (!streq(t->out, out)) {
				FAIL_LO2HI("str_subnet() returned `%s', expected `%s'",
					   out, t->out);
				continue;
			}
		}
	}
}

static void check_iprange_bits(void)
{
	static const struct test {
		int family;
		const char *lo;
		const char *hi;
		int range;
	} tests[] = {
		{ 4, "1.2.255.0", "1.2.254.255", 1 },
		{ 4, "1.2.3.0", "1.2.3.7", 3 },
		{ 4, "1.2.3.0", "1.2.3.255", 8 },
		{ 4, "1.2.3.240", "1.2.3.255", 4 },
		{ 4, "0.0.0.0", "255.255.255.255", 32 },
		{ 4, "1.2.3.4", "1.2.3.4", 0 },
		{ 4, "1.2.3.0", "1.2.3.254", 8 },
		{ 4, "1.2.3.0", "1.2.3.126", 7 },
		{ 4, "1.2.3.0", "1.2.3.125", 7 },
		{ 4, "1.2.0.0", "1.2.255.255", 16 },
		{ 4, "1.2.0.0", "1.2.0.255", 8 },
		{ 4, "1.2.255.0", "1.2.255.255", 8 },
		{ 4, "1.2.255.1", "1.2.255.255", 8 },
		{ 4, "1.2.0.1", "1.2.255.255", 16 },
		{ 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:ffff", 16 },
		{ 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:fff", 12 },
		{ 6, "1:2:3:4:5:6:7:f0", "1:2:3:4:5:6:7:ff", 4 },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_LO2HI(stdout, " -> %d", t->range);

		sa_family_t af = SA_FAMILY(t->family);

		ip_address lo;
		oops = ttoaddr(t->lo, 0, af, &lo);
		if (oops != NULL) {
			FAIL_LO2HI("ttoaddr failed converting '%s'", t->lo);
			continue;
		}

		ip_address hi;
		oops = ttoaddr(t->hi, 0, af, &hi);
		if (oops != NULL) {
			FAIL_LO2HI("ttoaddr failed converting '%s'", t->hi);
			continue;
		}

		/*
		 * XXX: apparently iprange_bits() working for both
		 * low-hi and hi-low is a feature!?!
		 */
		int lo2hi = iprange_bits(lo, hi);
		int hi2lo = iprange_bits(hi, lo);
		if (lo2hi != hi2lo) {
			FAIL_LO2HI("iprange_bits(lo,hi) returned %d and iprange_bits(hi,lo) returned %d",
				   lo2hi, hi2lo);
		}
		if (t->range != lo2hi) {
			FAIL_LO2HI("iprange_bits(lo,hi) returned '%d', expected '%d'",
				   lo2hi, t->range);
		}
	}
}

static void check_ttorange_2_str_range(void)
{
	static const struct test {
		int family;
		const char *in;
		long pool;
		const char *out;
	} tests[] = {
		/* er, pick one! */
		{ 4, "1.2.3.0-1.2.3.9", 10, "1.2.3.0-1.2.3.9", },
		/* { 4, "1.2.3.0-1.2.3.9", 9, "1.2.3.0-1.2.3.9", }, */
		{ 4, "1.2.3.0-nonenone", -1, NULL, },
		{ 4, "1.2.3.0/255.255.255.0", -1, NULL, },
		{ 4, "_", -1, NULL, },
		{ 4, "_/_", -1, NULL, },
		/* not implemented */
		{ 6, "1:0:3:0:0:0:0:2/128", -1, NULL, /*"1:0:3::2/128"*/ },
		{ 6, "abcd:ef01:2345:6789:0:00a:000:20/128",
		  -1, NULL, /*"abcd:ef01:2345:6789:0:a:0:20/128"*/ },
		{ 6, "%default", -1, NULL, /*"NULL"*/ },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		if (t->out != NULL) {
			PRINT_IN(stdout, " -> %s pool %ld", t->out, t->pool);
		} else {
			PRINT_IN(stdout, " -> <error>");
		}
		const char *oops = NULL;
		sa_family_t af = SA_FAMILY(t->family);

		ip_range range;
		oops = ttorange(t->in, 0, af, &range, false);
		if (oops != NULL && t->out == NULL) {
			/* Error was expected, do nothing */
			continue;
		}
		if (oops != NULL && t->out != NULL) {
			/* Error occurred, but we didn't expect one  */
			FAIL_IN("ttorange() failed: %s", oops);
			continue;
		}

		range_buf buf;
		const char *out = str_range(&range, &buf);
		if (!streq(out, t->out)) {
			FAIL_IN("str_range() returned '%s', expecting '%s'",
				out, t->out);
			continue;
		}

		/* er, isn't the point of this a function? */
		unsigned pool_size = (uint32_t)ntohl(range.end.u.v4.sin_addr.s_addr) -
			(uint32_t)ntohl(range.start.u.v4.sin_addr.s_addr);
		pool_size++;
		if (t->pool != (long)pool_size) {
			FAIL_IN("pool_size gave %u, expecting %ld",
				pool_size, t->pool);
		}
	}
}

void ip_range_check(void)
{
	check_rangetosubnet();
	check_iprange_bits();
	check_ttorange_2_str_range();
}
