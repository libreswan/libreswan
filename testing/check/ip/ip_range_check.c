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
#include "lswlog.h"

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

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_LO2HI(stdout, "-> '%s'",
			    t->out ? t->out : "<error>");
		const struct ip_info *type = IP_TYPE(t->family);

		ip_address lo;
		oops = numeric_to_address(shunk1(t->lo), type, &lo);
		if (oops != NULL) {
			FAIL_LO2HI("numeric_to_address(lo) failed: %s", oops);
			continue;
		}
		ip_address hi;
		oops = numeric_to_address(shunk1(t->hi), type, &hi);
		if (oops != NULL) {
			FAIL_LO2HI("numeric_to_address(hi) failed: %s", oops);
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
		{ 6, "2000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 125},
		{ 6, "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 127},
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_LO2HI(stdout, " -> %d", t->range);

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address lo;
		oops = numeric_to_address(shunk1(t->lo), type, &lo);
		if (oops != NULL) {
			FAIL_LO2HI("numeric_to_address() failed converting '%s'", t->lo);
			continue;
		}

		ip_address hi;
		oops = numeric_to_address(shunk1(t->hi), type, &hi);
		if (oops != NULL) {
			FAIL_LO2HI("numeric_to_address() failed converting '%s'", t->hi);
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

static void check_ttorange__to__str_range(void)
{
	static const struct test {
		int family;
		const char *in;
		long pool;
		const char *out;
	} tests[] = {
		/* smallest */
		{ 6, "8000::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 4294967295, "8000::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
		{ 6, "::1-::1", 1, "::1-::1", },
		{ 6, "::2/128", 1, "::2/128", },
		{ 4, "1.2.3.4-1.2.3.4", 1, "1.2.3.4-1.2.3.4", },
		/* normal */
		{ 6, "::1-::2", 2, "::1-::2", },
		{ 4, "1.2.3.0-1.2.3.9", 10, "1.2.3.0-1.2.3.9", },
		{ 6, "1:0:3:0:0:0:0:2/128", 1, "1:0:3::2/128", },
		{ 6, "2001:db8:0:9:1:2::/112", 65536, "2001:db8:0:9:1:2::/112", },
		{ 6, "abcd:ef01:2345:6789:0:00a:000:20/128", 1, "abcd:ef01:2345:6789:0:a:0:20/128", },
		{ 6, "2001:db8:0:8::/112", 65536, "2001:db8:0:8::/112",},
		{ 6, "2001:db8:0:9:ffff:fffe::-2001:db8:0:9:ffff:ffff::", 4294967295,"2001:db8:0:9:ffff:fffe::-2001:db8:0:9:ffff:ffff::", },
		{ 6, "2001:db8:0:9:ffff:ffff:0:2-2001:db8:0:9:ffff:ffff:ffff:ffff", 4294967294, "2001:db8:0:9:ffff:ffff:0:2-2001:db8:0:9:ffff:ffff:ffff:ffff", },
		{ 6, "2001:db8:0:9::1-2001:db8:0:9:0:0:ffff:ffff", 4294967295, "2001:db8:0:9::1-2001:db8:0:9::ffff:ffff", },
		{ 6, "2001:db8:0:1:2:ffff:0:2-2001:db8:0:1:2:ffff:ffff:fffe", 4294967293, "2001:db8:0:1:2:ffff:0:2-2001:db8:0:1:2:ffff:ffff:fffe", },
		{ 6, "2001:db8:0:7::/97", 2147483648, "2001:db8:0:7::/97", },
		/* truncated ranges */
		{ 6, "2001:db8:0:1::-2001:db8:0:1:0:0:ffff:ffff", 4294967295, "2001:db8:0:1::-2001:db8:0:1::ffff:ffff", },
		{ 6, "2001:db8:0:3::-2001:db8:0:3:0:ffff:ffff:ffff", 4294967295, "2001:db8:0:3::-2001:db8:0:3:0:ffff:ffff:ffff", },
		{ 6, "2001:db8:0:4::/96", 4294967295, "2001:db8:0:4::/96", },
		{ 6, "2001:db8:0:6::/64", 4294967295, "2001:db8:0:6::/64", },
		{ 6, "2001:db8::/32", 4294967295, "2001:db8::/32", },
		{ 6, "2000::/3", 4294967295, "2000::/3", },
		{ 6, "4000::/2", 4294967295, "4000::/2", },
		{ 6, "8000::/1", 4294967295, "8000::/1", },
		{ 6, "2001:db8:0:fffe::2-2001:db8:0:ffff::", 4294967294, "2001:db8:0:fffe::2-2001:db8:0:ffff::", },
		{ 6, "2001:db8:0:1:2:fffe::-2001:db8:0:1:2:ffff:ffff:ffee", 4294967295, "2001:db8:0:1:2:fffe::-2001:db8:0:1:2:ffff:ffff:ffee", },
		{ 6, "1000::-1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 4294967295, "1000::-1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
		{ 6, "8000::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 4294967294, "8000::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
		{ 6, "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 4294967295, "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
		{ 6, "2001:db8:0:7::/97:0", 2147483648, "2001:db8:0:7::/97", }, /* would be nice to error on this too */
		/* no port */
		{ 6, "2001:db8:0:7::/97:30", -1, NULL},
		/* wrong order */
		{ 4, "1.2.3.4-1.2.3.3", -1, NULL, },
		{ 6, "::2-::1", -1, NULL, },
		/* not masks; but why? */
		{ 4, "1.2.3.0/255.255.255.0", -1, NULL, },
		{ 4, "1.2.3.0/32", -1, NULL, },
		/* not any */
		{ 4, "0.0.0.0-0.0.0.0", -1, NULL, },
		{ 4, "0.0.0.0-0.0.0.1", -1, NULL, },
		{ 6, "::-::", -1, NULL, },
		{ 6, "::-::1", -1, NULL, },
		{ 6, "::/97", -1, NULL, },
		{ 6, "::0/64", -1, NULL, },
		{ 6, "::0/127", -1, NULL, },
		{ 6, "::/0", -1, NULL, },
		/* nonsense */
		{ 4, "1.2.3.0-nonenone", -1, NULL, },
		{ 4, "-", -1, NULL, },
		{ 4, "_/_", -1, NULL, },
		{ 6, "%default", -1, NULL, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		if (t->out != NULL) {
			PRINT_IN(stdout, " -> %s pool %ld", t->out, t->pool);
		} else {
			PRINT_IN(stdout, " -> <error>");
		}
		const char *oops = NULL;

		ip_range r;
		oops = ttorange(t->in, IP_TYPE(t->family), &r, &progname_logger);
		if (oops != NULL && t->out == NULL) {
			/* Error was expected, do nothing */
			continue;
		}
		if (oops != NULL && t->out != NULL) {
			/* Error occurred, but we didn't expect one  */
			FAIL_IN("ttorange() failed: %s", oops);
		}

		CHECK_TYPE(PRINT_IN, range_type(&r));

		range_buf buf;
		const char *out = str_range(&r, &buf);
		if (!streq(out, t->out)) {
			FAIL_IN("str_range() returned '%s', expecting '%s'",
				out, t->out);
			continue;
		}

		if (t->pool > 0) {
			uint32_t pool_size;
			range_size(&r, &pool_size);
			if (t->pool != (long)pool_size) {
				FAIL_IN("pool_size gave %u, expecting %ld",
					pool_size, t->pool);
			}
		}
	}
}

static void check_range_from_subnet(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *start;
		const char *end;
	} tests[] = {
		{ 4, "0.0.0.0/1", "0.0.0.0", "127.255.255.255", },
		{ 4, "1.2.2.0/23", "1.2.2.0", "1.2.3.255", },
		{ 4, "1.2.3.0/24", "1.2.3.0", "1.2.3.255", },
		{ 4, "1.2.3.0/25", "1.2.3.0", "1.2.3.127", },
		{ 4, "1.2.3.4/31", "1.2.3.4", "1.2.3.5", },
		{ 4, "1.2.3.4/32", "1.2.3.4", "1.2.3.4", },
		{ 6, "::/1", "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
		{ 6, "1:2:3:4::/63", "1:2:3:4::", "1:2:3:5:ffff:ffff:ffff:ffff", },
		{ 6, "1:2:3:4::/64", "1:2:3:4::", "1:2:3:4:ffff:ffff:ffff:ffff", },
		{ 6, "1:2:3:4::/65", "1:2:3:4::", "1:2:3:4:7fff:ffff:ffff:ffff", },
		{ 6, "1:2:3:4:8000::/65", "1:2:3:4:8000::", "1:2:3:4:ffff:ffff:ffff:ffff", },
		{ 6, "1:2:3:4:5:6:7:8/127", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", },
		{ 6, "1:2:3:4:5:6:7:8/128", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> '%s'..'%s'", t->start, t->end);

		sa_family_t af = SA_FAMILY(t->family);

		ip_subnet s;
		oops = ttosubnet(t->in, 0, af, '6', &s, &progname_logger);
		if (oops != NULL) {
			FAIL_IN("ttosubnet() failed: %s", oops);
		}

		CHECK_TYPE(PRINT_IN, subnet_type(&s));

		ip_range r = range_from_subnet(&s);
		CHECK_TYPE(PRINT_IN, range_type(&r));

		address_buf start_buf;
		const char *start = str_address(&r.start, &start_buf);
		if (!streq(t->start, start)) {
			FAIL_IN("r.start is '%s', expected '%s'",
				start, t->start);
		}
		CHECK_TYPE(PRINT_IN, address_type(&r.start));

		address_buf end_buf;
		const char *end = str_address(&r.end, &end_buf);
		if (!streq(t->end, end)) {
			FAIL_IN("r.end is '%s', expected '%s'",
				end, t->end);
		}
		CHECK_TYPE(PRINT_IN, address_type(&r.end));

	}
}

static void check_range_is(void)
{
	static const struct test {
		int family;
		const char *lo;
		const char *hi;
		bool set;
		bool specified;
	} tests[] = {
		{ 0, "", "",                .set = false, },

		{ 4, "0.0.0.0", "0.0.0.0",  .set = true, },
		{ 4, "0.0.0.1", "0.0.0.2",  .set = true, .specified = true, },

		{ 6, "::", "::",            .set = true, },
		{ 6, "::1", "::2",          .set = true, .specified = true, },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_LO2HI(stdout, " -> set: %s specified: %s",
			    bool_str(t->set), bool_str(t->specified));

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address lo;
		if (strlen(t->lo) > 0) {
			oops = numeric_to_address(shunk1(t->lo), type, &lo);
			if (oops != NULL) {
				FAIL_LO2HI("numeric_to_address() failed converting '%s'", t->lo);
			}
		} else {
			lo = unset_address;
		}

		ip_address hi;
		if (strlen(t->hi) > 0) {
			oops = numeric_to_address(shunk1(t->hi), type, &hi);
			if (oops != NULL) {
				FAIL_LO2HI("numeric_to_address() failed converting '%s'", t->hi);
			}
		} else {
			hi = unset_address;
		}

		ip_range r = range(&lo, &hi);
		CHECK_TYPE(PRINT_LO2HI, range_type(&r));

		bool set = range_is_set(&r);
		if (set != t->set) {
			FAIL_LO2HI("range_is_invalid() returned %s, expecting %s",
				   bool_str(set), bool_str(t->set));
		}

		bool specified = range_is_specified(&r);
		if (specified != t->specified) {
			FAIL_LO2HI("range_is_specified() returned %s, expecting %s",
				   bool_str(specified), bool_str(t->specified));
		}
	}
}

void ip_range_check(void)
{
	check_rangetosubnet();
	check_iprange_bits();
	check_ttorange__to__str_range();
	check_range_from_subnet();
	check_range_is();
}
