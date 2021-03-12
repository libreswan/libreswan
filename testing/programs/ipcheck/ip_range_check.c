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
#include <limits.h>		/* for UINT32_MAX */

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for streq() */
#include "ip_range.h"
#include "ip_subnet.h"
#include "ipcheck.h"

static void check_addresses_to(void)
{
	static const struct test {
		int line;
		int family;
		const char *lo;
		const char *hi;
		const char *subnet;	/* NULL means error expected */
		const char *range;	/* NULL means use subnet */
		const char *oldnet;
	} tests[] = {
		/* single address */
		{ LN, 4, "1.2.3.0",    "1.2.3.0", "1.2.3.0/32", NULL, NULL, },
		{ LN, 6, "::1",        "::1", "::1/128", NULL, NULL, },
		{ LN, 4, "1.2.3.4",    "1.2.3.4", "1.2.3.4/32", NULL, NULL, },

		/* subnet */
		{ LN, 4, "1.2.3.0",    "1.2.3.7", "1.2.3.0/29", NULL, NULL, },
		{ LN, 4, "1.2.3.240",  "1.2.3.255", "1.2.3.240/28", NULL, NULL, },
		{ LN, 4, "0.0.0.0",    "255.255.255.255", "0.0.0.0/0", NULL, NULL, },
		{ LN, 4, "1.2.0.0",    "1.2.255.255", "1.2.0.0/16", NULL, NULL, },
		{ LN, 4, "1.2.0.0",    "1.2.0.255", "1.2.0.0/24", NULL, NULL, },
		{ LN, 4, "1.2.255.0",  "1.2.255.255", "1.2.255.0/24", NULL, NULL, },
		{ LN, 6, "1:2:3:4:5:6:7:0",   "1:2:3:4:5:6:7:ffff", "1:2:3:4:5:6:7:0/112", NULL, NULL, },
		{ LN, 6, "1:2:3:4:5:6:7:0",   "1:2:3:4:5:6:7:fff", "1:2:3:4:5:6:7:0/116", NULL, NULL, },
		{ LN, 6, "1:2:3:4:5:6:7:f0",  "1:2:3:4:5:6:7:ff", "1:2:3:4:5:6:7:f0/124", NULL, NULL, },

		/* range only */
		{ LN, 4, "1.2.3.0",    "1.2.3.254", NULL, "1.2.3.0-1.2.3.254", NULL, },
		{ LN, 4, "1.2.3.0",    "1.2.3.126", NULL, "1.2.3.0-1.2.3.126", NULL, },
		{ LN, 4, "1.2.3.0",    "1.2.3.125", NULL, "1.2.3.0-1.2.3.125", NULL, },
		{ LN, 4, "1.2.255.1",  "1.2.255.255", NULL, "1.2.255.1-1.2.255.255", NULL, },
		{ LN, 4, "1.2.0.1",    "1.2.255.255", NULL, "1.2.0.1-1.2.255.255", NULL, },

		/* wrong order */
		{ LN, 4, "1.2.255.0",  "1.2.254.255", NULL, NULL, NULL, },

		/* any-any; almost any */
		{ LN, 4, "0.0.0.0", "0.0.0.0", NULL, NULL, "0.0.0.0/32", },
		{ LN, 6, "::",      "::",      NULL, NULL, "::/128", },
		{ LN, 4, "0.0.0.0", "0.0.0.1", "0.0.0.0/31", NULL, NULL, },
		{ LN, 6, "::",      "::1",      "::/127", NULL, NULL, },

		/* all */
		{ LN, 4, "0.0.0.0", "255.255.255.255", "0.0.0.0/0", NULL, NULL, },
		{ LN, 6, "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::/0", NULL, NULL, },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		const char *subnet = t->subnet;
		const char *range = t->range != NULL ? t->range : subnet;
		const char *oldnet = t->oldnet != NULL ? t->oldnet : subnet;
		PRINT("%s-%s -> %s -> %s|%s",
		      t->lo, t->hi,
		      range == NULL ? "<bad-range>" : range,
		      subnet == NULL ? "<bad-subnet>" : subnet,
		      oldnet == NULL ? "<bad-oldnet>" : oldnet);

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address lo;
		oops = numeric_to_address(shunk1(t->lo), type, &lo);
		if (oops != NULL) {
			FAIL("numeric_to_address(lo=%s) failed: %s", t->lo, oops);
			continue;
		}

		ip_address hi;
		oops = numeric_to_address(shunk1(t->hi), type, &hi);
		if (oops != NULL) {
			FAIL("numeric_to_address(hi=%s) failed: %s", t->hi, oops);
			continue;
		}

		ip_subnet s;
		subnet_buf sb;
		oops = rangetosubnet(&lo, &hi, &s);
		str_subnet(&s, &sb);

		if (oops != NULL && oldnet == NULL) {
			/* okay, error expected */
		} else if (oops != NULL) {
			FAIL("rangetosubnet(%s,%s) failed: %s", t->lo, t->hi, oops);
		} else if (oldnet == NULL) {
			FAIL("rangetosubnet(%s,%s) returned %s unexpectedly",
			     t->lo, t->hi, sb.buf);
		} else {
			if (!streq(oldnet, sb.buf)) {
				FAIL("rangetosubnet(%s,%s) returned `%s', expected `%s'",
				     t->lo, t->hi, sb.buf, oldnet);
			}
		}

		ip_range r;
		range_buf rb;
		oops = addresses_to_range(lo, hi, &r);
		r.is_subnet = true; /* maybe */
		str_range(&r, &rb);

		if (oops != NULL && range == NULL) {
			/* okay, error expected */
		} else if (oops != NULL) {
			FAIL("addresses_to_range(%s,%s) failed: %s",
			     t->lo, t->hi, oops);
		} else if (range == NULL) {
			FAIL("addresses_to_range(%s,%s) returned %s unexpectedly",
			     t->lo, t->hi, rb.buf);
		} else {
			if (!streq(range, rb.buf)) {
				FAIL("addresses_to_range(%s,%s) returned `%s', expected `%s'",
				     t->lo, t->hi, rb.buf, range);
			}
		}

		oops = addresses_to_subnet(lo, hi, &s);
		str_subnet(&s, &sb);

		if (oops != NULL && subnet == NULL) {
			/* okay, error expected */
		} else if (oops != NULL) {
			FAIL("addresses_to_subnet(%s,%s) failed: %s", t->lo, t->hi, oops);
		} else if (subnet == NULL) {
			FAIL("addresses_to_subnet(%s,%s) returned %s unexpectedly",
			     t->lo, t->hi, sb.buf);
		} else {
			if (!streq(subnet, sb.buf)) {
				FAIL("addresses_to_subnet(%s,%s) returned `%s', expected `%s'",
				     t->lo, t->hi, sb.buf, subnet);
			}
		}

		if (range == NULL) {
			continue;
		}

		oops = range_to_subnet(r, &s);
		str_subnet(&s, &sb);

		if (oops != NULL && subnet == NULL) {
			/* okay, error expected */
		} else if (oops != NULL) {
			FAIL("range_to_subnet(%s=>%s) failed: %s",
			     rb.buf, sb.buf, oops);
		} else if (subnet == NULL) {
			FAIL("range_to_subnet(%s) returned %s unexpectedly",
			     rb.buf, sb.buf);
		} else {
			if (!streq(subnet, sb.buf)) {
				FAIL("range_to_subnet(%s) returned `%s', expected `%s'",
				     rb.buf, sb.buf, subnet);
			}
		}

	}
}

static void check_iprange_bits(void)
{
	static const struct test {
		int line;
		int family;
		const char *lo;
		const char *hi;
		int range;
	} tests[] = {
		{ LN, 4, "1.2.255.0", "1.2.254.255", 1 },
		{ LN, 4, "1.2.3.0", "1.2.3.7", 3 },
		{ LN, 4, "1.2.3.0", "1.2.3.255", 8 },
		{ LN, 4, "1.2.3.240", "1.2.3.255", 4 },
		{ LN, 4, "0.0.0.0", "255.255.255.255", 32 },
		{ LN, 4, "1.2.3.4", "1.2.3.4", 0 },
		{ LN, 4, "1.2.3.0", "1.2.3.254", 8 },
		{ LN, 4, "1.2.3.0", "1.2.3.126", 7 },
		{ LN, 4, "1.2.3.0", "1.2.3.125", 7 },
		{ LN, 4, "1.2.0.0", "1.2.255.255", 16 },
		{ LN, 4, "1.2.0.0", "1.2.0.255", 8 },
		{ LN, 4, "1.2.255.0", "1.2.255.255", 8 },
		{ LN, 4, "1.2.255.1", "1.2.255.255", 8 },
		{ LN, 4, "1.2.0.1", "1.2.255.255", 16 },
		{ LN, 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:ffff", 16 },
		{ LN, 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:fff", 12 },
		{ LN, 6, "1:2:3:4:5:6:7:f0", "1:2:3:4:5:6:7:ff", 4 },
		{ LN, 6, "2000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 125},
		{ LN, 6, "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 127},
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s'-'%s'", pri_family(t->family), t->lo, t->hi)

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address lo;
		oops = numeric_to_address(shunk1(t->lo), type, &lo);
		if (oops != NULL) {
			FAIL("numeric_to_address() failed converting '%s'", t->lo);
			continue;
		}

		ip_address hi;
		oops = numeric_to_address(shunk1(t->hi), type, &hi);
		if (oops != NULL) {
			FAIL("numeric_to_address() failed converting '%s'", t->hi);
			continue;
		}

		/*
		 * XXX: apparently iprange_bits() working for both
		 * low-hi and hi-low is a feature!?!
		 */
		ip_range lo_hi = range2(&lo, &hi);
		ip_range hi_lo = range2(&hi, &lo);
		int lo2hi = range_host_bits(lo_hi);
		int hi2lo = range_host_bits(hi_lo);
		if (lo2hi != hi2lo) {
			FAIL("iprange_bits(lo,hi) returned %d and iprange_bits(hi,lo) returned %d",
			     lo2hi, hi2lo);
		}
		if (t->range != lo2hi) {
			FAIL("iprange_bits(lo,hi) returned '%d', expected '%d'",
			     lo2hi, t->range);
		}
	}
}

static void check_ttorange__to__str_range(void)
{
	static const struct test {
		int line;
		int family;
		const char *in;
		const char *out;
		uint32_t pool_size;
		bool truncated;
	} tests[] = {
		/* single address */
		{ LN, 4, "4.3.2.1", "4.3.2.1-4.3.2.1", 1, false},
		{ LN, 6, "::1", "::1-::1", 1, false, },
		{ LN, 4, "4.3.2.1-4.3.2.1", "4.3.2.1-4.3.2.1", 1, false, },
		{ LN, 6, "::1-::1", "::1-::1", 1, false, },
		{ LN, 4, "4.3.2.1/32", "4.3.2.1-4.3.2.1", 1, false, },
		{ LN, 6, "::2/128", "::2/128", 1, false, },
		/* normal range */
		{ LN, 6, "::1-::2", "::1-::2", 2, false, },
		{ LN, 4, "1.2.3.0-1.2.3.9", "1.2.3.0-1.2.3.9", 10, false, },
		/* largest */
		{ LN, 4, "0.0.0.1-255.255.255.255", "0.0.0.1-255.255.255.255", UINT32_MAX, false, },

		/* ok - largest - overflow - truncate */
		{ LN, 6, "1:2:3:4:5:6:0:0-1:2:3:4:5:6:ffff:fffd", "1:2:3:4:5:6::-1:2:3:4:5:6:ffff:fffd", UINT32_MAX-1, false, },
		{ LN, 6, "1:2:3:4:5:6:0:0-1:2:3:4:5:6:ffff:fffe", "1:2:3:4:5:6::-1:2:3:4:5:6:ffff:fffe", UINT32_MAX, false, },
		{ LN, 6, "1:2:3:4:5:6:0:0-1:2:3:4:5:6:ffff:ffff", "1:2:3:4:5:6::-1:2:3:4:5:6:ffff:ffff", UINT32_MAX, true, },
		{ LN, 6, "1:2:3:4:5:6:0:0-1:2:3:4:5:7:0000:0000", "1:2:3:4:5:6::-1:2:3:4:5:7::", UINT32_MAX, true, },

		/* ok - largest - overflow - truncate */
		{ LN, 6, "1:2:3:4:5:6:0:1-1:2:3:4:5:6:ffff:fffe", "1:2:3:4:5:6:0:1-1:2:3:4:5:6:ffff:fffe", UINT32_MAX-1, false, },
		{ LN, 6, "1:2:3:4:5:6:0:1-1:2:3:4:5:6:ffff:ffff", "1:2:3:4:5:6:0:1-1:2:3:4:5:6:ffff:ffff", UINT32_MAX, false, },
		{ LN, 6, "1:2:3:4:5:6:0:1-1:2:3:4:5:7:0000:0000", "1:2:3:4:5:6:0:1-1:2:3:4:5:7::", UINT32_MAX, true, },
		{ LN, 6, "1:2:3:4:5:6:0:1-1:2:3:4:5:7:0000:0001", "1:2:3:4:5:6:0:1-1:2:3:4:5:7:0:1", UINT32_MAX, true, },

		/* ok - largest - overflow - truncate */
		{ LN, 6, "1:2:3:4:5:6:0:2-1:2:3:4:5:6:ffff:ffff", "1:2:3:4:5:6:0:2-1:2:3:4:5:6:ffff:ffff", UINT32_MAX-1, false, },
		{ LN, 6, "1:2:3:4:5:6:0:2-1:2:3:4:5:7:0000:0000", "1:2:3:4:5:6:0:2-1:2:3:4:5:7::", UINT32_MAX, false, },
		{ LN, 6, "1:2:3:4:5:6:0:2-1:2:3:4:5:7:0000:0001", "1:2:3:4:5:6:0:2-1:2:3:4:5:7:0:1", UINT32_MAX, true, },
		{ LN, 6, "1:2:3:4:5:6:0:2-1:2:3:4:5:7:0000:0002", "1:2:3:4:5:6:0:2-1:2:3:4:5:7:0:2", UINT32_MAX, true, },

		/* ok - largest - overflow - truncate */
		{ LN, 6, "1:2:3:4:5:6:0:3-1:2:3:4:5:7:0000:0000", "1:2:3:4:5:6:0:3-1:2:3:4:5:7::", UINT32_MAX-1, false, },
		{ LN, 6, "1:2:3:4:5:6:0:3-1:2:3:4:5:7:0000:0001", "1:2:3:4:5:6:0:3-1:2:3:4:5:7:0:1", UINT32_MAX, false, },
		{ LN, 6, "1:2:3:4:5:6:0:3-1:2:3:4:5:7:0000:0002", "1:2:3:4:5:6:0:3-1:2:3:4:5:7:0:2", UINT32_MAX, true, },
		{ LN, 6, "1:2:3:4:5:6:0:3-1:2:3:4:5:7:0000:0003", "1:2:3:4:5:6:0:3-1:2:3:4:5:7:0:3", UINT32_MAX, true, },

		/* total overflow */
		{ LN, 6, "2001:db8:0:9:ffff:fffe::-2001:db8:0:9:ffff:ffff::", "2001:db8:0:9:ffff:fffe::-2001:db8:0:9:ffff:ffff::", UINT32_MAX, true, },
		{ LN, 6, "8000::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "8000::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UINT32_MAX, true, },
		{ LN, 6, "1000::-1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1000::-1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UINT32_MAX, true, },
		{ LN, 6, "8000::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "8000::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UINT32_MAX, true, },
		{ LN, 6, "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UINT32_MAX, true, },

		/* allow mask */
		{ LN, 4, "1.2.3.0/32", "1.2.3.0-1.2.3.0", 1, false, },
		{ LN, 6, "1:0:3:0:0:0:0:2/128", "1:0:3::2/128", 1, false, },
		{ LN, 6, "2001:db8:0:9:1:2::/112", "2001:db8:0:9:1:2::/112", 65536, false, },
		{ LN, 6, "abcd:ef01:2345:6789:0:00a:000:20/128", "abcd:ef01:2345:6789:0:a:0:20/128", 1, false, },
		{ LN, 6, "2001:db8:0:8::/112", "2001:db8:0:8::/112", 65536, false, },
		{ LN, 6, "2001:db8:0:7::/97", "2001:db8:0:7::/97", 2147483648, false, },
		{ LN, 6, "2001:db8:0:4::/96", "2001:db8:0:4::/96", UINT32_MAX, true, },
		{ LN, 6, "2001:db8:0:6::/64", "2001:db8:0:6::/64", UINT32_MAX, true, },
		{ LN, 6, "2001:db8::/32", "2001:db8::/32", UINT32_MAX, true, },
		{ LN, 6, "2000::/3", "2000::/3", UINT32_MAX, true, },
		{ LN, 6, "4000::/2", "4000::/2", UINT32_MAX, true, },
		{ LN, 6, "8000::/1", "8000::/1", UINT32_MAX, true, },

		/* reject port */
		{ LN, 6, "2001:db8:0:7::/97:0", NULL, -1, false, },
		{ LN, 6, "2001:db8:0:7::/97:30", NULL, -1, false},
		/* wrong order */
		{ LN, 4, "1.2.3.4-1.2.3.3", NULL, -1, false, },
		{ LN, 6, "::2-::1", NULL, -1, false, },
		/* cannot contain %any */
		{ LN, 4, "0.0.0.0-0.0.0.0", NULL, -1, false, },
		{ LN, 4, "0.0.0.0-0.0.0.1", NULL, -1, false, },
		{ LN, 6, "::-::", NULL, -1, false, },
		{ LN, 6, "::-::1", NULL, -1, false, },
		{ LN, 6, "::/97", NULL, -1, false, },
		{ LN, 6, "::0/64", NULL, -1, false, },
		{ LN, 6, "::0/127", NULL, -1, false, },
		{ LN, 6, "::/0", NULL, -1, false, },
		/* nonsense */
		{ LN, 4, "1.2.3.0-nonenone", NULL, -1, false, },
		{ LN, 4, "-", NULL, -1, false, },
		{ LN, 4, "_/_", NULL, -1, false, },
		{ LN, 6, "%default", NULL, -1, false, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		if (t->out != NULL) {
			PRINT("%s '%s' -> %s pool-size %"PRIu32" truncated %s", pri_family(t->family), t->in, t->out, t->pool_size, bool_str(t->truncated));
		} else {
			PRINT("%s '%s' -> <error>", pri_family(t->family), t->in);
		}
		const char *oops = NULL;

		ip_range r;
		oops = ttorange(t->in, IP_TYPE(t->family), &r);
		if (oops != NULL && t->out == NULL) {
			/* Error was expected, do nothing */
			continue;
		}
		if (oops != NULL && t->out != NULL) {
			/* Error occurred, but we didn't expect one  */
			FAIL("ttorange() failed: %s", oops);
		}

		CHECK_TYPE(range_type(&r));

		range_buf buf;
		const char *out = str_range(&r, &buf);
		if (!streq(out, t->out)) {
			FAIL("str_range() returned '%s', expecting '%s'",
				out, t->out);
			continue;
		}

		if (t->pool_size > 0) {
			uint32_t pool_size;
			bool truncated = range_size(r, &pool_size);
			if (t->pool_size != pool_size) {
				FAIL("pool_size gave %"PRIu32", expecting %"PRIu32,
					pool_size, t->pool_size);
			}
			if (t->truncated != truncated) {
				FAIL("pool_size gave %s, expecting %s",
					bool_str(truncated), bool_str(t->truncated));
			}
		}
	}
}

static void check_range_from_subnet(struct logger *logger)
{
	static const struct test {
		int line;
		int family;
		const char *in;
		const char *start;
		const char *end;
	} tests[] = {
		{ LN, 4, "0.0.0.0/1", "0.0.0.0", "127.255.255.255", },
		{ LN, 4, "1.2.2.0/23", "1.2.2.0", "1.2.3.255", },
		{ LN, 4, "1.2.3.0/24", "1.2.3.0", "1.2.3.255", },
		{ LN, 4, "1.2.3.0/25", "1.2.3.0", "1.2.3.127", },
		{ LN, 4, "1.2.3.4/31", "1.2.3.4", "1.2.3.5", },
		{ LN, 4, "1.2.3.4/32", "1.2.3.4", "1.2.3.4", },
		{ LN, 6, "::/1", "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
		{ LN, 6, "1:2:3:4::/63", "1:2:3:4::", "1:2:3:5:ffff:ffff:ffff:ffff", },
		{ LN, 6, "1:2:3:4::/64", "1:2:3:4::", "1:2:3:4:ffff:ffff:ffff:ffff", },
		{ LN, 6, "1:2:3:4::/65", "1:2:3:4::", "1:2:3:4:7fff:ffff:ffff:ffff", },
		{ LN, 6, "1:2:3:4:8000::/65", "1:2:3:4:8000::", "1:2:3:4:ffff:ffff:ffff:ffff", },
		{ LN, 6, "1:2:3:4:5:6:7:8/127", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", },
		{ LN, 6, "1:2:3:4:5:6:7:8/128", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> '%s'..'%s'", pri_family(t->family), t->in, t->start, t->end);

		ip_subnet s;
		oops = ttosubnet(shunk1(t->in), IP_TYPE(t->family), '6', &s, logger);
		if (oops != NULL) {
			FAIL("ttosubnet() failed: %s", oops);
		}

		CHECK_TYPE(subnet_type(&s));

		ip_range r = range_from_subnet(s);
		CHECK_TYPE(range_type(&r));

		address_buf start_buf;
		ip_address r_start = range_start(r);
		const char *start = str_address(&r_start, &start_buf);
		if (!streq(t->start, start)) {
			FAIL("r.start is '%s', expected '%s'",
				start, t->start);
		}
		CHECK_TYPE(address_type(&r_start));

		address_buf end_buf;
		ip_address r_end = range_end(r);
		const char *end = str_address(&r_end, &end_buf);
		if (!streq(t->end, end)) {
			FAIL("r.end is '%s', expected '%s'",
				end, t->end);
		}
		CHECK_TYPE(address_type(&r_end));

	}
}

static void check_range_op(void)
{
	static const struct test {
		int line;
		int family;
		const char *lo;
		const char *hi;
		bool is_unset;
		bool is_specified;
	} tests[] = {
		{ LN, 0, "", "",                .is_unset = true, },

		{ LN, 4, "0.0.0.0", "0.0.0.0",  .is_specified = false, },
		{ LN, 4, "0.0.0.1", "0.0.0.2",  .is_specified = true, },

		{ LN, 6, "::", "::",            .is_specified = false, },
		{ LN, 6, "::1", "::2",          .is_specified = true, },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s'-'%s'", pri_family(t->family), t->lo, t->hi)

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address lo;
		if (strlen(t->lo) > 0) {
			oops = numeric_to_address(shunk1(t->lo), type, &lo);
			if (oops != NULL) {
				FAIL("numeric_to_address() failed converting '%s'", t->lo);
			}
		} else {
			lo = unset_address;
		}

		ip_address hi;
		if (strlen(t->hi) > 0) {
			oops = numeric_to_address(shunk1(t->hi), type, &hi);
			if (oops != NULL) {
				FAIL("numeric_to_address() failed converting '%s'", t->hi);
			}
		} else {
			hi = unset_address;
		}

		const ip_range range[] = { range2(&lo, &hi), }; /* pointer */
		CHECK_TYPE(range_type(range));

		CHECK_COND(range, is_unset);
		CHECK_COND2(range, is_specified);
	}
}

static void check_range_op2(void)
{
	static const struct test {
		int line;
		int family;
		const char *l;
		const char *r;
		bool range_eq;
		bool range_in;
		bool range_overlap;
		bool address_in_range;
	} tests[] = {

		/* eq */
		{ LN, 0, "0.0.0.1", "0.0.0.1",                true,  true,  true,  true, },
		{ LN, 0, "0.0.1.0/24", "0.0.1.0/24",          true,  true,  true,  true, },
		{ LN, 0, "::0100/120", "::0100/120",          true,  true,  true,  true, },

		/* ne */
		{ LN, 0, "0.0.1.0/24", "0.0.2.0/24",          false, false, false, false, },
		{ LN, 0, "0.0.0.1", "0.0.0.2",                false, false, false, false, },
		{ LN, 0, "::1", "::2",                        false, false, false, false, },
		{ LN, 0, "::1", "0.0.0.1",                    false, false, false, false, },

		/* in */
		{ LN, 0, "::0124", "::0100/120",              false, true,  true,  true, },
		{ LN, 0, "::0124/126", "::0100/120",          false, true,  true,  true, },

		/* out */
		{ LN, 0, "::0100/120", "::0124",              false, false, true,  false, },
		{ LN, 0, "::0100/120", "::0124/126",          false, false, true,  false, },

		/* overlap */
		{ LN, 0, "::1-::2", "::2-::3",                false, false, true,  false, },

		/* silly */
		{ LN, 4, NULL, "0.0.0.1",       false, false, false, false, },
		{ LN, 4, "0.0.0.1", NULL,       false, false, false, false, },

	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s vs %s", t->l, t->r);

#define TT(R)								\
		ip_range R;						\
		if (t->R != NULL) {					\
			oops = ttorange(t->R, 0, &R);			\
			if (oops != NULL) {				\
				FAIL("ttorange(%s) failed: %s", t->R, oops); \
			}						\
		} else {						\
			l = unset_range;				\
		}
		TT(l);
		TT(r);
#undef TT

#define T(OP,L,R)							\
		{							\
			bool cond = OP(L,R);				\
			if (cond != t->OP) {				\
				FAIL(#OP"(%s,%s) returned %s, expecting %s", \
				     t->l, t->r,			\
				     bool_str(cond),			\
				     bool_str(t->OP));			\
			}						\
		}
		T(range_eq, l, r);
		T(range_in, l, r);
		T(range_overlap, l, r);
		ip_address a = range_start(l);
		T(address_in_range,a,r);
	}
}

static void check_range_to_address(void)
{
	static const struct test {
		int line;
		const char *range;
		uintmax_t offset;
		const char *address;
	} tests[] = {
		{ LN, "1.0.0.0/32",	         0, "1.0.0.0", },
		{ LN, "1.0.0.0/31",	         1, "1.0.0.1", },
		{ LN, "1.0.0.0/24",	       255, "1.0.0.255", },
		{ LN, "1.0.0.0/24",            256, NULL, },
		{ LN, "1.0.0.0/23",            256, "1.0.1.0", },
		/* bits */
		{ LN, "::1-::2",                 0, "::1", },
		{ LN, "::1-::2",                 1, "::2", },
		/* carry/overflow */
		{ LN, "::ffff-::1:0000",         1, "::1:0", },
		{ LN, "::ffff-::1:ffff",   0x10001, NULL, },
		{ LN, "0.0.0.1-255.255.255.255", UINT32_MAX-1ULL, "255.255.255.255", },
		{ LN, "0.0.0.1-255.255.255.255", UINT32_MAX,      NULL, },
		{ LN, "0.0.0.1-255.255.255.255", UINT32_MAX+1ULL, NULL, },
	};

	err_t err;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s + %jx -> %s", t->range, t->offset,
		      t->address == NULL ? "<unset>" : t->address);

		/* convert it *to* internal format */
		ip_range range;
		err = ttorange(t->range, NULL/*auto-detect*/, &range);
		if (err != NULL) {
			FAIL("ttorange(%s) failed: %s", t->range, err);
		}

		ip_address address;
		err = range_to_address(range, t->offset, &address);
		address_buf out;
		str_address(&address, &out);

		if (t->address == NULL) {
			if (!address_is_unset(&address)) {
				FAIL("range_to_address(%s + %jx -> %s) should have returned <unset>",
				     t->range, t->offset, out.buf);
			}
		} else if (!streq(out.buf, t->address)) {
			FAIL("range_to_address(%s + %jx -> %s) should have returned %s",
			     t->range, t->offset, out.buf, t->address);
		}

		PRINT("range_to_address(%s + %jx -> %s): %s",
		      t->range, t->offset, out.buf, err == NULL ? "<ok>" : err);

	}
}

static void check_range_to_offset(void)
{
	static const struct test {
		int line;
		const char *range;
		const char *address;
		uintmax_t offset;
		bool ok;
	} tests[] = {
		{ LN, "1.0.0.0/32", "1.0.0.0", 0, true, },
		{ LN, "0.0.0.1-255.255.255.255", "255.255.255.255", UINT32_MAX-1ULL, true, },
		/* out of range */
		{ LN, "1.0.0.0/32", "0.255.255.255", UINTMAX_MAX, false, },
		{ LN, "1.0.0.0/32", "1.0.0.1", UINTMAX_MAX, false, },
	};

	err_t err;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s - %s -> %jx ok: %s",
		      t->range, t->address,
		      t->offset, bool_str(t->ok));

		ip_range range;
		err = ttorange(t->range, NULL/*auto-detect*/, &range);
		if (err != NULL) {
			FAIL("ttorange(%s) failed: %s", t->range, err);
		}

		ip_address address;
		err = numeric_to_address(shunk1(t->address), NULL/*auto-detect*/, &address);
		if (err != NULL) {
			FAIL("numeric_to_address(%s) failed: %s", t->address, err);
		}

		uintmax_t offset;
		err = range_to_offset(range, address, &offset);

		if (t->ok) {
			if (err != NULL) {
				FAIL("range_to_offset(%s - %s -> %jx) unexpectedly failed: %s",
				     t->range, t->address, offset, err);
			}
		} else if (err == NULL) {
			FAIL("range_to_offset(%s - %s -> %jx) unexpectedly succeeded",
			     t->range, t->address, offset);
		}

		if (offset != t->offset) {
			FAIL("range_to_offset(%s - %s -> %jx) should have returned %jx",
			     t->range, t->address, offset, t->offset);
		}

		PRINT("range_to_offset(%s - %s -> %jx): %s",
		      t->range, t->address, offset, err == NULL ? "<ok>" : err);

	}
}

void ip_range_check(struct logger *logger)
{
	check_addresses_to();
	check_iprange_bits();
	check_ttorange__to__str_range();
	check_range_from_subnet(logger);
	check_range_op();
	check_range_op2();
	check_range_to_address();
	check_range_to_offset();
}
