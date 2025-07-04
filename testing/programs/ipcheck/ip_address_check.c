/* ip_address tests, for libreswan
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

#include <stdio.h>
#include <string.h>

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for streq() */
#include "ip_address.h"
#include "ipcheck.h"

static void check_ttoaddress_num(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		const char *str;
	} tests[] = {

		/* unset */
		{ LN, 0, "", NULL, },

		/* any */
		{ LN, &ipv4_info, "0.0.0.0", "0.0.0.0", },
		{ LN, &ipv6_info, "::", "::", },
		{ LN, &ipv6_info, "0:0:0:0:0:0:0:0", "::", },

		/* local (zero's fill) */
		{ LN, &ipv4_info, "127.1", "127.0.0.1", },
		{ LN, &ipv4_info, "127.0.1", "127.0.0.1", },
		{ LN, &ipv4_info, "127.0.0.1", "127.0.0.1", },
		{ LN, &ipv6_info, "::1", "::1", },
		{ LN, &ipv6_info, "0:0:0:0:0:0:0:1", "::1", },

		/* mask - and buffer overflow */
		{ LN, &ipv4_info, "255.255.255.255", "255.255.255.255", },
		{ LN, &ipv6_info, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },

		/* all bytes */
		{ LN, &ipv4_info, "1.2.3.4", "1.2.3.4", },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", },

		/* last digit is a big num - see wikepedia */
		{ LN, &ipv4_info, "127.254", "127.0.0.254", },
		{ LN, &ipv4_info, "127.65534", "127.0.255.254", },
		{ LN, &ipv4_info, "127.16777214", "127.255.255.254", },
		/* last digit overflow */
		{ LN, &ipv4_info, "127.16777216", NULL, },
		{ LN, &ipv4_info, "127.0.65536", NULL, },
		{ LN, &ipv4_info, "127.0.0.256", NULL, },

		/* hex/octal */
		{ LN, &ipv4_info, "0x01.0x02.0x03.0x04", "1.2.3.4", },
		{ LN, &ipv4_info, "0001.0002.0003.0004", "1.2.3.4", },
		{ LN, &ipv4_info, "0x01020304", "1.2.3.4", },

		/* trailing garbage */
		{ LN, &ipv4_info, "1.2.3.4.", NULL, },
		{ LN, &ipv4_info, "1.2.3.4a", NULL, },
		{ LN, &ipv4_info, "1.2.3.0a", NULL, },

		/* bad digits */
		{ LN, &ipv4_info, "256.2.3.4", NULL, },
		{ LN, &ipv4_info, "0008.2.3.4", NULL, },
		{ LN, &ipv4_info, "0x0g.2.3.4", NULL, },

		/* good :: */

		/* suppress leading zeros - 01 vs 1 */
		{ LN, &ipv6_info, "0001:0012:0003:0014:0005:0016:0007:0018", "1:12:3:14:5:16:7:18", },
		/* drop leading 0:0: */
		{ LN, &ipv6_info, "::3:4:5:6:7:8", "::3:4:5:6:7:8", },
		{ LN, &ipv6_info, "0:0:3:4:5:6:7:8", "::3:4:5:6:7:8", },
		/* drop middle 0:...:0 */
		{ LN, &ipv6_info, "1:2::7:8", "1:2::7:8", },
		{ LN, &ipv6_info, "1:2:0:0:0:0:7:8", "1:2::7:8", },
		/* drop trailing :0..:0 */
		{ LN, &ipv6_info, "1:2:3:4:5::", "1:2:3:4:5::", },
		{ LN, &ipv6_info, "1:2:3:4:5:0:0:0", "1:2:3:4:5::", },
		/* drop first 0:..:0 */
		{ LN, &ipv6_info, "1:2::5:6:0:0", "1:2::5:6:0:0", },
		{ LN, &ipv6_info, "1:2:0:0:5:6:0:0", "1:2::5:6:0:0", },
		/* drop logest 0:..:0 */
		{ LN, &ipv6_info, "0:0:3::7:8", "0:0:3::7:8", },
		{ LN, &ipv6_info, "0:0:3:0:0:0:7:8", "0:0:3::7:8", },
		/* need two 0 */
		{ LN, &ipv6_info, "0:2:0:4:0:6:0:8", "0:2:0:4:0:6:0:8", },

		/* bad: ::: */
		{ LN, &ipv6_info, ":::", NULL, },
		{ LN, &ipv6_info, "::::", NULL, },
		{ LN, &ipv6_info, "1:::", NULL, },
		{ LN, &ipv6_info, ":::1", NULL, },
		{ LN, &ipv6_info, "1:::1", NULL, },

		/* bad: ::..:: */
		{ LN, &ipv6_info, "::1::", NULL, },
		{ LN, &ipv6_info, "1::1::", NULL, },
		{ LN, &ipv6_info, "::1::1", NULL, },
		{ LN, &ipv6_info, "1::1::1", NULL, },

		/* bad: too short / too long */
		{ LN, &ipv6_info, "1:2:3:4:5:6:7", NULL, },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:8:9", NULL, },

		/* bad: leading/trailing : */
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:", NULL, },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:8:", NULL, },
		{ LN, &ipv6_info, ":2:3:4:5:6:7:8", NULL, },
		{ LN, &ipv6_info, ":1:2:3:4:5:6:7:8", NULL, },
		{ LN, &ipv6_info, ":2:3:4:5:6:7:", NULL, },
		{ LN, &ipv6_info, ":1:2:3:4:5:6:7:8:", NULL, },
	};

	err_t err;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];

		/*
		 * For each address, perform lookups:
		 *
		 * - first with a generic family and then with the
		 *   specified family
		 *
		 * - first with ttoaddress_num() and then
		 *   ttoaddress_dns() (but only when it should work)
		 */

		const struct ip_info *afis[] = { 0, &ipv4_info, &ipv6_info, };

		FOR_EACH_ELEMENT(afip, afis) {
			const struct ip_info *afi = (*afip);
			bool err_expected = (t->str == NULL ||
					     (afi != NULL && afi != t->afi));

			struct lookup {
				const char *name;
				err_t (*ttoaddress)(shunk_t, const struct ip_info *, ip_address *);
				bool need_dns;
			} lookups[] = {
				{
					"ttoaddress_num",
					ttoaddress_num,
					false,
				},
				{
					"ttoaddress_dns",
					ttoaddress_dns,
					true,
				},
				{
					.name = NULL,
				},
			};
			for (struct lookup *lookup = lookups; lookup->name != NULL; lookup++) {

				/*
				 * Without DNS a
				 * ttoaddress_dns() lookup of
				 * a bogus IP address will go
				 * into the weeds.
				 */
				bool skip = (lookup->need_dns && have_dns != DNS_YES);

				PRINT("%s('%s', %s) -> '%s'%s",
				      lookup->name, t->in, pri_afi(afi),
				      err_expected ? "ERROR" : t->str,
				      skip ? "; skipped as no DNS" : "");

				if (skip) {
					continue;
				}

				ip_address tmp, *address = &tmp;
				err = lookup->ttoaddress(shunk1(t->in), afi, address);
				if (err_expected) {
					if (err == NULL) {
						FAIL("%s(%s, %s) unexpectedly succeeded",
						     lookup->name, t->in, pri_afi(afi));
					}
					PRINT("%s(%s, %s) returned: %s",
					      lookup->name, t->in, pri_afi(afi), err);
				} else if (err != NULL) {
					FAIL("%s(%s, %s) unexpectedly failed: %s",
					     lookup->name, t->in, pri_afi(afi), err);
				} else {
					CHECK_STR2(address);
				}
			}
		}
	}
}

static void check_ttoaddress_dns(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		const char *str;
		bool need_dns;
	} tests[] = {

		/* localhost is found in /etc/hosts on all platforms */
		{ LN, 0, "localhost", "127.0.0.1", false, },
		{ LN, &ipv4_info, "localhost", "127.0.0.1", false, },
		{ LN, &ipv6_info, "localhost", "::1",       false, },

		{ LN, 0, "www.libreswan.org", "188.127.201.229", true, },
		{ LN, &ipv4_info, "www.libreswan.org", "188.127.201.229", true, },
		{ LN, &ipv6_info, "www.libreswan.org", "2a00:1190:c00a:f00::229", true, },

		{ LN, 0, "nowhere.libreswan.org", NULL, true, },
		{ LN, &ipv4_info, "nowhere.libreswan.org", NULL, true, },
		{ LN, &ipv6_info, "nowhere.libreswan.org", NULL, true, },

		{ LN, 0, "", NULL, false, },
		{ LN, &ipv4_info, "", NULL, false, },
		{ LN, &ipv6_info, "", NULL, false, },

	};

	err_t err;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		const struct ip_info *afi = t->afi;
		bool skip = (have_dns == DNS_NO || (have_dns != DNS_YES && t->need_dns));

		PRINT("%s '%s' -> str: '%s' lookup: %s%s",
		      pri_afi(t->afi), t->in,
		      t->str == NULL ? "ERROR" : t->str,
		      (t->need_dns ? "DNS" : "/etc/hosts"),
		      (skip ? "; skipped as no DNS" : ""));

		if (skip) {
			continue;
		}

		ip_address tmp, *address = &tmp;
		err = ttoaddress_dns(shunk1(t->in), afi, address);
		if (err != NULL) {
			if (t->str != NULL) {
				FAIL("ttoaddress_dns(%s, %s) unexpectedly failed: %s",
				     t->in, pri_afi(t->afi), err);
			}
			PRINT("ttoaddress_dns(%s, %s) failed as expected: %s",
			      t->in, pri_afi(t->afi), err);
		} else if (t->str == NULL) {
			address_buf b;
			FAIL("ttoaddress_dns(%s, %s) unexpectedly succeeded with %s",
			     t->in, pri_afi(t->afi),
			     str_address(address, &b));
		} else {
			address_buf b;
			PRINT("ttoaddress_dns(%s, %s) succeeded with %s",
			      t->in, pri_afi(t->afi),
			      str_address(address, &b));
			if (t->afi != NULL) {
				CHECK_INFO(address);
			}
			/* and back */
			CHECK_STR2(address);
		}
	}
}

static void check_str_address_sensitive(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		const char *out;
	} tests[] = {
		{ LN, &ipv4_info, "1.2.3.4",			"<address>" },
		{ LN, &ipv6_info, "1:12:3:14:5:16:7:18",	"<address>" },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> '%s'", pri_afi(t->afi), t->in, t->out);

		/* convert it *to* internal format */
		const struct ip_info *type = NULL;
		ip_address tmp, *address = &tmp;
		err_t err = ttoaddress_num(shunk1(t->in), type, address);
		if (err != NULL) {
			FAIL("ttoaddress_num() failed: %s", err);
		}
		CHECK_INFO(address);
		CHECK_STR(address_buf, address_sensitive, t->out, address);
	}
}

static void check_str_address_reversed(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		const char *out;                   /* NULL means error expected */
	} tests[] = {
		{ LN, &ipv4_info, "1.2.3.4", "4.3.2.1.IN-ADDR.ARPA." },
		/* 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f */
		{ LN, &ipv6_info, "0123:4567:89ab:cdef:1234:5678:9abc:def0",
		  "0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.IP6.ARPA.", }
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> '%s", pri_afi(t->afi), t->in, t->out);

		/* convert it *to* internal format */
		const struct ip_info *type = NULL;
		ip_address tmp, *address = &tmp;
		err_t err = ttoaddress_num(shunk1(t->in), type, address);
		if (err != NULL) {
			FAIL("ttoaddress_num() returned: %s", err);
		}
		CHECK_INFO(address);
		CHECK_STR(address_reversed_buf, address_reversed, t->out, address);
	}
}

static void check_in_addr(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		uint8_t addr[16];
	} tests[] = {
		{ LN, &ipv4_info, "1.2.3.4", { 1, 2, 3, 4, }, },
		{ LN, &ipv6_info, "102:304:506:708:90a:b0c:d0e:f10", { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, }, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> '%s'", pri_afi(t->afi), t->in, t->in);

		ip_address a;
		switch (t->afi->ip.version) {
		case IPv4:
		{
			struct in_addr in;
			memcpy(&in, t->addr, sizeof(in));
			a = address_from_in_addr(&in);
			break;
		}
		case IPv6:
		{
			struct in6_addr in6;
			memcpy(&in6, t->addr, sizeof(in6));
			a = address_from_in6_addr(&in6);
			break;
		}
		default:
			FAIL("test %zd has invalid family %s", ti,
			     pri_afi(t->afi));
		}

		/* as a string */
		address_buf buf;
		const char *out = str_address(&a, &buf);
		if (out == NULL) {
			FAIL("str_address() returned NULL");
		} else if (!strcaseeq(out, t->in)) {
			FAIL("str_address() returned '%s', expecting '%s'",
				out, t->in);
		}

	}
}

static void check_address_is(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		bool is_unset;
		bool is_specified;
		bool is_loopback;
	} tests[] = {
		{ LN, 0, "<invalid>",		.is_unset = true, },
		{ LN, &ipv4_info, "0.0.0.0",		.is_unset = false, },
		{ LN, &ipv6_info, "::",			.is_unset = false, },
		{ LN, &ipv4_info, "1.2.3.4",		.is_specified = true, },
		{ LN, &ipv6_info, "1:12:3:14:5:16:7:18",	.is_specified = true, },
		{ LN, &ipv4_info, "127.0.0.1",		.is_specified = true, .is_loopback = true, },
		{ LN, &ipv6_info, "::1",			.is_specified = true, .is_loopback = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s'-> unset: %s, specified: %s", pri_afi(t->afi), t->in,
		      bool_str(t->is_unset), bool_str(t->is_specified));

		/* convert it *to* internal format */
		ip_address tmp, *address = &tmp;
		if (t->afi == NULL) {
			tmp = unset_address;
		} else {
			const struct ip_info *type = NULL;
			err_t err = ttoaddress_num(shunk1(t->in), type, &tmp);
			if (err != NULL) {
				FAIL("ttoaddress_num() failed: %s", err);
			}
		}

		CHECK_COND(address, is_unset);
		CHECK_COND2(address, is_specified);
		CHECK_COND2(address, is_loopback);
	}
}

static void check_addresses_to(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *lo;
		const char *hi;
		const char *subnet;	/* NULL means error expected */
		const char *range;	/* NULL means use subnet */
	} tests[] = {

		/* zero-zero; zero-one */
		{ LN, &ipv4_info, "0.0.0.0", "0.0.0.0", NULL, NULL, },
		{ LN, &ipv6_info, "::",      "::",      NULL, NULL, },
		{ LN, &ipv4_info, "0.0.0.0", "0.0.0.1", "0.0.0.0/31", NULL, },
		{ LN, &ipv6_info, "::",      "::1",     "::/127", NULL, },

		/* single address */
		{ LN, &ipv4_info, "1.2.3.0",    "1.2.3.0",   "1.2.3.0/32", NULL, },
		{ LN, &ipv6_info, "::1",        "::1",       "::1/128", NULL, },
		{ LN, &ipv4_info, "1.2.3.4",    "1.2.3.4",   "1.2.3.4/32", NULL, },

		/* subnet */
		{ LN, &ipv4_info, "1.2.3.8",    "1.2.3.15", "1.2.3.8/29", NULL, },
		{ LN, &ipv4_info, "1.2.3.240",  "1.2.3.255", "1.2.3.240/28", NULL, },
		{ LN, &ipv4_info, "0.0.0.0",    "255.255.255.255", "0.0.0.0/0", NULL, },
		{ LN, &ipv4_info, "1.2.0.0",    "1.2.255.255", "1.2.0.0/16", NULL, },
		{ LN, &ipv4_info, "1.2.0.0",    "1.2.0.255", "1.2.0.0/24", NULL, },
		{ LN, &ipv4_info, "1.2.255.0",  "1.2.255.255", "1.2.255.0/24", NULL, },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:0",   "1:2:3:4:5:6:7:ffff", "1:2:3:4:5:6:7:0/112", NULL, },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:0",   "1:2:3:4:5:6:7:fff", "1:2:3:4:5:6:7:0/116", NULL, },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:f0",  "1:2:3:4:5:6:7:ff", "1:2:3:4:5:6:7:f0/124", NULL, },

		/* range only */
		{ LN, &ipv4_info, "1.2.3.0",    "1.2.3.254", NULL, "1.2.3.0-1.2.3.254", },
		{ LN, &ipv4_info, "1.2.3.0",    "1.2.3.126", NULL, "1.2.3.0-1.2.3.126", },
		{ LN, &ipv4_info, "1.2.3.0",    "1.2.3.125", NULL, "1.2.3.0-1.2.3.125", },
		{ LN, &ipv4_info, "1.2.255.1",  "1.2.255.255", NULL, "1.2.255.1-1.2.255.255", },
		{ LN, &ipv4_info, "1.2.0.1",    "1.2.255.255", NULL, "1.2.0.1-1.2.255.255", },

		/* all */
		{ LN, &ipv4_info, "0.0.0.0", IPv4_MAX, "0.0.0.0/0", NULL, },
		{ LN, &ipv6_info, "::",      IPv6_MAX, "::/0",      NULL, },

		/* wrong order */
		{ LN, &ipv4_info, "1.2.255.0",  "1.2.254.255", NULL, NULL, },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		/* range falls back to subnet */
		PRINT("%s-%s -> %s -> %s",
		      t->lo, t->hi,
		      t->range == NULL ? "<bad-range>" : t->range,
		      t->subnet == NULL ? "<bad-subnet>" : t->subnet);

		const struct ip_info *type = t->afi;

		ip_address lo;
		oops = ttoaddress_num(shunk1(t->lo), type, &lo);
		if (oops != NULL) {
			FAIL("ttoaddress_num(lo=%s) failed: %s", t->lo, oops);
		}

		ip_address hi;
		oops = ttoaddress_num(shunk1(t->hi), type, &hi);
		if (oops != NULL) {
			FAIL("ttoaddress_num(hi=%s) failed: %s", t->hi, oops);
		}

		ip_subnet s;
		oops = addresses_to_nonzero_subnet(lo, hi, &s);
		subnet_buf sb;
		str_subnet(&s, &sb);

		if (oops != NULL) {
			if (t->subnet != NULL) {
				FAIL("addresses_to_subnet(%s,%s) failed: %s", t->lo, t->hi, oops);
			}
		} else if (t->subnet == NULL) {
			FAIL("addresses_to_subnet(%s,%s) returned %s unexpectedly",
			     t->lo, t->hi, sb.buf);
		} else if (!streq(t->subnet, sb.buf)) {
			FAIL("addresses_to_subnet(%s,%s) returned `%s', expected `%s'",
			     t->lo, t->hi, sb.buf, t->subnet);
		}

		ip_range r;
		range_buf rb;
		oops = addresses_to_nonzero_range(lo, hi, &r);
		str_range(&r, &rb);

		if (oops != NULL) {
			if (t->range != NULL || t->subnet != NULL) {
				FAIL("addresses_to_range(%s,%s) unexpectedly failed: %s",
				     t->lo, t->hi, oops);
			}
		} else if (t->range != NULL) {
			if (!streq(t->range, rb.buf)) {
				FAIL("addresses_to_range(%s,%s) returned `%s', expected `%s'",
				     t->lo, t->hi, rb.buf, t->range);
			}
		} else if (t->subnet != NULL) {
			if (!streq(t->subnet, rb.buf)) {
				FAIL("addresses_to_range(%s,%s) returned `%s', expected `%s'",
				     t->lo, t->hi, rb.buf, t->subnet);
			}
		} else {
			FAIL("addresses_to_range(%s,%s) returned %s unexpectedly",
			     t->lo, t->hi, rb.buf);
		}

		if (t->range == NULL) {
			continue;
		}

		oops = range_to_subnet(r, &s);
		str_subnet(&s, &sb);

		if (oops != NULL && t->subnet == NULL) {
			/* okay, error expected */
		} else if (oops != NULL) {
			FAIL("range_to_subnet(%s=>%s) failed: %s",
			     rb.buf, sb.buf, oops);
		} else if (t->subnet == NULL) {
			FAIL("range_to_subnet(%s) returned %s unexpectedly",
			     rb.buf, sb.buf);
		} else {
			if (!streq(t->subnet, sb.buf)) {
				FAIL("range_to_subnet(%s) returned `%s', expected `%s'",
				     rb.buf, sb.buf, t->subnet);
			}
		}

	}
}

void ip_address_check(void)
{
	check_ttoaddress_num();
	check_ttoaddress_dns();
	check_str_address_sensitive();
	check_str_address_reversed();
	check_address_is();
	check_in_addr();
	check_addresses_to();
}
