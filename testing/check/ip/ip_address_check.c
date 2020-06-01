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
#include "jambuf.h"
#include "ipcheck.h"

static void check_shunk_to_address(void)
{
	static const struct test {
		int family;
		const char *in;
		const char sep;
		const char *cooked;
		const char *raw;
		bool requires_dns;
	} tests[] = {

		/* any/unspec */
		{ 4, "0.0.0.0", 0, "0.0.0.0", NULL, false, },
		{ 6, "::", 0, "::", "0:0:0:0:0:0:0:0", false, },
		{ 6, "0:0:0:0:0:0:0:0", 0, "::", "0:0:0:0:0:0:0:0", false, },

		/* local */
		{ 4, "127.0.0.1", 0, "127.0.0.1", NULL, false, },
		{ 6, "::1", 0, "::1", "0:0:0:0:0:0:0:1", false, },
		{ 6, "0:0:0:0:0:0:0:1", 0, "::1", "0:0:0:0:0:0:0:1", false, },

		/* mask - and buffer overflow */
		{ 4, "255.255.255.255", 0, "255.255.255.255", NULL, false, },
		{ 6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", NULL, false, },

		/* all bytes and '/' */
		{ 4, "1.2.3.4", '/', "1.2.3.4", "1/2/3/4", false, },
		{ 6, "1:2:3:4:5:6:7:8", '/', "1:2:3:4:5:6:7:8", "1/2/3/4/5/6/7/8", false, },

		/* suppress leading zeros - 01 vs 1 */
		{ 6, "0001:0012:0003:0014:0005:0016:0007:0018", 0, "1:12:3:14:5:16:7:18", NULL, false, },
		/* drop leading 0:0: */
		{ 6, "0:0:3:4:5:6:7:8", 0, "::3:4:5:6:7:8", "0:0:3:4:5:6:7:8", false, },
		/* drop middle 0:...:0 */
		{ 6, "1:2:0:0:0:0:7:8", 0, "1:2::7:8", "1:2:0:0:0:0:7:8", false, },
		/* drop trailing :0..:0 */
		{ 6, "1:2:3:4:5:0:0:0", 0, "1:2:3:4:5::", "1:2:3:4:5:0:0:0", false, },
		/* drop first 0:..:0 */
		{ 6, "1:2:0:0:5:6:0:0", 0, "1:2::5:6:0:0", "1:2:0:0:5:6:0:0", false, },
		/* drop logest 0:..:0 */
		{ 6, "0:0:3:0:0:0:7:8", 0, "0:0:3::7:8", "0:0:3:0:0:0:7:8", false, },
		/* need two 0 */
		{ 6, "0:2:0:4:0:6:0:8", 0, "0:2:0:4:0:6:0:8", NULL, false, },

		{ 4, "www.libreswan.org", 0, "188.127.201.229", .requires_dns = true, },
	};

	err_t err;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " '%c' -> cooked: %s raw: %s dns: %s",
			 t->sep == 0 ? '0' : t->sep,
			 t->cooked == NULL ? "ERROR" : t->cooked,
			 t->raw == NULL ? t->cooked == NULL ? "ERROR" : t->cooked : t->raw,
			 bool_str(t->requires_dns));

		const struct ip_info *type;
		ip_address a;

		/* NUMERIC/NULL */

		type = NULL;
		err = numeric_to_address(shunk1(t->in), type, &a);
		if (err != NULL) {
			if (t->cooked != NULL && !t->requires_dns) {
				FAIL_IN("numeric_to_address(NULL) unexpecedly failed: %s", err);
			}
		} else if (t->requires_dns) {
			FAIL_IN(" numeric_to_address(NULL) unexpecedly parsed a DNS address");
		} else if (t->cooked == NULL) {
			FAIL_IN(" numeric_to_address(NULL) unexpecedly succeeded");
		} else {
			CHECK_TYPE(PRINT_IN, address_type(&a));
		}

		/* NUMERIC/TYPE */

		type = IP_TYPE(t->family);
		err = numeric_to_address(shunk1(t->in), type, &a);
		if (err != NULL) {
			if (!t->requires_dns && t->raw != NULL) {
				FAIL_IN(" numeric_to_address(type) unexpecedly failed: %s", err);
			}
		} else if (t->requires_dns) {
			FAIL_IN(" numeric_to_address(type) unexpecedly parsed a DNS address");
		} else if (t->cooked == NULL) {
			FAIL_IN(" numeric_to_address(type) unexpecedly succeeded");
		} else {
			CHECK_TYPE(PRINT_IN, address_type(&a));
		}

		if (t->requires_dns && !use_dns) {
			PRINT_IN(stdout, " skipping str_address() tests as no DNS");
			continue;
		}

		/* DNS/TYPE */

		if (t->requires_dns && !use_dns) {
			PRINT_IN(stdout, " skipping dns_hunk_to_address(type) -- no DNS");
		} else {
			type = IP_TYPE(t->family);
			err = domain_to_address(shunk1(t->in), type, &a);
			if (err != NULL) {
				if (t->cooked != NULL) {
					FAIL_IN("dns_hunk_to_address(type) unexpecedly failed: %s", err);
				}
			} else if (t->cooked == NULL) {
				FAIL_IN(" dns_hunk_to_address(type) unexpecedly succeeded");
			} else {
				CHECK_TYPE(PRINT_IN, address_type(&a));
			}
		}

		/* now convert it back cooked */
		CHECK_STR(address_buf, address, t->cooked, &a);
		CHECK_STR(address_buf, address_raw, t->raw == NULL ? t->cooked : t->raw, &a, t->sep);

	}
}

static void check_str_address_sensitive(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *out;
	} tests[] = {
		{ 4, "1.2.3.4",			"<ip-address>" },
		{ 6, "1:12:3:14:5:16:7:18",	"<ip-address>" },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> '%s'", t->out);

		/* convert it *to* internal format */
		const struct ip_info *type = NULL;
		ip_address a;
		err_t err = numeric_to_address(shunk1(t->in), type, &a);
		if (err != NULL) {
			FAIL_IN("numeric_to_address() failed: %s", err);
			continue;
		}
		CHECK_TYPE(PRINT_IN, address_type(&a));
		CHECK_STR(address_buf, address_sensitive, t->out, &a);
	}
}

static void check_str_address_reversed(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *out;                   /* NULL means error expected */
	} tests[] = {
		{ 4, "1.2.3.4", "4.3.2.1.IN-ADDR.ARPA." },
		/* 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f */
		{ 6, "0123:4567:89ab:cdef:1234:5678:9abc:def0",
		  "0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.IP6.ARPA.", }
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> '%s", t->out);

		/* convert it *to* internal format */
		const struct ip_info *type = NULL;
		ip_address a;
		err_t err = numeric_to_address(shunk1(t->in), type, &a);
		if (err != NULL) {
			FAIL_IN("numeric_to_address() returned: %s", err);
			continue;
		}
		CHECK_TYPE(PRINT_IN, address_type(&a));
		CHECK_STR(address_reversed_buf, address_reversed, t->out, &a);
	}
}

static void check_in_addr(void)
{
	static const struct test {
		const int family;
		const char *in;
		uint8_t addr[16];
	} tests[] = {
		{ 4, "1.2.3.4", { 1, 2, 3, 4, }, },
		{ 6, "102:304:506:708:90a:b0c:d0e:f10", { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, }, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> '%s'", t->in);

		ip_address a;
		switch (t->family) {
		case 4:
		{
			struct in_addr in;
			memcpy(&in, t->addr, sizeof(in));
			a = address_from_in_addr(&in);
			break;
		}
		case 6:
		{
			struct in6_addr in6;
			memcpy(&in6, t->addr, sizeof(in6));
			a = address_from_in6_addr(&in6);
			break;
		}
		}

		/* as a string */
		address_buf buf;
		const char *out = str_address(&a, &buf);
		if (out == NULL) {
			FAIL_IN("str_address() returned NULL");
		} else if (!strcaseeq(out, t->in)) {
			FAIL_IN("str_address() returned '%s', expecting '%s'",
				out, t->in);
		}

		switch (t->family) {
		case 4:
		{
			uint32_t h = ntohl_address(&a);
			uint32_t n = htonl(h);
			if (!memeq(&n, t->addr, sizeof(n))) {
				FAIL_IN("ntohl_address() returned %08"PRIx32", expecting something else", h);
			}
			break;
		}
		}
	}
}

static void check_address_is(void)
{
	static const struct test {
		int family;
		const char *in;
		bool set;
		bool any;
		bool specified;
		bool loopback;
	} tests[] = {
		{ 0, "<invalid>",		.set = false, },
		{ 4, "0.0.0.0",			.set = true, .any = true, },
		{ 6, "::",			.set = true, .any = true, },
		{ 4, "1.2.3.4",			.set = true, .specified = true, },
		{ 6, "1:12:3:14:5:16:7:18",	.set = true, .specified = true, },
		{ 4, "127.0.0.1",		.set = true, .specified = true, .loopback = true, },
		{ 6, "::1",			.set = true, .specified = true, .loopback = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, "-> set: %s, any: %s, specified: %s",
			 bool_str(t->set), bool_str(t->any), bool_str(t->specified));

		/* convert it *to* internal format */
		ip_address a;
		if (t->family == 0) {
			a = unset_address;
		} else {
			const struct ip_info *type = NULL;
			err_t err = numeric_to_address(shunk1(t->in), type, &a);
			if (err != NULL) {
				FAIL_IN("numeric_to_address() failed: %s", err);
			}
		}

		CHECK_ADDRESS(PRINT_IN, &a);
	}
}

void ip_address_check(void)
{
	check_shunk_to_address();
	check_str_address_sensitive();
	check_str_address_reversed();
	check_address_is();
	check_in_addr();
}
