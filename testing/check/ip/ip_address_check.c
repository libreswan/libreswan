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

static void check_str_address_raw(void)
{
	static const struct test {
		int family;
		const char *in;
		const char sep;
		const char *out;
	} tests[] = {
		/* any */
		{ 4, "0.0.0.0", 0, "0.0.0.0", },
		{ 6, "::", 0, "0:0:0:0:0:0:0:0", },
		/* all */
		{ 4, "1.2.3.4", 0, "1.2.3.4", },
		{ 6, "1:2:3:4:5:6:7:8", 0, "1:2:3:4:5:6:7:8", },
		/* local */
		{ 4, "127.0.0.1", 0, "127.0.0.1", },
		{ 6, "::1", 0, "0:0:0:0:0:0:0:1", },
		/* different sepc */
		{ 4, "127.0.0.1", '/', "127/0/0/1", },
		{ 6, "1:2::7:8", '/', "1/2/0/0/0/0/7/8", },
		/* buffer overflow */
		{ 4, "255.255.255.255", 0, "255.255.255.255", },
		{ 6, "1111:2222:3333:4444:5555:6666:7777:8888", 0, "1111:2222:3333:4444:5555:6666:7777:8888", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		if (t->sep == 0) {
			PRINT_IN(stdout, " 0 -> '%s'", t->out);
		} else {
			PRINT_IN(stdout, " '%c' -> '%s'", t->sep, t->out);
		}

		/* convert it *to* internal format */
		ip_address a;
		err_t err = ttoaddr(t->in, strlen(t->in), AF_UNSPEC, &a);
		if (err != NULL) {
			FAIL_IN("ttoaddr failed: %s", err);
			continue;
		}
		CHECK_TYPE(FAIL_IN, address_type(&a), t->family);

		/* now convert it back */
		address_buf buf;
		const char *out = str_address_raw(&a, t->sep, &buf);
		if (out == NULL) {
			FAIL_IN("failed");
		} else if (!strcaseeq(t->out, out)) {
			FAIL_IN("returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_str_address(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *out;
	} tests[] = {
		/* anything else? */
		{ 4, "0.0.0.0", "0.0.0.0", },
		{ 4, "1.2.3.4", "1.2.3.4" },

		/* suppress leading zeros - 01 vs 1 */
		{ 6, "1:12:3:14:5:16:7:18",	"1:12:3:14:5:16:7:18" },
		/* drop leading 0:0: */
		{ 6, "0:0:3:4:5:6:7:8",		"::3:4:5:6:7:8" },
		/* drop middle 0:...:0 */
		{ 6, "1:2:0:0:0:0:7:8",		"1:2::7:8" },
		/* drop trailing :0..:0 */
		{ 6, "1:2:3:4:5:0:0:0",		"1:2:3:4:5::" },
		/* drop first 0:..:0 */
		{ 6, "1:2:0:0:3:4:0:0",		"1:2::3:4:0:0" },
		/* drop logest 0:..:0 */
		{ 6, "0:0:3:0:0:0:7:8",		"0:0:3::7:8" },
		/* need two 0 */
		{ 6, "0:2:0:4:0:6:0:8",		"0:2:0:4:0:6:0:8" },
		/* edge cases */
		{ 6, "0:0:0:0:0:0:0:1",		"::1" },
		{ 6, "0:0:0:0:0:0:0:0",		"::" },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> '%s'", t->out);

		/* convert it *to* internal format */
		ip_address a;
		err_t err = ttoaddr(t->in, strlen(t->in), AF_UNSPEC, &a);
		if (err != NULL) {
			FAIL_IN("%s", err);
			continue;
		}
		CHECK_TYPE(FAIL_IN, address_type(&a), t->family);

		/* now convert it back */
		address_buf buf;
		const char *out = str_address(&a, &buf);
		if (out == NULL) {
			FAIL_IN("failed");
		} else if (!strcaseeq(t->out, out)) {
			FAIL_IN("returned '%s', expected '%s'",
				out, t->out);
		}
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
		ip_address a;
		err_t err = ttoaddr(t->in, strlen(t->in), AF_UNSPEC, &a);
		if (err != NULL) {
			FAIL_IN("%s", err);
			continue;
		}
		CHECK_TYPE(FAIL_IN, address_type(&a), t->family);

		/* now convert it back */
		address_buf buf;
		const char *out = str_address_sensitive(&a, &buf);
		if (out == NULL) {
			FAIL_IN("failed");
		} else if (!strcaseeq(t->out, out)) {
			FAIL_IN("returned '%s', expected '%s'",
				out, t->out);
		}
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
		ip_address a;
		err_t err = ttoaddr(t->in, strlen(t->in), AF_UNSPEC, &a);
		if (err != NULL) {
			FAIL_IN("%s", err);
			continue;
		}
		CHECK_TYPE(FAIL_IN, address_type(&a), t->family);

		address_reversed_buf buf;
		const char *out = str_address_reversed(&a, &buf);
		if (!strcaseeq(t->out, out)) {
			FAIL_IN("str_address_reversed returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_address_any(void)
{
	static const struct test {
		int family;
		const char *in;
		bool any;
	} tests[] = {
		{ 4, "<%any>",			true },
		{ 6, "<%any6>",			true },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		const char *any = t->any ? "true" : "false";
		PRINT_IN(stdout, "-> %s", any);

		/* convert it *to* internal format */
		ip_address a = address_any(IP_TYPE(t->family));
		bool a_is_any = address_is_any(&a);
		if (a_is_any != t->any) {
			FAIL_IN("addres_is_any() returned %s, expected %s",
				a_is_any ? "true" : "false", any);
		}
		CHECK_TYPE(FAIL_IN, address_type(&a), t->family);
	}
}

static void check_address_is(void)
{
	static const struct test {
		int family;
		const char *in;
		bool invalid;
		bool any;
		bool specified;
	} tests[] = {
		{ 0, "<invalid>",		.invalid = true, },
		{ 4, "0.0.0.0",			.any = true, },
		{ 6, "::",			.any = true, },
		{ 4, "1.2.3.4",			.specified = true, },
		{ 6, "1:12:3:14:5:16:7:18",	.specified = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, "-> invalid: %s, any: %s, specified: %s",
			 bool_str(t->invalid), bool_str(t->any), bool_str(t->specified));

		/* convert it *to* internal format */
		ip_address a;
		if (t->family == 0) {
			a = address_invalid;
		} else {
			err_t err = ttoaddr(t->in, strlen(t->in), AF_UNSPEC, &a);
			if (err != NULL) {
				FAIL_IN("%s", err);
			}
		}
		CHECK_TYPE(FAIL_IN, address_type(&a), t->family);

		/* aka address_type(&a) == NULL; */
		bool invalid = address_is_invalid(&a);
		if (invalid != t->invalid) {
			FAIL_IN("addres_is_invalid() returned %s, expected %s",
				bool_str(invalid), bool_str(t->invalid));
		}

		bool any = address_is_any(&a);
		if (any != t->any) {
			FAIL_IN("addres_is_any() returned %s, expected %s",
				bool_str(any), bool_str(t->any));
		}

		bool specified = address_is_specified(&a);
		if (specified != t->specified) {
			FAIL_IN("addres_is_specified() returned %s, expected %s",
				bool_str(specified), bool_str(t->specified));
		}
	}
}


static void check_ttoaddr_dns(void)
{
	static const struct test {
		int family;
		const char *in;
		bool numonly;
		bool expectfailure;
		const char *out;	/* NULL means error expected */
	} tests[] = {
		{ 4, "www.libreswan.org", false, false, "188.127.201.229" },
		{ 0, "www.libreswan.org", true, true, "1.2.3.4" },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		if (!t->numonly && !use_dns) {
			PRINT_IN(stdout, "%s%s -> '%s' SKIPPED - NO DNS",
				 t->numonly ? "" : " DNS",
				 t->expectfailure ? " fail" : "",
				 t->out);
			continue;
		}
		PRINT_IN(stdout, "%s%s -> '%s",
			 t->numonly ? "" : " DNS",
			 t->expectfailure ? " fail" : "",
			 t->out);
		sa_family_t af = SA_FAMILY(t->family);

		ip_address a;
		memset(&a, 0, sizeof(a));

		if (t->numonly) {
			/* convert it *to* internal format (no DNS) */
			oops = ttoaddr_num(t->in, strlen(t->in), af, &a);
		} else {
			/* convert it *to* internal format */
			oops = ttoaddr(t->in, strlen(t->in), af, &a);
		}
		CHECK_TYPE(FAIL_IN, address_type(&a), t->family);

		if (t->expectfailure && oops == NULL) {
			FAIL_IN("expected failure, but it succeeded");
			continue;
		}

		if (oops != NULL) {
			if (!t->expectfailure) {
				FAIL_IN("failed to parse: %s", oops);
			}
			continue;
		}

		/* now convert it back */
		address_buf buf;
		const char *out = str_address(&a, &buf);
		if (!strcaseeq(t->out, out)) {
			FAIL_IN("addrtoc returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

void ip_address_check(void)
{
	check_str_address_raw();
	check_str_address();
	check_str_address_sensitive();
	check_str_address_reversed();
	check_address_any();
	check_address_is();
	check_ttoaddr_dns();
}
