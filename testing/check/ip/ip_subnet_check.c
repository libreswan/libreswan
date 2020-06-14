/* test subnets, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2018, 2019  Andrew Cagney
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
#include "ip_selector.h"	/* should be in ip_selector_check.c */

static void check_str_subnet(void)
{
	static const struct test {
		int family;
		char *in;
		char *out;	/* NULL means error expected */
	} tests[] = {
		{ 4, "1.2.3.0/255.255.255.0", "1.2.3.0/24" },
		{ 4, "1.2.3.0/24", "1.2.3.0/24" },
		{ 4, "1.2.3.0/255.255.255.240", "1.2.3.0/28" },
		{ 4, "1.2.3.1/32", "1.2.3.1/32" },
		{ 4, "0.0.0.0/0", "0.0.0.0/0" },
/*	{4, "1.2.3.0/255.255.127.0",	"1.2.3.0/255.255.127.0"}, */
		{ 4, "1.2.3.1/255.255.127.0", NULL },
		{ 4, "128.009.000.032/32", "128.9.0.32/32" },
		{ 4, "128.0x9.0.32/32", NULL },
		{ 4, "0x80090020/32", "128.9.0.32/32" },
		{ 4, "0x800x0020/32", NULL },
		{ 4, "128.9.0.0/0xffFF0000", "128.9.0.0/16" },
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
		{ 6, "::/0", "::/0" },
		{ 6, "3049:1::8007:2040/128", "3049:1::8007:2040/128" },
		{ 6, "3049:1::192.168.0.1/128", NULL },	/*"3049:1::c0a8:1/128",*/
		{ 6, "3049:1::8007::2040/128", NULL },
		{ 6, "3049:1::8007:2040/ffff:0", NULL },
		{ 6, "3049:1::/64", "3049:1::/64" },
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
		{ 6, "3049:10::/28", "3049:10::/28" },
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
		oops = ttosubnet(t->in, 0, af, '6', &s);
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

		CHECK_TYPE(PRINT_IN, subnet_type(&s));

		subnet_buf buf;
		const char *out = str_subnet(&s, &buf);
		if (!streq(t->out, out)) {
			FAIL_IN("str_subnet() returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_str_subnet_port(void)
{
	/*
	 * XXX: can't yet do invalid ports.
	 */
	static const struct test {
		int family;
		char *in;
		char *out;	/* NULL means error expected */
	} tests[] = {
		/* no port as in :0 should not appear (broken as uint16_t port) */
		{ 4, "0.0.0.0/0", "0.0.0.0/0:0" },
		{ 6, "::/0", "::/0:0", },
		/* any */
		{ 4, "0.0.0.0/0:0", "0.0.0.0/0:0" },
		{ 6, "::/0:0", "::/0:0", },
		/* longest */
		{ 4, "101.102.103.104/32:65535", "101.102.103.104/32:65535" },
		{ 6, "1001:1002:1003:1004:1005:1006:1007:1008/128:65535", "1001:1002:1003:1004:1005:1006:1007:1008/128:65535", },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> '%s'",
			 t->out ? t->out : "<error>");

		sa_family_t af = SA_FAMILY(t->family);

		ip_subnet s;
		oops = ttosubnet(t->in, 0, af, '6', &s);
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

		CHECK_TYPE(PRINT_IN, subnet_type(&s));

		selector_buf buf;
		const char *out = str_selector(&s, &buf);
		if (!streq(t->out, out)) {
			FAIL_IN("str_subnet_port() returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_subnet_mask(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *mask;
	} tests[] = {
		{ 4, "0.0.0.0/1", "128.0.0.0", },
		{ 4, "1.2.0.0/23", "255.255.254.0", },
		{ 4, "1.2.3.0/24", "255.255.255.0", },
		{ 4, "1.2.3.0/25", "255.255.255.128", },
		{ 4, "1.2.3.4/31", "255.255.255.254", },
		{ 4, "1.2.3.4/32", "255.255.255.255", },
		{ 6, "0::/1", "8000::", },
		{ 6, "1:2:3:4::/63", "ffff:ffff:ffff:fffe::", },
		{ 6, "1:2:3:4::/64", "ffff:ffff:ffff:ffff::", },
		{ 6, "1:2:3:4::/65", "ffff:ffff:ffff:ffff:8000::", },
		{ 6, "1:2:3:4:5:6:7:8/127", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", },
		{ 6, "1:2:3:4:5:6:7:8/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> %s", t->mask);

		sa_family_t af = SA_FAMILY(t->family);

		ip_subnet s;
		err_t oops = ttosubnet(t->in, 0, af, '6', &s);
		if (oops != NULL) {
			FAIL_IN("ttosubnet() failed: %s", oops);
		}

		CHECK_TYPE(PRINT_IN, subnet_type(&s));

		address_buf buf;
		const char *out;

		ip_address mask = subnet_mask(&s);
		out = str_address(&mask, &buf);
		if (!streq(t->mask, out)) {
			FAIL_IN("subnet_mask() returned '%s', expected '%s'",
				out, t->mask);
		}
		CHECK_TYPE(PRINT_IN, address_type(&mask));
	}
}

static void check_subnet_prefix(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *out;
	} tests[] = {
		{ 4, "128.0.0.0/1", "128.0.0.0", },
		{ 6, "8000::/1", "8000::", },

		{ 4, "1.2.254.0/23", "1.2.254.0", },
		{ 4, "1.2.255.0/24", "1.2.255.0", },
		{ 4, "1.2.255.128/25", "1.2.255.128", },
		{ 6, "1:2:3:fffe::/63", "1:2:3:fffe::", },
		{ 6, "1:2:3:ffff::/64", "1:2:3:ffff::", },
		{ 6, "1:2:3:ffff:8000::/65", "1:2:3:ffff:8000::", },

		{ 4, "1.2.3.254/31", "1.2.3.254", },
		{ 4, "1.2.3.255/32", "1.2.3.255", },
		{ 6, "1:2:3:4:5:6:7:fffe/127", "1:2:3:4:5:6:7:fffe", },
		{ 6, "1:2:3:4:5:6:7:ffff/128", "1:2:3:4:5:6:7:ffff", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, " -> %s", t->out);

		sa_family_t af = SA_FAMILY(t->family);

		ip_subnet s;
		err_t oops = ttosubnet(t->in, 0, af, '6', &s);
		if (oops != NULL) {
			FAIL_IN("ttosubnet() failed: %s", oops);
		}

		CHECK_TYPE(PRINT_IN, subnet_type(&s));

		ip_address prefix = subnet_prefix(&s);
		CHECK_TYPE(PRINT_IN, address_type(&prefix));

		address_buf buf;
		const char *out = str_address(&prefix, &buf);
		if (!streq(out, t->out)) {
			FAIL_IN("subnet_prefix() returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_cidr_to_subnet(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *prefix;
		const char *host;
	} tests[] = {
		{ 4, "128.0.0.0/0", "0.0.0.0", "128.0.0.0", },
		{ 6, "8000::/0", "::", "8000::", },

		{ 4, "128.0.0.0/1", "128.0.0.0", "0.0.0.0", },
		{ 6, "8000::/1", "8000::", "::", },

		{ 4, "1.2.255.4/23", "1.2.254.0", "0.0.1.4", },
		{ 4, "1.2.255.255/24", "1.2.255.0", "0.0.0.255", },
		{ 4, "1.2.3.255/25", "1.2.3.128", "0.0.0.127", },

		{ 6, "1:2:3:ffff::/63", "1:2:3:fffe::", "0:0:0:1::", },
		{ 6, "1:2:3:ffff:ffff::/64", "1:2:3:ffff::", "::ffff:0:0:0", },
		{ 6, "1:2:3:4:ffff::/65", "1:2:3:4:8000::", "::7fff:0:0:0", },

		{ 4, "1.2.3.255/31", "1.2.3.254", "0.0.0.1", },
		{ 4, "1.2.3.255/32", "1.2.3.255", "0.0.0.0", },
		{ 6, "1:2:3:4:5:6:7:ffff/127", "1:2:3:4:5:6:7:fffe", "::1", },
		{ 6, "1:2:3:4:5:6:7:ffff/128", "1:2:3:4:5:6:7:ffff", "::", },

		{ 4, "1.2.3.4", NULL, NULL, },
		{ 6, "1:2:3:4:5:6:7:8", NULL, NULL, },
		{ 4, "1.2.3.255/33", NULL, NULL, },
		{ 6, "1:2:3:4:5:6:7:ffff/129", NULL, NULL, },
	};

#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s %s %s"FMT,					\
	      t->in,							\
	      t->prefix != NULL ? t->prefix : "N/A",			\
	      t->host != NULL ? t->host : "N/A",			\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		OUT(stdout, "");

		ip_subnet subnet;
		err_t err = text_cidr_to_subnet(shunk1(t->in), IP_TYPE(t->family), &subnet);
		if (err != NULL) {
			if (t->prefix != NULL) {
				FAIL(OUT, "cidr_to_subnet() unexpectedly failed: %s", err);
			}
			continue;
		} else if (t->prefix == NULL) {
			FAIL(OUT, "cidr_to_subnet() unexpectedly succeeded");
		}

		CHECK_TYPE(OUT, subnet_type(&subnet));

		ip_address prefix = subnet_prefix(&subnet);
		address_buf pb;
		const char *p = str_address(&prefix, &pb);
		if (!streq(p, t->prefix)) {
			FAIL(OUT, "subnet_prefix() returned '%s', expected '%s'",
			     p, t->prefix);
		}

		ip_address host = subnet_host(&subnet);
		address_buf hb;
		const char *h = str_address(&host, &hb);
		if (!streq(h, t->host)) {
			FAIL(OUT, "subnet_host() returned '%s', expected '%s'",
			     h, t->host);
		}
#undef OUT
	}
}

static void check_subnet_contains(void)
{
	static const struct test {
		int family;
		const char *in;
		bool is_unset;
		bool contains_all_addresses;
		bool is_specified;
		bool contains_one_address;
		bool contains_no_addresses;
	} tests[] = {
		/* unset */
		{ 0, NULL,           true, false, false, false, false, },
		/* all_addresses */
		{ 4, "0.0.0.0/0",    false, true, false, false, false, },
		{ 6, "::/0",         false, true, false, false, false, },
		/* some_address+one_address? */
		{ 4, "127.0.0./31",  false, false, true, false, false, },
		{ 6, "1::/127",      false, false, true, false, false,  },
		/* one_address */
		{ 4, "127.0.0.1/32", false, false, true, true, false, },
		{ 6, "::1/128",      false, false, true, true, false,  },
		/* no_addresses */
		{ 4, "0.0.0.0/32",   false, false, false, false, true, },
		{ 6, "::/128",       false, false, false, false, true, },
	};
#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s %s unset=%s all=%s some=%s one=%s none=%s"FMT,	\
	      pri_family(t->family),					\
	      t->in != NULL ? t->in : "<unset>",			\
	      bool_str(t->is_unset),					\
	      bool_str(t->contains_all_addresses),			\
	      bool_str(t->is_specified),				\
	      bool_str(t->contains_one_address),			\
	      bool_str(t->contains_no_addresses),			\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		OUT(stdout, "");

		ip_subnet s = unset_subnet;
		if (t->family != 0) {
			sa_family_t af = SA_FAMILY(t->family);
			err_t oops = ttosubnet(t->in, 0, af, '6', &s);
			if (oops != NULL) {
				FAIL(OUT, "ttosubnet() failed: %s", oops);
			}
			CHECK_TYPE(OUT, subnet_type(&s));
		}

#define T(COND)								\
		bool COND = subnet_##COND(&s);				\
		if (COND != t->COND) {					\
			FAIL(OUT, "subnet_"#COND"() returned %s, expecting %s", \
			     bool_str(COND), bool_str(t->COND));	\
		}
		T(is_unset);
		T(contains_no_addresses);
		T(is_specified);
		T(contains_one_address);
		T(contains_all_addresses);
	}
#undef T
#undef OUT

}

static bool address_is_0xff(const ip_address *a)
{
	shunk_t bytes = address_as_shunk(a);
	const uint8_t *byte = bytes.ptr;
	for (unsigned i = 0; i < bytes.len; i++) {
		if (byte[i] != 0xff) {
			return false;
		}
	}
	return true;
}

static void check_subnet_from_address(void)
{
	static const struct test {
		int family;
		const char *in;
		const char *mask;
	} tests[] = {
		{ 4, "0.0.0.0", NULL, },
		{ 6, "::", NULL, },
		{ 4, "127.0.0.1", NULL, },
		{ 6, "::1",  NULL, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, "");

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address a;
		err_t oops = numeric_to_address(shunk1(t->in), type, &a);
		if (oops != NULL) {
			FAIL_IN("numeric_to_address() failed: %s", oops);
		}
		ip_subnet s = subnet_from_address(&a);

		CHECK_TYPE(PRINT_IN, subnet_type(&s));

		int hport = subnet_hport(&s);
		if (hport != 0) {
			FAIL_IN("subnet_port() returned %d, expecting 0", hport);
		}

		ip_address prefix = subnet_prefix(&s);
		if (!sameaddr(&prefix, &a)) {
			address_buf pb, ab;
			FAIL_IN("subnet_prefix(&s) returned %s, expecting %s",
				str_address(&prefix, &pb), str_address(&a, &ab));
		}

		ip_address mask = subnet_mask(&s);
		if (!address_is_0xff(&mask)) {
			address_buf mb;
			FAIL_IN("subnet_mask(&s) returned %s, expecting 255.255.255.255",
				str_address(&mask, &mb));
		}
	}
}

static void check_address_mask_to_subnet(void)
{
	static const struct test {
		const char *address;
		const char *mask;
		const char *subnet;
	} tests[] = {
		/* XXX: this code isn/t used by IPv6? */

		/* any address */
		{ "0.0.0.0", "0.0.0.0", "0.0.0.0/0" },
		{ "::", "::", "::/0" },

		/* one address */
		{ "1.2.3.4", "255.255.255.255", "1.2.3.4/32" },
		{ "1:2:3:4:5:6:7:8", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1:2:3:4:5:6:7:8/128" },

		/* subnet boundary on byte */
		{ "1.2.0.0", "255.255.0.0", "1.2.0.0/16" },
		{ "1:2:3:4::", "ffff:ffff:ffff:ffff::", "1:2:3:4::/64" },

		/* subnet boundary within byte */
		{ "1.2.192.0", "255.255.192.0", "1.2.192.0/18" },
		{ "1:2:3:4:c000::", "ffff:ffff:ffff:ffff:c000::", "1:2:3:4:c000::/66" },

		/* address/mask type mashup */
		{ "1.2.192.0", "::", NULL, },
		{ "1:2:3:4:c000::", "0.0.0.0", NULL, },

		/* gaps */
		{ "1.2.3.4", "255.0.255.0", NULL, },
		{ "1.2.3.4", "255.254.255.255", NULL, },

		/* fixup screwup */
		{ "1.2.3.255", "255.255.255.0", "1.2.3.0/24", },
		{ "1.2.3.255", "255.255.255.128", "1.2.3.128/25", },

	};
#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s/%s -> %s"FMT,					\
	      t->address != NULL ? t->address : "N/A",			\
	      t->mask != NULL ? t->mask : "N/A",			\
	      t->subnet != NULL ? t->subnet : "<error>",		\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		err_t err;
		const struct test *t = &tests[ti];
		OUT(stdout, "");

		ip_address address;
		err = numeric_to_address(shunk1(t->address), NULL, &address);
		if (err != NULL) {
			FAIL(OUT, "numeric_to_address(%s) failed: %s",
			     t->address, err);
		}

		ip_address mask;
		err = numeric_to_address(shunk1(t->mask), NULL, &mask);
		if (err != NULL) {
			FAIL(OUT, "numeric_to_address(%s) failed: %s",
			     t->mask, err);
		}

		ip_subnet subnet;
		err = address_mask_to_subnet(&address, &mask, &subnet);
		if (err != NULL) {
			if (t->subnet != NULL) {
				FAIL(OUT, "address_mask_to_subnet() unexpectedly failed: %s", err);
			}
			continue;
		} else if (t->subnet == NULL) {
			FAIL(OUT, "address_mask_to_subnet() unexpectedly succeeded");
		}

		subnet_buf sb;
		const char *s = str_subnet(&subnet, &sb);
		if (!streq(s, t->subnet)) {
			FAIL(OUT, "str_subnet() returned %s, expecting %s", s, t->subnet);
		}
	}
#undef OUT
}

void ip_subnet_check(void)
{
	check_str_subnet();
	check_str_subnet_port();
	check_subnet_prefix();
	check_subnet_mask();
	check_subnet_contains();
	check_subnet_from_address();
	check_address_mask_to_subnet();
	check_cidr_to_subnet();
}
