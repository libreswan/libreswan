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

static void check_str_subnet(struct logger *logger)
{
	static const struct test {
		int line;
		int family;
		char *in;
		char *out;	/* NULL means error expected */
	} tests[] = {
		{ LN, 4, "1.2.3.0/255.255.255.0", "1.2.3.0/24" },
		{ LN, 4, "1.2.3.0/24", "1.2.3.0/24" },
		{ LN, 4, "1.2.3.0/255.255.255.240", "1.2.3.0/28" },
		{ LN, 4, "1.2.3.1/32", "1.2.3.1/32" },
		{ LN, 4, "0.0.0.0/0", "0.0.0.0/0" },
/*	{4, "1.2.3.0/255.255.127.0",	"1.2.3.0/255.255.127.0"}, */
		{ LN, 4, "1.2.3.1/255.255.127.0", NULL },
		{ LN, 4, "128.009.000.032/32", "128.9.0.32/32" },
		{ LN, 4, "128.0x9.0.32/32", NULL },
		{ LN, 4, "0x80090020/32", "128.9.0.32/32" },
		{ LN, 4, "0x800x0020/32", NULL },
		{ LN, 4, "128.9.0.0/0xffFF0000", "128.9.0.0/16" },
		{ LN, 4, "128.9.0.32/0xff0000FF", NULL },
		{ LN, 4, "128.9.0.32/0x0000ffFF", NULL },
		{ LN, 4, "128.9.0.32/0x00ffFF0000", NULL },
		{ LN, 4, "128.9.0.32/0xffFF", NULL },
		{ LN, 4, "128.9.0.32.27/32", NULL },
		{ LN, 4, "128.9.0k32/32", NULL },
		{ LN, 4, "328.9.0.32/32", NULL },
		{ LN, 4, "128.9..32/32", NULL },
		{ LN, 4, "10/8", "10.0.0.0/8" },
		{ LN, 4, "10.0/8", "10.0.0.0/8" },
		{ LN, 4, "10.0.0/8", "10.0.0.0/8" },
		{ LN, 4, "10.0.1/24", "10.0.1.0/24" },
		{ LN, 4, "_", NULL },
		{ LN, 4, "_/_", NULL },
		{ LN, 4, "1.2.3.1", NULL },
		{ LN, 4, "1.2.3.1/_", NULL },
		{ LN, 4, "1.2.3.1/24._", NULL },
		{ LN, 4, "1.2.3.1/99", NULL },
		{ LN, 4, "localhost/32", NULL },
		{ LN, 4, "%default", "0.0.0.0/0" },
		{ LN, 6, "::/0", "::/0" },
		{ LN, 6, "3049:1::8007:2040/128", "3049:1::8007:2040/128" },
		{ LN, 6, "3049:1::192.168.0.1/128", NULL },	/*"3049:1::c0a8:1/128",*/
		{ LN, 6, "3049:1::8007::2040/128", NULL },
		{ LN, 6, "3049:1::8007:2040/ffff:0", NULL },
		{ LN, 6, "3049:1::/64", "3049:1::/64" },
		{ LN, 6, "3049:1::8007:2040/ffff:", NULL },
		{ LN, 6, "3049:1::8007:2040/0000:ffff::0", NULL },
		{ LN, 6, "3049:1::8007:2040/ff1f:0", NULL },
		{ LN, 6, "3049:1::8007:x:2040/128", NULL },
		{ LN, 6, "3049:1t::8007:2040/128", NULL },
		{ LN, 6, "3049:1::80071:2040/128", NULL },
		{ LN, 6, "::/21", "::/21" },
		{ LN, 6, "::1/128", "::1/128" },
		{ LN, 6, "1::/21", "1::/21" },
		{ LN, 6, "1::2/128", "1::2/128" },
		{ LN, 6, "1:0:0:0:0:0:0:2/128", "1::2/128" },
		{ LN, 6, "1:0:0:0:3:0:0:2/128", "1::3:0:0:2/128" },
		{ LN, 6, "1:0:0:3:0:0:0:2/128", "1:0:0:3::2/128" },
		{ LN, 6, "1:0:3:0:0:0:0:2/128", "1:0:3::2/128" },
		{ LN, 6, "abcd:ef01:2345:6789:0:00a:000:20/128",
		  "abcd:ef01:2345:6789:0:a:0:20/128" },
		{ LN, 6, "3049:1::8007:2040/ffff:ffff:", NULL },
		{ LN, 6, "3049:1::8007:2040/ffff:88:", NULL },
		{ LN, 6, "3049:12::9000:3200/ffff:fff0", NULL },
		{ LN, 6, "3049:10::/28", "3049:10::/28" },
		{ LN, 6, "3049:12::9000:3200/ff00:", NULL },
		{ LN, 6, "3049:12::9000:3200/ffff:", NULL },
		{ LN, 6, "3049:12::9000:3200/128_", NULL },
		{ LN, 6, "3049:12::9000:3200/", NULL },
		{ LN, 6, "%default", "::/0" },

		/* any:0 */
		{ LN, 4, "0.0.0.0/0:0", NULL, },
		{ LN, 6, "::/0:0", NULL, },
		/* longest:port */
		{ LN, 4, "101.102.103.104/32:65535", NULL, },
		{ LN, 6, "1001:1002:1003:1004:1005:1006:1007:1008/128:65535", NULL, },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> '%s'", pri_family(t->family), t->in,
		      t->out ? t->out : "<error>");

		ip_subnet s;
		oops = ttosubnet(shunk1(t->in), IP_TYPE(t->family), '6', &s, logger);
		if (oops != NULL && t->out == NULL) {
			/* Error was expected, do nothing */
			continue;
		} else if (oops != NULL && t->out != NULL) {
			/* Error occurred, but we didn't expect one  */
			FAIL("ttosubnet failed: %s", oops);
		} else if (oops == NULL && t->out == NULL) {
			/* If no errors, but we expected one */
			FAIL("ttosubnet succeeded unexpectedly");
		}

		CHECK_TYPE(subnet_type(&s));

		subnet_buf buf;
		const char *out = str_subnet(&s, &buf);
		if (!streq(t->out, out)) {
			FAIL("str_subnet() returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_subnet_mask(struct logger *logger)
{
	static const struct test {
		int line;
		int family;
		const char *in;
		const char *mask;
	} tests[] = {
		{ LN, 4, "0.0.0.0/1", "128.0.0.0", },
		{ LN, 4, "1.2.0.0/23", "255.255.254.0", },
		{ LN, 4, "1.2.3.0/24", "255.255.255.0", },
		{ LN, 4, "1.2.3.0/25", "255.255.255.128", },
		{ LN, 4, "1.2.3.4/31", "255.255.255.254", },
		{ LN, 4, "1.2.3.4/32", "255.255.255.255", },
		{ LN, 6, "0::/1", "8000::", },
		{ LN, 6, "1:2:3:4::/63", "ffff:ffff:ffff:fffe::", },
		{ LN, 6, "1:2:3:4::/64", "ffff:ffff:ffff:ffff::", },
		{ LN, 6, "1:2:3:4::/65", "ffff:ffff:ffff:ffff:8000::", },
		{ LN, 6, "1:2:3:4:5:6:7:8/127", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", },
		{ LN, 6, "1:2:3:4:5:6:7:8/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> %s", pri_family(t->family), t->in, t->mask);

		ip_subnet s;
		err_t oops = ttosubnet(shunk1(t->in), IP_TYPE(t->family), '6', &s, logger);
		if (oops != NULL) {
			FAIL("ttosubnet() failed: %s", oops);
		}

		CHECK_TYPE(subnet_type(&s));

		address_buf buf;
		const char *out;

		ip_address mask = subnet_prefix_mask(&s);
		out = str_address(&mask, &buf);
		if (!streq(t->mask, out)) {
			FAIL("subnet_mask() returned '%s', expected '%s'",
				out, t->mask);
		}
		CHECK_TYPE(address_type(&mask));
	}
}

static void check_subnet_prefix(struct logger *logger)
{
	static const struct test {
		int line;
		int family;
		const char *in;
		const char *out;
	} tests[] = {
		{ LN, 4, "128.0.0.0/1", "128.0.0.0", },
		{ LN, 6, "8000::/1", "8000::", },

		{ LN, 4, "1.2.254.0/23", "1.2.254.0", },
		{ LN, 4, "1.2.255.0/24", "1.2.255.0", },
		{ LN, 4, "1.2.255.128/25", "1.2.255.128", },
		{ LN, 6, "1:2:3:fffe::/63", "1:2:3:fffe::", },
		{ LN, 6, "1:2:3:ffff::/64", "1:2:3:ffff::", },
		{ LN, 6, "1:2:3:ffff:8000::/65", "1:2:3:ffff:8000::", },

		{ LN, 4, "1.2.3.254/31", "1.2.3.254", },
		{ LN, 4, "1.2.3.255/32", "1.2.3.255", },
		{ LN, 6, "1:2:3:4:5:6:7:fffe/127", "1:2:3:4:5:6:7:fffe", },
		{ LN, 6, "1:2:3:4:5:6:7:ffff/128", "1:2:3:4:5:6:7:ffff", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> %s", pri_family(t->family), t->in, t->out);

		ip_subnet s;
		err_t oops = ttosubnet(shunk1(t->in), IP_TYPE(t->family), '6', &s, logger);
		if (oops != NULL) {
			FAIL("ttosubnet() failed: %s", oops);
		}

		CHECK_TYPE(subnet_type(&s));

		ip_address prefix = subnet_prefix(&s);
		CHECK_TYPE(address_type(&prefix));

		address_buf buf;
		const char *out = str_address(&prefix, &buf);
		if (!streq(out, t->out)) {
			FAIL("subnet_prefix() returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_subnet_contains(struct logger *logger)
{
	static const struct test {
		int line;
		int family;
		const char *in;
		bool is_unset;
		bool contains_all_addresses;
		bool is_specified;
		bool contains_no_addresses;
	} tests[] = {
		/* unset */
		{ LN, 0, NULL,           true, false, false, false, },
		/* all_addresses */
		{ LN, 4, "0.0.0.0/0",    false, true, false, false, },
		{ LN, 6, "::/0",         false, true, false, false, },
		/* some_address+one_address? */
		{ LN, 4, "127.0.0./31",  false, false, true, false, },
		{ LN, 6, "1::/127",      false, false, true, false,  },
		/* one_address */
		{ LN, 4, "127.0.0.1/32", false, false, true, false, },
		{ LN, 6, "::1/128",      false, false, true, false,  },
		/* no_addresses */
		{ LN, 4, "0.0.0.0/32",   false, false, false, true, },
		{ LN, 6, "::/128",       false, false, false, true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s %s unset=%s all=%s some=%s none=%s",
		      pri_family(t->family),
		      t->in != NULL ? t->in : "<unset>",
		      bool_str(t->is_unset),
		      bool_str(t->contains_all_addresses),
		      bool_str(t->is_specified),
		      bool_str(t->contains_no_addresses));

		ip_subnet tmp = unset_subnet, *subnet = &tmp;
		if (t->family != 0) {
			err_t oops = ttosubnet(shunk1(t->in), IP_TYPE(t->family), '6', &tmp, logger);
			if (oops != NULL) {
				FAIL("ttosubnet() failed: %s", oops);
			}
			CHECK_TYPE(subnet_type(subnet));
		}

		CHECK_COND(subnet, is_unset);
		CHECK_COND(subnet, contains_no_addresses);
		CHECK_COND(subnet, is_specified);
		CHECK_COND(subnet, contains_all_addresses);
	}
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
		int line;
		int family;
		const char *in;
		const char *mask;
	} tests[] = {
		{ LN, 4, "0.0.0.0", NULL, },
		{ LN, 6, "::", NULL, },
		{ LN, 4, "127.0.0.1", NULL, },
		{ LN, 6, "::1",  NULL, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s'", pri_family(t->family), t->in);

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address a;
		err_t oops = numeric_to_address(shunk1(t->in), type, &a);
		if (oops != NULL) {
			FAIL("numeric_to_address() failed: %s", oops);
		}
		ip_subnet s = subnet_from_address(a);

		CHECK_TYPE(subnet_type(&s));

		ip_address prefix = subnet_prefix(&s);
		if (!sameaddr(&prefix, &a)) {
			address_buf pb, ab;
			FAIL("subnet_prefix(&s) returned %s, expecting %s",
				str_address(&prefix, &pb), str_address(&a, &ab));
		}

		ip_address mask = subnet_prefix_mask(&s);
		if (!address_is_0xff(&mask)) {
			address_buf mb;
			FAIL("subnet_mask(&s) returned %s, expecting 255.255.255.255",
				str_address(&mask, &mb));
		}
	}
}

static void check_address_mask_to_subnet(void)
{
	static const struct test {
		int line;
		const char *address;
		const char *mask;
		const char *subnet;
	} tests[] = {
		/* XXX: this code isn/t used by IPv6? */

		/* any address */
		{ LN, "0.0.0.0", "0.0.0.0", "0.0.0.0/0" },
		{ LN, "::", "::", "::/0" },

		/* one address */
		{ LN, "1.2.3.4", "255.255.255.255", "1.2.3.4/32" },
		{ LN, "1:2:3:4:5:6:7:8", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1:2:3:4:5:6:7:8/128" },

		/* subnet boundary on byte */
		{ LN, "1.2.0.0", "255.255.0.0", "1.2.0.0/16" },
		{ LN, "1:2:3:4::", "ffff:ffff:ffff:ffff::", "1:2:3:4::/64" },

		/* subnet boundary within byte */
		{ LN, "1.2.192.0", "255.255.192.0", "1.2.192.0/18" },
		{ LN, "1:2:3:4:c000::", "ffff:ffff:ffff:ffff:c000::", "1:2:3:4:c000::/66" },

		/* address/mask type mashup */
		{ LN, "1.2.192.0", "::", NULL, },
		{ LN, "1:2:3:4:c000::", "0.0.0.0", NULL, },

		/* gaps */
		{ LN, "1.2.3.4", "255.0.255.0", NULL, },
		{ LN, "1.2.3.4", "255.254.255.255", NULL, },

		/* fixup screwup */
		{ LN, "1.2.3.255", "255.255.255.0", "1.2.3.0/24", },
		{ LN, "1.2.3.255", "255.255.255.128", "1.2.3.128/25", },

	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		err_t err;
		const struct test *t = &tests[ti];
		PRINT("%s/%s -> %s",
		      t->address != NULL ? t->address : "N/A",
		      t->mask != NULL ? t->mask : "N/A",
		      t->subnet != NULL ? t->subnet : "<error>");

		ip_address address;
		err = numeric_to_address(shunk1(t->address), NULL, &address);
		if (err != NULL) {
			FAIL("numeric_to_address(%s) failed: %s",
			     t->address, err);
		}

		ip_address mask;
		err = numeric_to_address(shunk1(t->mask), NULL, &mask);
		if (err != NULL) {
			FAIL("numeric_to_address(%s) failed: %s",
			     t->mask, err);
		}

		ip_subnet subnet;
		err = address_mask_to_subnet(address, mask, &subnet);
		if (err != NULL) {
			if (t->subnet != NULL) {
				FAIL("address_mask_to_subnet() unexpectedly failed: %s", err);
			}
			continue;
		} else if (t->subnet == NULL) {
			FAIL("address_mask_to_subnet() unexpectedly succeeded");
		}

		subnet_buf sb;
		const char *s = str_subnet(&subnet, &sb);
		if (!streq(s, t->subnet)) {
			FAIL("str_subnet() returned %s, expecting %s", s, t->subnet);
		}
	}
#undef OUT
}

void ip_subnet_check(struct logger *logger)
{
	check_str_subnet(logger);
	check_subnet_prefix(logger);
	check_subnet_mask(logger);
	check_subnet_contains(logger);
	check_subnet_from_address();
	check_address_mask_to_subnet();
}
