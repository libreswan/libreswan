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

static void check__ttosubnet_num__str_subnet(struct logger *logger UNUSED)
{
	static const struct test {
		int line;
		int family;
		char *in;
		char *str;	/* NULL means error expected */
		bool zeroed;	/* true means host part was zeroed */
	} tests[] = {
		{ LN, 4, "", NULL, false, },
		{ LN, 4, "1.2.3.0/255.255.255.0", "1.2.3.0/24", false, },
		{ LN, 4, "1.2.3.0/24", "1.2.3.0/24", false, },
		{ LN, 4, "1.2.3.0/255.255.255.240", "1.2.3.0/28", false, },
		{ LN, 4, "1.2.3.1/32", "1.2.3.1/32", false, },
		{ LN, 4, "1.2.3.1/31", "1.2.3.0/31", true, },
		{ LN, 4, "0.0.0.0/0", "0.0.0.0/0", false, },
/*	{4, "1.2.3.0/255.255.127.0",	"1.2.3.0/255.255.127.0"}, */
		{ LN, 4, "1.2.3.1/255.255.127.0", NULL, false, },
		{ LN, 4, "1.2.3.1/255.255.128.0", "1.2.0.0/17", true, },
		{ LN, 4, "128.0007.0000.0032/32", "128.7.0.26/32", false, },
		{ LN, 4, "128.0x0f.0.32/32", "128.15.0.32/32", false, },
		{ LN, 4, "0x80090020/32", "128.9.0.32/32", false, },
		{ LN, 4, "0x800x0020/32", NULL, false, },
		{ LN, 4, "128.9.0.0/0xffFF0000", "128.9.0.0/16", false, },
		{ LN, 4, "128.9.0.32/0xff0000FF", NULL, false, },
		{ LN, 4, "128.9.0.32/0x0000ffFF", NULL, false, },
		{ LN, 4, "128.9.0.32/0x00ffFF0000", NULL, false, },
		{ LN, 4, "128.9.0.32/0xffFF", NULL, false, },
		{ LN, 4, "128.9.0.32.27/32", NULL, false, },
		{ LN, 4, "128.9.0k32/32", NULL, false, },
		{ LN, 4, "328.9.0.32/32", NULL, false, },
		{ LN, 4, "128.9..32/32", NULL, false, },
		{ LN, 4, "10/8", "10.0.0.0/8", false, },
		{ LN, 4, "10.0/8", "10.0.0.0/8", false, },
		{ LN, 4, "10.0.0/8", "10.0.0.0/8", false, },
		{ LN, 4, "10.0.1.0/24", "10.0.1.0/24", false, },
		{ LN, 4, "_", NULL, false, },
		{ LN, 4, "_/_", NULL, false, },
		{ LN, 4, "1.2.3.1", NULL, false, },
		{ LN, 4, "1.2.3.1/_", NULL, false, },
		{ LN, 4, "1.2.3.1/24._", NULL, false, },
		{ LN, 4, "1.2.3.1/99", NULL, false, },
		{ LN, 4, "localhost/32", NULL, false, },
		{ LN, 4, "%default", "0.0.0.0/0", false, },
		{ LN, 6, "::/0", "::/0", false, },
		{ LN, 6, "3049:1::8007:2040/128", "3049:1::8007:2040/128", false, },
		{ LN, 6, "3049:1::192.168.0.1/128", NULL, false, },	/*"3049:1::c0a8:1/128",*/
		{ LN, 6, "3049:1::8007::2040/128", NULL, false, },
		{ LN, 6, "3049:1::8007:2040/ffff:0", NULL, false, },
		{ LN, 6, "3049:1::/64", "3049:1::/64", false, },
		{ LN, 6, "3049:1::8007:2040/ffff:", NULL, false, },
		{ LN, 6, "3049:1::8007:2040/0000:ffff::0", NULL, false, },
		{ LN, 6, "3049:1::8007:2040/ff1f:0", NULL, false, },
		{ LN, 6, "3049:1::8007:x:2040/128", NULL, false, },
		{ LN, 6, "3049:1t::8007:2040/128", NULL, false, },
		{ LN, 6, "3049:1::80071:2040/128", NULL, false, },
		{ LN, 6, "::/21", "::/21", false, },
		{ LN, 6, "::1/128", "::1/128", false, },
		{ LN, 6, "::1/127", "::/127", true, },
		{ LN, 6, "1::/21", "1::/21", false, },
		{ LN, 6, "1::2/128", "1::2/128", false, },
		{ LN, 6, "1:0:0:0:0:0:0:2/128", "1::2/128", false, },
		{ LN, 6, "1:0:0:0:3:0:0:2/128", "1::3:0:0:2/128", false, },
		{ LN, 6, "1:0:0:3:0:0:0:2/128", "1:0:0:3::2/128", false, },
		{ LN, 6, "1:0:3:0:0:0:0:2/128", "1:0:3::2/128", false, },
		{ LN, 6, "abcd:ef01:2345:6789:0:00a:000:20/128", "abcd:ef01:2345:6789:0:a:0:20/128", false, },
		{ LN, 6, "3049:1::8007:2040/ffff:ffff:", NULL, false, },
		{ LN, 6, "3049:1::8007:2040/ffff:88:", NULL, false, },
		{ LN, 6, "3049:12::9000:3200/ffff:fff0", NULL, false, },
		{ LN, 6, "3049:10::/28", "3049:10::/28", false, },
		{ LN, 6, "3049:12::9000:3200/ff00:", NULL, false, },
		{ LN, 6, "3049:12::9000:3200/ffff:", NULL, false, },
		{ LN, 6, "3049:12::9000:3200/128_", NULL, false, },
		{ LN, 6, "3049:12::9000:3200/", NULL, false, },
		{ LN, 6, "%default", "::/0", false, },

		/* any:0 */
		{ LN, 4, "0.0.0.0/0:0", NULL, false, },
		{ LN, 6, "::/0:0", NULL, false, },
		/* longest:port */
		{ LN, 4, "101.102.103.104/32:65535", NULL, false, },
		{ LN, 6, "1001:1002:1003:1004:1005:1006:1007:1008/128:65535", NULL, false, },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> '%s'", pri_family(t->family), t->in,
		      t->str == NULL ? "<error>" : t->str);

		ip_subnet tmp, *subnet = &tmp;
		ip_address nonzero_host;
		oops = ttosubnet_num(shunk1(t->in), IP_TYPE(t->family),
				     subnet, &nonzero_host);
		if (oops != NULL && t->str == NULL) {
			/* Error was expected, do nothing */
			continue;
		} else if (oops != NULL && t->str != NULL) {
			/* Error occurred, but we didn't expect one */
			FAIL("ttosubnet(%s) failed: %s", t->in, oops);
		} else if (oops == NULL && t->str == NULL) {
			/* If no errors, but we expected one */
			FAIL("ttosubnet(%s) succeeded unexpectedly", t->in);
		}

		if (nonzero_host.is_set != t->zeroed) {
			FAIL("ttosubnet(%s) failed: zeroed %s should be %s",
			     t->in, bool_str(nonzero_host.is_set), bool_str(t->zeroed));
		}

		CHECK_TYPE(subnet);
		CHECK_STR2(subnet);
	}
}

static void check_subnet_mask(void)
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

		ip_subnet tmp, *subnet = &tmp;
		ip_address nonzero_host;
		err_t oops = ttosubnet_num(shunk1(t->in), IP_TYPE(t->family),
					   subnet, &nonzero_host);
		if (oops != NULL) {
			FAIL("ttosubnet(%s) failed: %s", t->in, oops);
		}
		if (nonzero_host.is_set) {
			FAIL("ttosubnet(%s) failed: host identifier is non-zero", t->in);
		}

		CHECK_TYPE(subnet);

		address_buf buf;
		const char *out;

		ip_address mask = subnet_prefix_mask(*subnet);
		out = str_address(&mask, &buf);
		if (!streq(t->mask, out)) {
			FAIL("subnet_mask() returned '%s', expected '%s'",
				out, t->mask);
		}
		CHECK_FAMILY(t->family, address, &mask);
	}
}

static void check_subnet_prefix(void)
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

		ip_subnet tmp, *subnet = &tmp;
		ip_address nonzero_host;
		err_t oops = ttosubnet_num(shunk1(t->in), IP_TYPE(t->family),
					   subnet, &nonzero_host);
		if (oops != NULL) {
			FAIL("ttosubnet(%s) failed: %s", t->in, oops);
		}
		if (nonzero_host.is_set) {
			FAIL("ttosubnet(%s) failed: host identifier is non-zero", t->in);
		}

		CHECK_TYPE(subnet);

		ip_address prefix = subnet_prefix(*subnet);
		CHECK_FAMILY(t->family, address, &prefix);

		address_buf buf;
		const char *out = str_address(&prefix, &buf);
		if (!streq(out, t->out)) {
			FAIL("subnet_prefix() returned '%s', expected '%s'",
				out, t->out);
		}
	}
}

static void check_subnet_is(void)
{
	static const struct test {
		int line;
		int family;
		const char *in;
		bool is_unset;
		uintmax_t size;
		bool is_zero;
		bool is_all;
	} tests[] = {
		/* unset */
		{ LN, 0, NULL,           .is_unset = true, },
		/* no_addresses */
		{ LN, 4, "0.0.0.0/32",   .size = 1, .is_zero = true, },
		{ LN, 6, "::/128",       .size = 1, .is_zero = true, },
		/* one_address */
		{ LN, 4, "127.0.0.1/32", .size = 1, },
		{ LN, 6, "::1/128",      .size = 1, },
		/* some_address+one_address? */
		{ LN, 4, "127.0.0.0/31", .size = 2, },
		{ LN, 6, "1::/127",      .size = 2, },
		/* all addresses */
		{ LN, 4, "0.0.0.0/0",    .size = (uintmax_t)1 << 32, .is_all = true, },
		{ LN, 6, "::/0",         .size = UINTMAX_MAX,        .is_all = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s %s unset=%s size=%ju zero=%s all=%s",
		      pri_family(t->family),
		      t->in != NULL ? t->in : "<unset>",
		      bool_str(t->is_unset),
		      t->size,
		      bool_str(t->is_zero),
		      bool_str(t->is_all));

		ip_subnet tmp = unset_subnet, *subnet = &tmp;
		if (t->family != 0) {
			ip_address nonzero_host;
			err_t oops = ttosubnet_num(shunk1(t->in), IP_TYPE(t->family),
						   &tmp, &nonzero_host);
			if (oops != NULL) {
				FAIL("ttosubnet(%s) failed: %s", t->in, oops);
			}
			if (nonzero_host.is_set) {
				FAIL("ttosubnet(%s) failed: non-zero host identifier", t->in);
			}
			CHECK_TYPE(subnet);
		}

		CHECK_COND(subnet, is_unset);
		CHECK_COND2(subnet, is_all);
		CHECK_COND2(subnet, is_zero);
		CHECK_UNOP(subnet, size, "%ju", );
	}
}

static void check_subnet_from_address(void)
{
	static const struct test {
		int line;
		int family;
		const char *in;
		const char *prefix_mask;
	} tests[] = {
		{ LN, 4, "0.0.0.0",   "255.255.255.255", },
		{ LN, 6, "::",        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
		{ LN, 4, "127.0.0.1", "255.255.255.255", },
		{ LN, 6, "::1",       "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s'", pri_family(t->family), t->in);

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address a;
		err_t oops = ttoaddress_num(shunk1(t->in), type, &a);
		if (oops != NULL) {
			FAIL("ttoaddress_num() failed: %s", oops);
		}

		ip_subnet tmp = subnet_from_address(a), *subnet = &tmp;

		CHECK_TYPE(subnet);

		ip_address prefix = subnet_prefix(*subnet);
		if (!sameaddr(&prefix, &a)) {
			address_buf pb, ab;
			FAIL("subnet_prefix(&s) returned %s, expecting %s",
				str_address(&prefix, &pb), str_address(&a, &ab));
		}

		if (!subnet_eq_address(*subnet, a)) {
			subnet_buf sb;
			address_buf ab;
			FAIL("subnet_is_address(%s,%s) unexpectedly failed",
			     str_subnet(subnet, &sb), str_address(&a, &ab));
		}

		ip_address m = subnet_prefix_mask(*subnet);
		address_buf mb;
		str_address(&m, &mb);
		if (!streq(mb.buf, t->prefix_mask)) {
			subnet_buf sb;
			FAIL("subnet_mask(%s) returned %s, expecting %s",
			     str_subnet(subnet, &sb), mb.buf, t->prefix_mask);
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
		err = ttoaddress_num(shunk1(t->address), NULL, &address);
		if (err != NULL) {
			FAIL("ttoaddress_num(%s) failed: %s",
			     t->address, err);
		}

		ip_address mask;
		err = ttoaddress_num(shunk1(t->mask), NULL, &mask);
		if (err != NULL) {
			FAIL("ttoaddress_num(%s) failed: %s",
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
	check__ttosubnet_num__str_subnet(logger);
	check_subnet_prefix();
	check_subnet_mask();
	check_subnet_is();
	check_subnet_from_address();
	check_address_mask_to_subnet();
}
