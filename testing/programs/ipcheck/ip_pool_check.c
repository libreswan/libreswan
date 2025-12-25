/* ip pool tests, for libreswan
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

#include "lswlog.h"
#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for streq() */
#include "ip_pool.h"
#include "ip_subnet.h"
#include "ipcheck.h"

static void check_ippool_bits(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *lo;
		const char *hi;
		int prefix_len;
		int host_len;
	} tests[] = {
		{ LN, &ipv4_info, "1.2.254.255", "1.2.255.0", -1, -1 },
		{ LN, &ipv4_info, "1.2.3.0", "1.2.3.7", 29, 3 },
		{ LN, &ipv4_info, "1.2.3.0", "1.2.3.255", 24, 8 },
		{ LN, &ipv4_info, "1.2.3.240", "1.2.3.255", 28, 4 },
		{ LN, &ipv4_info, "0.0.0.0", "255.255.255.255", 0, 32 },
		{ LN, &ipv4_info, "1.2.3.4", "1.2.3.4", 32, 0 },
		{ LN, &ipv4_info, "1.2.3.0", "1.2.3.254", -1, -1 },
		/* across boundary */
		{ LN, &ipv4_info, "1.2.3.0", "1.2.3.126", -1, -1 },
		{ LN, &ipv4_info, "1.2.3.0", "1.2.3.127", 25, 7 },
		{ LN, &ipv4_info, "1.2.3.0", "1.2.3.128", -1, -1 },
		/* 16-bit */
		{ LN, &ipv4_info, "1.2.0.0", "1.2.255.255", 16, 16 },
		{ LN, &ipv4_info, "1.2.0.0", "1.2.0.255", 24, 8 },
		{ LN, &ipv4_info, "1.2.255.0", "1.2.255.255", 24, 8 },
		{ LN, &ipv4_info, "1.2.255.1", "1.2.255.255", -1, -1 },
		{ LN, &ipv4_info, "1.2.0.1", "1.2.255.255", -1, -1 },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:ffff", 112, 16 },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:fff", 116, 12 },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:f0", "1:2:3:4:5:6:7:ff", 124, 4 },
		{ LN, &ipv6_info, "2000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 3, 125},
		{ LN, &ipv6_info, "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1, 127},
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s'-'%s'", pri_afi(t->afi), t->lo, t->hi)

		const struct ip_info *afi = t->afi;

		ip_address lo;
		oops = ttoaddress_num(shunk1(t->lo), afi, &lo);
		if (oops != NULL) {
			FAIL("ttoaddress_num() failed converting '%s'", t->lo);
		}

		ip_address hi;
		oops = ttoaddress_num(shunk1(t->hi), afi, &hi);
		if (oops != NULL) {
			FAIL("ttoaddress_num() failed converting '%s'", t->hi);
		}

		ip_pool pool = pool_from_raw(HERE, afi,
						lo.bytes, hi.bytes,
						afi->mask_cnt);
		int host_len = pool_host_len(pool);
		if (host_len != t->host_len) {
			FAIL("pool_host_len(pool) returned '%d', expected '%d'",
			     host_len, t->host_len);
		}

		int prefix_len = pool_prefix_len(pool);
		if (prefix_len != t->prefix_len) {
			FAIL("pool_prefix_len(pool) returned '%d', expected '%d'",
			     prefix_len, t->prefix_len);
		}
	}
}

static void check_ttopool__to__str_pool(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		const char *str;
		uintmax_t pool_size;
	} tests[] = {
		/* single address */
		{ LN, &ipv4_info, "4.3.2.1", "4.3.2.1/32", 1, },
		{ LN, &ipv6_info, "::1", "::1/128", 1, },
		{ LN, &ipv4_info, "4.3.2.1-4.3.2.1", "4.3.2.1/32", 1, },
		{ LN, &ipv6_info, "::1-::1", "::1/128", 1, },
		{ LN, &ipv4_info, "4.3.2.1/32", "4.3.2.1/32", 1, },
		{ LN, &ipv6_info, "::2/128", "::2/128", 1, },
		{ LN, &ipv4_info, "4.3.2.1/32/32", "4.3.2.1/32", 1, },
		{ LN, &ipv6_info, "::2/128/128", "::2/128", 1, },

		/* normal pool */
		{ LN, &ipv6_info, "::1-::2", "::1-::2", 2, },
		{ LN, &ipv4_info, "1.2.3.0-1.2.3.9", "1.2.3.0-1.2.3.9", 10, },

		/* largest */
		{ LN, &ipv4_info, "0.0.0.1-255.255.255.255", "0.0.0.1-255.255.255.255", UINT32_MAX, },

		/* ok - largest - overflow - truncate */
		{ LN, &ipv6_info, "1:2:3:4::-1:2:3:4:ffff:ffff:ffff:fffd", "1:2:3:4::-1:2:3:4:ffff:ffff:ffff:fffd", UINTMAX_MAX-1, },
		{ LN, &ipv6_info, "1:2:3:4::-1:2:3:4:ffff:ffff:ffff:fffe", "1:2:3:4::-1:2:3:4:ffff:ffff:ffff:fffe", UINTMAX_MAX, },
		{ LN, &ipv6_info, "1:2:3:4::-1:2:3:4:ffff:ffff:ffff:ffff", "1:2:3:4::/64", UINTMAX_MAX, },
		{ LN, &ipv6_info, "1:2:3:4::-1:2:3:5:0000:0000:0000:0000", "1:2:3:4::-1:2:3:5::", UINTMAX_MAX, },

		/* ok - largest - overflow - truncate */
		{ LN, &ipv6_info, "1:2:3:4::1-1:2:3:4:ffff:ffff:ffff:fffe", "1:2:3:4::1-1:2:3:4:ffff:ffff:ffff:fffe", UINTMAX_MAX-1, },
		{ LN, &ipv6_info, "1:2:3:4::1-1:2:3:4:ffff:ffff:ffff:ffff", "1:2:3:4::1-1:2:3:4:ffff:ffff:ffff:ffff", UINTMAX_MAX, },
		{ LN, &ipv6_info, "1:2:3:4::1-1:2:3:5:0000:0000:0000:0000", "1:2:3:4::1-1:2:3:5::", UINTMAX_MAX, },
		{ LN, &ipv6_info, "1:2:3:4::1-1:2:3:5:0000:0000:0000:0001", "1:2:3:4::1-1:2:3:5::1", UINTMAX_MAX, },

		/* ok - largest - overflow - truncate */
		{ LN, &ipv6_info, "1:2:3:4::2-1:2:3:4:ffff:ffff:ffff:ffff", "1:2:3:4::2-1:2:3:4:ffff:ffff:ffff:ffff", UINTMAX_MAX-1, },
		{ LN, &ipv6_info, "1:2:3:4::2-1:2:3:5:0000:0000:0000:0000", "1:2:3:4::2-1:2:3:5::", UINTMAX_MAX, },
		{ LN, &ipv6_info, "1:2:3:4::2-1:2:3:5:0000:0000:0000:0001", "1:2:3:4::2-1:2:3:5::1", UINTMAX_MAX, },
		{ LN, &ipv6_info, "1:2:3:4::2-1:2:3:5:0000:0000:0000:0002", "1:2:3:4::2-1:2:3:5::2", UINTMAX_MAX, },

		/* ok - largest - overflow - truncate */
		{ LN, &ipv6_info, "1:2:3:4:0:0:0:3-1:2:3:5::0", "1:2:3:4::3-1:2:3:5::", UINTMAX_MAX-1, },
		{ LN, &ipv6_info, "1:2:3:4:0:0:0:3-1:2:3:5::1", "1:2:3:4::3-1:2:3:5::1", UINTMAX_MAX, },
		{ LN, &ipv6_info, "1:2:3:4:0:0:0:3-1:2:3:5::2", "1:2:3:4::3-1:2:3:5::2", UINTMAX_MAX, },
		{ LN, &ipv6_info, "1:2:3:4:0:0:0:3-1:2:3:5::3", "1:2:3:4::3-1:2:3:5::3", UINTMAX_MAX, },

		/* total overflow */
		{ LN, &ipv6_info, "8000::0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "8000::/1", UINTMAX_MAX, },
		{ LN, &ipv6_info, "8000::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "8000::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UINTMAX_MAX, },
		{ LN, &ipv6_info, "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::/0", UINTMAX_MAX, },
		{ LN, &ipv6_info, "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UINTMAX_MAX, },

		/* allow CIDR prefix */
		{ LN, &ipv4_info, "1.2.3.0/32", "1.2.3.0/32", 1, },
		{ LN, &ipv6_info, "1:0:3:0:0:0:0:2/128", "1:0:3::2/128", 1, },
		{ LN, &ipv6_info, "2001:db8:0:9:1:2::/112", "2001:db8:0:9:1:2::/112", 65536, },
		{ LN, &ipv6_info, "abcd:ef01:2345:6789:0:00a:000:20/128", "abcd:ef01:2345:6789:0:a:0:20/128", 1, },
		{ LN, &ipv6_info, "2001:db8:0:8::/112", "2001:db8:0:8::/112", 65536, },
		{ LN, &ipv6_info, "2001:db8:0:7::/97", "2001:db8:0:7::/97", 2147483648, },
		{ LN, &ipv6_info, "2001:db8:0:4::/96", "2001:db8:0:4::/96", (uintmax_t)UINT32_MAX+1, },
		{ LN, &ipv6_info, "2001:db8:0:6::/64", "2001:db8:0:6::/64", UINT64_MAX, },
		{ LN, &ipv6_info, "2001:db8::/32", "2001:db8::/32", UINTMAX_MAX, },
		{ LN, &ipv6_info, "2000::/3", "2000::/3", UINTMAX_MAX, },
		{ LN, &ipv6_info, "4000::/2", "4000::/2", UINTMAX_MAX, },
		{ LN, &ipv6_info, "8000::/1", "8000::/1", UINTMAX_MAX, },

		/* allow CIDR prefix / subprefix */
		{ LN, &ipv4_info, "1.2.3.0/31/32", "1.2.3.0/31", 2, },
		{ LN, &ipv6_info, "1:0:3:0:0:0:0:2/127/128", "1:0:3::2/127", 2, },
		{ LN, &ipv4_info, "1.2.3.0/24/28", "1.2.3.0/24/28", 256, },
		{ LN, &ipv6_info, "1:0:3::/124/126", "1:0:3::/124/126", 16, },

		/* reject port */
		{ LN, &ipv6_info, "2001:db8:0:7::/97:0", NULL, -1, },
		{ LN, &ipv6_info, "2001:db8:0:7::/97:30", NULL, -1, },

		/* wrong order */
		{ LN, &ipv4_info, "1.2.3.4-1.2.3.3", NULL, -1, },
		{ LN, &ipv6_info, "::2-::1", NULL, -1, },

		/* can contain %any */
		{ LN, &ipv4_info, "0.0.0.0-0.0.0.0", "0.0.0.0/32", 1, },
		{ LN, &ipv4_info, "0.0.0.0-0.0.0.1", "0.0.0.0/31", 2, },
		{ LN, &ipv6_info, "::-::", "::/128", 1, },
		{ LN, &ipv6_info, "::-::1", "::/127", 2, },
		{ LN, &ipv6_info, "::/97", "::/97", ((uintmax_t)UINT32_MAX + 1) >> 1, },
		{ LN, &ipv6_info, "::0/64", "::/64", UINT64_MAX, },
		{ LN, &ipv6_info, "::0/127", "::/127", 2, },
		{ LN, &ipv6_info, "::/0", "::/0", UINTMAX_MAX, },

		/* nonsense */
		{ LN, &ipv4_info, "1.2.3.0-nonenone", NULL, -1, },
		{ LN, &ipv4_info, "", NULL, -1, },
		{ LN, &ipv4_info, "-", NULL, -1, },
		{ LN, &ipv4_info, "_/_", NULL, -1, },
		{ LN, &ipv6_info, "%default", NULL, -1, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		diag_t d;
		const struct test *t = &tests[ti];
		if (t->str != NULL) {
			PRINT("%s '%s' -> %s pool-size %ju",
			      pri_afi(t->afi), t->in, t->str, t->pool_size);
		} else {
			PRINT("%s '%s' -> <error>", pri_afi(t->afi), t->in);
		}
		const char *oops = NULL;

		ip_pool tmp, *pool = &tmp;
		d = ttopool_num(shunk1(t->in), t->afi, pool);
		if (d != NULL && t->str == NULL) {
			/* Error was expected, do nothing */
			pfree_diag(&d);
			continue;
		}
		if (oops != NULL && t->str != NULL) {
			/* Error occurred, but we didn't expect one */
			FAIL("ttopool() failed: %s", oops);
		}

		CHECK_INFO(pool);
		if (t->str == NULL) {
			continue;
		}
		CHECK_STR2(pool);

		if (t->pool_size > 0) {
			uintmax_t size = pool_size(*pool);
			if (t->pool_size != size) {
				pool_buf rb;
				FAIL("pool_size(%s) returned %ju, expecting %ju",
				     str_pool(pool, &rb),
				     size, t->pool_size);
			}
		}
	}
}

static void check_pool_from_subnet(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		const char *start;
		const char *end;
	} tests[] = {
		{ LN, &ipv4_info, "0.0.0.0/1", "0.0.0.0", "127.255.255.255", },
		{ LN, &ipv4_info, "1.2.2.0/23", "1.2.2.0", "1.2.3.255", },
		{ LN, &ipv4_info, "1.2.3.0/24", "1.2.3.0", "1.2.3.255", },
		{ LN, &ipv4_info, "1.2.3.0/25", "1.2.3.0", "1.2.3.127", },
		{ LN, &ipv4_info, "1.2.3.4/31", "1.2.3.4", "1.2.3.5", },
		{ LN, &ipv4_info, "1.2.3.4/32", "1.2.3.4", "1.2.3.4", },
		{ LN, &ipv6_info, "::/1", "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", },
		{ LN, &ipv6_info, "1:2:3:4::/63", "1:2:3:4::", "1:2:3:5:ffff:ffff:ffff:ffff", },
		{ LN, &ipv6_info, "1:2:3:4::/64", "1:2:3:4::", "1:2:3:4:ffff:ffff:ffff:ffff", },
		{ LN, &ipv6_info, "1:2:3:4::/65", "1:2:3:4::", "1:2:3:4:7fff:ffff:ffff:ffff", },
		{ LN, &ipv6_info, "1:2:3:4:8000::/65", "1:2:3:4:8000::", "1:2:3:4:ffff:ffff:ffff:ffff", },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:8/127", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", },
		{ LN, &ipv6_info, "1:2:3:4:5:6:7:8/128", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s' -> '%s'..'%s'", pri_afi(t->afi), t->in, t->start, t->end);

		ip_subnet tmp, *subnet = &tmp;
		ip_address nonzero_host;
		oops = ttosubnet_num(shunk1(t->in), t->afi,
				     subnet, &nonzero_host);
		if (oops != NULL) {
			FAIL("ttosubnet(%s) failed: %s", t->in, oops);
		}
		if (nonzero_host.ip.is_set) {
			FAIL("ttosubnet(%s) failed: non-zero host identifier", t->in);
		}

		CHECK_INFO(subnet);

		ip_pool tr = pool_from_subnet(*subnet), *pool = &tr;
		CHECK_INFO(pool);

		address_buf start_buf;
		ip_address r_start = pool_start(*pool);
		const char *start = str_address(&r_start, &start_buf);
		if (!streq(t->start, start)) {
			FAIL("r.start is '%s', expected '%s'",
				start, t->start);
		}
		CHECK_AFI(t->afi, address, &r_start);

		address_buf end_buf;
		ip_address r_end = pool_end(*pool);
		const char *end = str_address(&r_end, &end_buf);
		if (!streq(t->end, end)) {
			FAIL("r.end is '%s', expected '%s'",
				end, t->end);
		}
		CHECK_AFI(t->afi, address, &r_end);

	}
}

static void check_pool_is(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *lo;
		const char *hi;
		const char *str;
		bool is_unset;
		bool is_zero;
		uintmax_t size;
	} tests[] = {
		{ LN, NULL, "", "",                "<unset-pool>",   .is_unset = true, },

		{ LN, &ipv4_info, "0.0.0.0", "0.0.0.0",  "0.0.0.0/32", .is_zero = true, .size = 1, },
		{ LN, &ipv4_info, "0.0.0.1", "0.0.0.2",  "0.0.0.1-0.0.0.2", .size = 2, },

		{ LN, &ipv6_info, "::", "::",            "::/128",           .is_zero = true, .size = 1, },
		{ LN, &ipv6_info, "::1", "::2",          "::1-::2",         .size = 2, },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s'-'%s'", pri_afi(t->afi), t->lo, t->hi)

		const struct ip_info *afi = t->afi;

		ip_address lo;
		if (strlen(t->lo) > 0) {
			oops = ttoaddress_num(shunk1(t->lo), afi, &lo);
			if (oops != NULL) {
				FAIL("ttoaddress_num() failed converting '%s'", t->lo);
			}
		} else {
			lo = unset_address;
		}

		ip_address hi;
		if (strlen(t->hi) > 0) {
			oops = ttoaddress_num(shunk1(t->hi), afi, &hi);
			if (oops != NULL) {
				FAIL("ttoaddress_num() failed converting '%s'", t->hi);
			}
		} else {
			hi = unset_address;
		}

		ip_pool tmp = (strlen(t->lo) == 0 ? unset_pool :
				pool_from_raw(HERE, afi,
					       lo.bytes, hi.bytes,
					       afi->mask_cnt));
		ip_pool *pool = &tmp;
		CHECK_INFO(pool);
		CHECK_STR2(pool);
		CHECK_COND(pool, is_unset);
		CHECK_COND2(pool, is_zero);
		CHECK_UNOP(pool, size, "%ju", );
	}
}

static void check_pool_op_pool(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *l;
		const char *r;
		bool pool_eq_pool;
		bool pool_in_pool;
		bool pool_overlaps_pool;
		bool address_in_pool;
	} tests[] = {

		/* eq */
		{ LN, NULL, "0.0.0.1", "0.0.0.1",                true,  true,  true,  true, },
		{ LN, NULL, "0.0.1.0/24", "0.0.1.0/24",          true,  true,  true,  true, },
		{ LN, NULL, "::0100/120", "::0100/120",          true,  true,  true,  true, },

		/* ne */
		{ LN, NULL, "0.0.1.0/24", "0.0.2.0/24",          false, false, false, false, },
		{ LN, NULL, "0.0.0.1", "0.0.0.2",                false, false, false, false, },
		{ LN, NULL, "::1", "::2",                        false, false, false, false, },
		{ LN, NULL, "::1", "0.0.0.1",                    false, false, false, false, },

		/* in */
		{ LN, NULL, "::0124", "::0100/120",              false, true,  true,  true, },
		{ LN, NULL, "::0124/126", "::0100/120",          false, true,  true,  true, },

		/* out */
		{ LN, NULL, "::0100/120", "::0124",              false, false, true,  false, },
		{ LN, NULL, "::0100/120", "::0124/126",          false, false, true,  false, },

		/* overlap */
		{ LN, NULL, "::1-::2", "::2-::3",                false, false, true,  false, },

		/* silly */
		{ LN, &ipv4_info, NULL, "0.0.0.1",       false, false, false, false, },
		{ LN, &ipv4_info, "0.0.0.1", NULL,       false, false, false, false, },

	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s vs %s", t->l, t->r);

#define TT(R)								\
		ip_pool R;						\
		if (t->R != NULL) {					\
			diag_t d = ttopool_num(shunk1(t->R), 0, &R);	\
			if (d != NULL) {				\
				FAIL("ttopool(%s) failed: %s", t->R,	\
				     str_diag(d));			\
			}						\
		} else {						\
			R = unset_pool;					\
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
		T(pool_eq_pool, l, r);
		T(pool_in_pool, l, r);
		T(pool_overlaps_pool, l, r);
		ip_address a = pool_start(l);
		T(address_in_pool,a,r);
	}
}

static void check_pool_offset_to_cidr(void)
{
	static const struct test {
		int line;
		const char *pool;
		uintmax_t offset;
		const char *cidr;
	} tests[] = {
		{ LN, "1.0.0.0/32",	         0, "1.0.0.0/32", },
		{ LN, "1.0.0.0/31",	         1, "1.0.0.1/32", },
		{ LN, "1.0.0.0/24",	       255, "1.0.0.255/32", },
		{ LN, "1.0.0.0/24",            256, NULL, },
		{ LN, "1.0.0.0/23",            256, "1.0.1.0/32", },

		/* bits */
		{ LN, "::1-::2",                 0, "::1/128", },
		{ LN, "::1-::2",                 1, "::2/128", },

		/* cidr */
		{ LN, "1.0.0.0/24/28",           0, "1.0.0.0/28", },
		{ LN, "1.0.0.0/24/28",           8, "1.0.0.128/28", },
		{ LN, "1.0.0.0/24/28",           15, "1.0.0.240/28", },

		/* carry/overflow */
		{ LN, "::ffff-::1:0000",         1, "::1:0/128", },
		{ LN, "::ffff-::1:ffff",   0x10001, NULL, },
		{ LN, "0.0.0.1-255.255.255.255", UINT32_MAX-1ULL, "255.255.255.255/32", },
		{ LN, "0.0.0.1-255.255.255.255", UINT32_MAX,      NULL, },
		{ LN, "0.0.0.1-255.255.255.255", UINT32_MAX+1ULL, NULL, },
	};

	err_t err;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		diag_t d;
		const struct test *t = &tests[ti];
		PRINT("%s + %jd -> %s", t->pool, t->offset,
		      t->cidr == NULL ? "<unset>" : t->cidr);

		/* convert it *to* internal format */
		ip_pool pool;
		d = ttopool_num(shunk1(t->pool), NULL/*auto-detect*/, &pool);
		if (d != NULL) {
			FAIL("ttopool(%s) failed: %s", t->pool,
			     str_diag(d));
		}

		ip_cidr cidr;
		err = pool_offset_to_cidr(pool, t->offset, &cidr);
		cidr_buf out;
		str_cidr(&cidr, &out);

		if (t->cidr == NULL) {
			if (cidr.ip.is_set) {
				FAIL("pool_offset_to_cidr(%s + %jd -> %s) should have returned <unset>",
				     t->pool, t->offset, out.buf);
			}
		} else if (!streq(out.buf, t->cidr)) {
			FAIL("pool_offset_to_cidr(%s + %jd -> %s) should have returned %s",
			     t->pool, t->offset, out.buf, t->cidr);
		}

		PRINT("pool_offset_to_cidr(%s + %jd -> %s): %s",
		      t->pool, t->offset, out.buf, err == NULL ? "<ok>" : err);

	}
}

static void check_cidr_to_pool_offset(void)
{
	static const struct test {
		int line;
		const char *pool;
		const char *cidr;
		uintmax_t offset;
		bool ok;
	} tests[] = {
		{ LN, "1.0.0.0/32",              "1.0.0.0", 0, true, },
		{ LN, "0.0.0.1-255.255.255.255", "255.255.255.255", UINT32_MAX-1ULL, true, },

		/* full subnet cidrs */
		{ LN, "1.0.0.0/24/28",           "1.0.0.0", 0, true, },
		{ LN, "1.0.0.0/24/28",           "1.0.0.128/28", 8, true, },
		{ LN, "1.0.0.0/24/28",           "1.0.0.255/28", 15, true, },

		/* out of pool */
		{ LN, "1.0.0.0/32",              "0.255.255.255", UINTMAX_MAX, false, },
		{ LN, "1.0.0.0/32",              "1.0.0.1", UINTMAX_MAX, false, },
	};

	err_t err;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		diag_t d;
		const struct test *t = &tests[ti];
		PRINT("%s - %s -> %ju ok: %s",
		      t->pool,
		      t->cidr,
		      t->offset,
		      bool_str(t->ok));

		ip_pool pool;
		d = ttopool_num(shunk1(t->pool), NULL/*auto-detect*/, &pool);
		if (d != NULL) {
			FAIL("ttopool(%s) failed: %s", t->pool,
			     str_diag(d));
		}

		ip_cidr cidr;
		err = ttocidr_num(shunk1(t->cidr), NULL/*auto-detect*/, &cidr);
		if (err != NULL) {
			FAIL("ttocidr_num(%s) failed: %s", t->cidr, err);
		}

		uintmax_t offset;
		err = cidr_to_pool_offset(pool, cidr, &offset);

		if (t->ok) {
			if (err != NULL) {
				FAIL("cidr_to_pool_offset(%s - %s -> %ju) unexpectedly failed: %s",
				     t->pool, t->cidr, offset, err);
			}
		} else if (err == NULL) {
			FAIL("cidr_to_pool_offset(%s - %s -> %ju) unexpectedly succeeded",
			     t->pool, t->cidr, offset);
		}

		if (offset != t->offset) {
			FAIL("cidr_to_pool_offset(%s - %s -> %ju) should have returned %jx",
			     t->pool, t->cidr, offset, t->offset);
		}

		PRINT("cidr_to_pool_offset(%s - %s -> %ju): %s",
		      t->pool, t->cidr, offset, err == NULL ? "<ok>" : err);

	}
}

void ip_pool_check(struct logger *logger UNUSED)
{
	check_ippool_bits();
	check_ttopool__to__str_pool();
	check_pool_from_subnet();
	check_pool_is();
	check_pool_op_pool();
	check_pool_offset_to_cidr();
	check_cidr_to_pool_offset();
}
