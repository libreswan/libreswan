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
#include "ip_selector.h"
#include "ip_range.h"

#include "ipcheck.h"

/*
 * Check equality.  First form assumes NULL allowed, second does
 * not.
 */

#define CHECK_EQ(TYPE)							\
	for (size_t ti = 0; ti < elemsof(tests); ti++) {		\
		const struct test *t = &tests[ti];			\
		const ip_##TYPE *ai = t->TYPE;				\
		for (size_t tj = 0; tj < elemsof(tests); tj++) {	\
			const ip_##TYPE *aj = tests[tj].TYPE;		\
			TYPE##_buf bi, bj;				\
			bool expected = eq[ti][tj];			\
			PRINT("[%zu][%zu] "#TYPE"_eq(%s,%s) == %s",	\
			      ti, tj,					\
			      str_##TYPE(ai, &bi),			\
			      str_##TYPE(aj, &bj),			\
			      bool_str(expected));			\
			bool actual = TYPE##_eq(ai, aj);		\
			if (expected != actual) {			\
				FAIL("[%zu][%zu] "#TYPE"_eq(%s,%s) returned %s, expecting %s", \
				     ti, tj,				\
				     str_##TYPE(ai, &bi),		\
				     str_##TYPE(aj, &bj),		\
				     bool_str(actual),			\
				     bool_str(expected));		\
			}						\
		}							\
	}

#define CHECK_EQ2(TYPE)							\
	for (size_t ti = 0; ti < elemsof(tests); ti++) {		\
		const struct test *t = &tests[ti];			\
		const ip_##TYPE *ai =					\
			(tests[ti].TYPE == NULL ? &unset_##TYPE : tests[ti].TYPE); \
		for (size_t tj = 0; tj < elemsof(tests); tj++) {	\
			const ip_##TYPE *aj =				\
				(tests[tj].TYPE == NULL ? &unset_##TYPE : tests[tj].TYPE); \
			TYPE##_buf bi, bj;				\
			bool expected = eq[ti][tj];			\
			PRINT("[%zu][%zu] "#TYPE"_eq(%s,%s) == %s",	\
			      ti, tj,					\
			      str_##TYPE(ai, &bi),			\
			      str_##TYPE(aj, &bj),			\
			      bool_str(expected));			\
			bool actual = TYPE##_eq(*ai, *aj);		\
			if (expected != actual) {			\
				FAIL("[%zu][%zu] "#TYPE"_eq(%s,%s) returned %s, expecting %s", \
				     ti, tj,				\
				     str_##TYPE(ai, &bi),		\
				     str_##TYPE(aj, &bj),		\
				     bool_str(actual),			\
				     bool_str(expected));		\
			}						\
		}							\
	}

static void check_ip_info_address(void)
{
	static const struct test {
		int line;
		int family;
		const ip_address *address;
		bool is_unset;
		bool is_any;
		bool is_specified;
		bool is_loopback;
	} tests[] = {
		{ LN, 0, NULL,                        .is_unset = true, },
		{ LN, 0, &unset_address,              .is_unset = true, },
		{ LN, 4, &ipv4_info.address.any,      .is_any = true },
		{ LN, 6, &ipv6_info.address.any,      .is_any = true },
		{ LN, 4, &ipv4_info.address.loopback, .is_specified = true, .is_loopback = true, },
		{ LN, 6, &ipv6_info.address.loopback, .is_specified = true, .is_loopback = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s", pri_family(t->family));

		const ip_address *address = t->address;
		CHECK_TYPE(address_type(address));

		CHECK_COND(address, is_unset);
		CHECK_COND(address, is_any);
		CHECK_COND(address, is_specified);
		CHECK_COND(address, is_loopback);
	}

	/* must match table above */
	bool eq[elemsof(tests)][elemsof(tests)] = {
		/* unset/NULL */
		[0][0] = true,
		[0][1] = true,
		[1][1] = true,
		[1][0] = true,
		/* other */
		[2][2] = true,
		[3][3] = true,
		[4][4] = true,
		[5][5] = true,
	};
	CHECK_EQ(address);
}

static void check_ip_info_endpoint(void)
{
	static const struct test {
		int line;
		int family;
		const ip_endpoint *endpoint;
		bool is_unset;
		bool is_specified;
		int hport;
	} tests[] = {
		{ LN, 0, NULL,                    .is_unset = true, .hport = -1, },
		{ LN, 0, &unset_endpoint,         .is_unset = true, .hport = -1, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s", pri_family(t->family));

		const ip_endpoint *endpoint = t->endpoint;
		CHECK_TYPE(endpoint_type(endpoint));

		CHECK_COND(endpoint, is_unset);
		CHECK_COND(endpoint, is_specified);

		if (!t->is_unset) {
			int hport = endpoint_hport(endpoint);
			if (hport != t->hport) {
				FAIL(" endpoint_port() returned %d, expecting %d",
				     hport, t->hport);
			}
		}
	}

	/* must match table above */
	bool eq[elemsof(tests)][elemsof(tests)] = {
		/* unset/NULL */
		[0][0] = true,
		[0][1] = true,
		[1][1] = true,
		[1][0] = true,
	};
	CHECK_EQ(endpoint);
}

static void check_ip_info_subnet(void)
{
	static const struct test {
		int line;
		int family;
		const ip_subnet *subnet;
		bool is_unset;
		bool contains_all_addresses;
		bool is_specified;
		bool contains_one_address;
		bool contains_no_addresses;
	} tests[] = {
		{ LN, 0, NULL,                    .is_unset = true, },
		{ LN, 0, &unset_subnet,           .is_unset = true, },
		{ LN, 4, &ipv4_info.subnet.none,  .contains_no_addresses = true, },
		{ LN, 6, &ipv6_info.subnet.none,  .contains_no_addresses = true, },
		{ LN, 4, &ipv4_info.subnet.all,   .contains_all_addresses = true, },
		{ LN, 6, &ipv6_info.subnet.all,   .contains_all_addresses = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s unset=%s all=%s some=%s one=%s none=%s",
		      pri_family(t->family),
		      bool_str(t->is_unset),
		      bool_str(t->contains_all_addresses),
		      bool_str(t->is_specified),
		      bool_str(t->contains_one_address),
		      bool_str(t->contains_no_addresses));

		const ip_subnet *subnet = t->subnet;
		if (t->family != 0) {
			CHECK_TYPE(subnet_type(subnet));
		}

		CHECK_COND(subnet, is_unset);
		CHECK_COND(subnet, contains_all_addresses);
		CHECK_COND(subnet, is_specified);
		CHECK_COND(subnet, contains_one_address);
		CHECK_COND(subnet, contains_no_addresses);
	}

	/* must match table above */
	bool eq[elemsof(tests)][elemsof(tests)] = {
		/* unset/NULL */
		[0][0] = true,
		[0][1] = true,
		[1][1] = true,
		[1][0] = true,
		/* other */
		[2][2] = true,
		[3][3] = true,
		[4][4] = true,
		[5][5] = true,
	};
	CHECK_EQ(subnet);
}

static void check_ip_info_selector(void)
{
	static const struct test {
		int line;
		int family;
		const ip_selector *selector;
		bool is_unset;
		bool contains_all_addresses;
		bool is_one_address;
		bool contains_no_addresses;
	} tests[] = {
		{ LN, 0, NULL,                     .is_unset = true, },
		{ LN, 0, &unset_selector,          .is_unset = true, },
		{ LN, 4, &ipv4_info.selector.none, .contains_no_addresses = true, },
		{ LN, 6, &ipv6_info.selector.none, .contains_no_addresses = true, },
		{ LN, 4, &ipv4_info.selector.all,  .contains_all_addresses = true, },
		{ LN, 6, &ipv6_info.selector.all,  .contains_all_addresses = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s", pri_family(t->family));

		const ip_selector *selector = t->selector;
		CHECK_TYPE(selector_type(selector));

		CHECK_COND(selector, is_unset);
		CHECK_COND(selector, contains_all_addresses);
		CHECK_COND(selector, is_one_address);
		CHECK_COND(selector, contains_no_addresses);
	}

	/* must match table above */
	bool eq[elemsof(tests)][elemsof(tests)] = {
		/* unset/NULL */
		[0][0] = true,
		[0][1] = true,
		[1][1] = true,
		[1][0] = true,
		/* other */
		[2][2] = true,
		[3][3] = true,
		[4][4] = true,
		[5][5] = true,
	};
	CHECK_EQ(selector);
}

static void check_ip_info_range(void)
{
	static const struct test {
		int line;
		int family;
		const ip_range *range;
		bool is_unset;
		bool is_specified;
	} tests[] = {
		{ LN, 0, NULL,                 	.is_unset = true, },
		{ LN, 0, &unset_range,         	.is_unset = true, },
		{ LN, 4, &ipv4_info.range.none,     .is_unset = false, },
		{ LN, 6, &ipv6_info.range.none,     .is_unset = false, },
		{ LN, 4, &ipv4_info.range.all,      .is_unset = false, },
		{ LN, 6, &ipv6_info.range.all,      .is_unset = false, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s", pri_family(t->family));

		const ip_range *range = t->range;
		CHECK_TYPE(range_type(range));

		CHECK_COND(range, is_unset);
		CHECK_COND2(range, is_specified);
	}

	/* must match table above */
	bool eq[elemsof(tests)][elemsof(tests)] = {
		/* unset/NULL */
		[0][0] = true,
		[0][1] = true,
		[1][1] = true,
		[1][0] = true,
		/* other */
		[2][2] = true,
		[3][3] = true,
		[4][4] = true,
		[5][5] = true,
	};
	CHECK_EQ2(range);
}

void ip_info_check(void)
{
	check_ip_info_address();
	check_ip_info_endpoint();
	check_ip_info_subnet();
	check_ip_info_selector();
	check_ip_info_range();
}
