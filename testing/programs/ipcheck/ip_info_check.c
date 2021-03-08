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

#define PRINT_INFO(FILE, FMT, ...)					\
	PRINT(FILE, "%s"FMT,						\
	      pri_family(t->family),##__VA_ARGS__);
#define FAIL_INFO(FMT, ...)				\
	FAIL(PRINT_INFO, FMT,##__VA_ARGS__)

#define CHECK_EQ(TYPE) \
	for (size_t ti = 0; ti < elemsof(tests); ti++) {		\
		const struct test *t = &tests[ti];			\
		const ip_##TYPE *ai = t->TYPE;				\
		for (size_t tj = 0; tj < elemsof(tests); tj++) {	\
			const ip_##TYPE *aj = tests[tj].TYPE;		\
			TYPE##_buf bi, bj;				\
			bool expected = eq[ti][tj];			\
			PRINT_INFO(stdout, " [%zu][%zu] "#TYPE"_eq(%s,%s) == %s", \
				   ti, tj,				\
				   str_##TYPE(ai, &bi),			\
				   str_##TYPE(aj, &bj),			\
				   bool_str(expected));			\
			bool actual = TYPE##_eq(ai, aj);		\
			if (expected != actual) {			\
				FAIL_INFO(" [%zu][%zu] "#TYPE"_eq(%s,%s) returned %s, expecting %s", \
					  ti, tj,			\
					  str_##TYPE(ai, &bi),		\
					  str_##TYPE(aj, &bj),		\
					  bool_str(actual),		\
					  bool_str(expected));		\
			}						\
		}							\
	}

static void check_ip_info_address(void)
{
	static const struct test {
		int family;
		const ip_address *address;
		bool unset;
		bool any;
		bool specified;
		bool loopback;
	} tests[] = {
		{ 0, NULL,                        .unset = true, },
		{ 0, &unset_address,              .unset = true, },
		{ 4, &ipv4_info.address.any,      .any = true },
		{ 6, &ipv6_info.address.any,      .any = true },
		{ 4, &ipv4_info.address.loopback, .specified = true, .loopback = true, },
		{ 6, &ipv6_info.address.loopback, .specified = true, .loopback = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		CHECK_ADDRESS(PRINT_INFO, t->address);
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
		int family;
		const ip_endpoint *endpoint;
		bool unset;
		bool any;
		bool specified;
		bool loopback;
		int hport;
	} tests[] = {
		{ 0, NULL,                    .unset = true, .hport = -1, },
		{ 0, &unset_endpoint,         .unset = true, .hport = -1, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		const ip_endpoint *e = t->endpoint;
		CHECK_TYPE(PRINT_INFO, endpoint_type(e));

		ip_address a = endpoint_address(e);
		CHECK_ADDRESS(PRINT_INFO, &a);

		if (!t->unset) {
			int hport = endpoint_hport(e);
			if (hport != t->hport) {
				FAIL(PRINT_INFO, " endpoint_port() returned %d, expecting %d",
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
		int family;
		const ip_subnet *subnet;
		bool is_unset;
		bool contains_all_addresses;
		bool is_specified;
		bool contains_one_address;
		bool contains_no_addresses;
	} tests[] = {
		{ 0, NULL,                    .is_unset = true, },
		{ 0, &unset_subnet,           .is_unset = true, },
		{ 4, &ipv4_info.subnet.none,  .contains_no_addresses = true, },
		{ 6, &ipv6_info.subnet.none,  .contains_no_addresses = true, },
		{ 4, &ipv4_info.subnet.all,   .contains_all_addresses = true, },
		{ 6, &ipv6_info.subnet.all,   .contains_all_addresses = true, },
	};
#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s unset=%s all=%s some=%s one=%s none=%s"FMT,	\
	      pri_family(t->family),					\
	      bool_str(t->is_unset),					\
	      bool_str(t->contains_all_addresses),			\
	      bool_str(t->is_specified),				\
	      bool_str(t->contains_one_address),			\
	      bool_str(t->contains_no_addresses),			\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		OUT(stdout, "");

		if (t->family != 0) {
			CHECK_TYPE(PRINT_INFO, subnet_type(t->subnet));
		}

#define T(COND)								\
		bool COND = subnet_##COND(t->subnet);			\
		if (COND != t->COND) {					\
			FAIL_INFO("subnet_"#COND"() returned %s, expecting %s", \
				  bool_str(COND), bool_str(t->COND));	\
		}
		T(is_unset);
		T(contains_all_addresses);
		T(is_specified);
		T(contains_one_address);
		T(contains_no_addresses);
#undef T
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
		int family;
		const ip_selector *selector;
		bool is_unset;
		bool contains_all_addresses;
		bool is_one_address;
		bool contains_no_addresses;
	} tests[] = {
		{ 0, NULL,                     .is_unset = true, },
		{ 0, &unset_selector,          .is_unset = true, },
		{ 4, &ipv4_info.selector.none, .contains_no_addresses = true, },
		{ 6, &ipv6_info.selector.none, .contains_no_addresses = true, },
		{ 4, &ipv4_info.selector.all,  .contains_all_addresses = true, },
		{ 6, &ipv6_info.selector.all,  .contains_all_addresses = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		const ip_selector *s = t->selector;
		CHECK_TYPE(PRINT_INFO, selector_type(s));

#define T(COND)								\
		bool COND = selector_##COND(t->selector);		\
		if (COND != t->COND) {					\
			FAIL_INFO("selector_"#COND"() returned %s, expecting %s", \
				  bool_str(COND), bool_str(t->COND));	\
		}
		T(is_unset);
		T(contains_all_addresses);
		T(is_one_address);
		T(contains_no_addresses);
#undef T
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
		int family;
		const ip_range *range;
		bool unset;
	} tests[] = {
		{ 0, NULL,                 .unset = true, },
		{ 0, &unset_range,         .unset = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		const ip_range *r = t->range;
		CHECK_TYPE(PRINT_INFO, range_type(r));
	}

	/* must match table above */
	bool eq[elemsof(tests)][elemsof(tests)] = {
		/* unset/NULL */
		[0][0] = true,
		[0][1] = true,
		[1][1] = true,
		[1][0] = true,
		/* other */
	};
	CHECK_EQ(range);
}

void ip_info_check(void)
{
	check_ip_info_address();
	check_ip_info_endpoint();
	check_ip_info_subnet();
	check_ip_info_selector();
	check_ip_info_range();
}
