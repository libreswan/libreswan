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

#define PRINT_INFO(FILE, FMT, ...)					\
	PRINT(FILE, "%s"FMT,						\
	      pri_family(t->family),##__VA_ARGS__);
#define FAIL_INFO(FMT, ...)				\
	FAIL(PRINT_INFO, FMT,##__VA_ARGS__)

static void check_ip_info_address(void)
{
	static const struct test {
		int family;
		const ip_address *address;
		bool set;
		bool any;
		bool specified;
		bool loopback;
	} tests[] = {
		{ 0, &unset_address,              .set = false, },
		{ 4, &ipv4_info.any_address,      .set = true, .any = true },
		{ 6, &ipv6_info.any_address,      .set = true, .any = true },
		{ 4, &ipv4_info.loopback_address, .set = true, .specified = true, .loopback = true, },
		{ 6, &ipv6_info.loopback_address, .set = true, .specified = true, .loopback = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		CHECK_ADDRESS(PRINT_INFO, t->address);
	}
}

static void check_ip_info_endpoint(void)
{
	static const struct test {
		int family;
		const ip_endpoint *endpoint;
		bool set;
		bool any;
		bool specified;
		bool loopback;
		int hport;
	} tests[] = {
		{ 0, &unset_endpoint,         .set = false, .hport = -1, },
		{ 4, &ipv4_info.any_endpoint, .set = true, .any = true },
		{ 6, &ipv6_info.any_endpoint, .set = true, .any = true },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		ip_endpoint e = *t->endpoint;
		CHECK_TYPE(PRINT_INFO, endpoint_type(&e));

		ip_address a = endpoint_address(&e);
		CHECK_ADDRESS(PRINT_INFO, &a);

		if (t->set) {
			int hport = endpoint_hport(&e);
			if (hport != t->hport) {
				FAIL(PRINT_INFO, " endpoint_port() returned %d, expecting %d",
				     hport, t->hport);
			}
		}
	}
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
		{ 0, &unset_subnet,              true, false, false, false, false, },
		{ 4, &ipv4_info.no_addresses,    false, false, false, false, true },
		{ 6, &ipv6_info.no_addresses,    false, false, false, false, true },
		{ 4, &ipv4_info.all_addresses,   false, true, false, false, false, },
		{ 6, &ipv6_info.all_addresses,   false, true, false, false, false, },
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
}

void ip_info_check(void)
{
	check_ip_info_address();
	check_ip_info_endpoint();
	check_ip_info_subnet();
}
