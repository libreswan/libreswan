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
		bool set;
		bool no;
		bool all;
	} tests[] = {
		{ 0, &unset_subnet,              .set = false, },
		{ 4, &ipv4_info.no_addresses,    .set = true, .no = true },
		{ 6, &ipv6_info.no_addresses,    .set = true, .no = true },
		{ 4, &ipv4_info.all_addresses,   .set = true, .all = true },
		{ 6, &ipv6_info.all_addresses,   .set = true, .all = true },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		CHECK_TYPE(PRINT_INFO, subnet_type(t->subnet));

		bool set = subnet_is_set(t->subnet);
		if (set != t->set) {
			FAIL_INFO("subnet_is_set() returned %s, expecting %s",
				  bool_str(set), bool_str(t->set));
		}

		if (t->set) {
			bool no = subnet_contains_no_addresses(t->subnet);
			if (no != t->no) {
				FAIL_INFO("subnet_is_no() returned %s, expecting %s",
					  bool_str(no), bool_str(t->no));
			}
		}

		if (t->set) {
			bool all = subnet_contains_all_addresses(t->subnet);
			if (all != t->all) {
				FAIL_INFO("subnet_is_all() returned %s, expecting %s",
					  bool_str(all), bool_str(t->all));
			}
		}

	}
}

void ip_info_check(void)
{
	check_ip_info_address();
	check_ip_info_endpoint();
	check_ip_info_subnet();
}
