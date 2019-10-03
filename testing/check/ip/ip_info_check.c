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
	PRINT(FILE, "%s %s"FMT,						\
	      pri_family(t->family), t->info->ip_name ,##__VA_ARGS__);

static void check_ip_info_any_address(void)
{
	static const struct test {
		int family;
		const struct ip_info *info;
		bool invalid;
		bool any;
		bool specified;
		bool loopback;
	} tests[] = {
		{ 4, &ipv4_info, .any = true },
		{ 6, &ipv6_info, .any = true },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		CHECK_ADDRESS(PRINT_INFO, &t->info->any_address);
		ip_address a = address_any(IP_TYPE(t->family));
		CHECK_ADDRESS(PRINT_INFO, &a);
	}
}

static void check_ip_info_loopback_address(void)
{
	static const struct test {
		int family;
		const struct ip_info *info;
		bool invalid;
		bool any;
		bool specified;
		bool loopback;
	} tests[] = {
		{ 4, &ipv4_info, .specified = true, .loopback = true, },
		{ 6, &ipv6_info, .specified = true, .loopback = true, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");
		CHECK_ADDRESS(PRINT_INFO, &t->info->loopback_address);
	}
}

static void check_ip_info_any_endpoint(void)
{
	static const struct test {
		int family;
		const struct ip_info *info;
		bool invalid;
		bool any;
		bool specified;
		bool loopback;
	} tests[] = {
		{ 4, &ipv4_info, .any = true },
		{ 6, &ipv6_info, .any = true },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_INFO(stdout, "");

		ip_endpoint e = t->info->any_endpoint;
		CHECK_TYPE(PRINT_INFO, endpoint_type(&e));

		ip_address a = endpoint_address(&e);
		CHECK_ADDRESS(PRINT_INFO, &a);

		int hport = endpoint_hport(&e);
		if (hport != 0) {
			FAIL(PRINT_INFO, " endpoint_port() returned %d, expecting zero", hport);
		}
	}
}

void ip_info_check(void)
{
	check_ip_info_any_address();
	check_ip_info_loopback_address();
	check_ip_info_any_endpoint();
}
