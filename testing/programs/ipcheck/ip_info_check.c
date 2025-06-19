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

#define CHECK_OP(L,OP,R)						\
	for (size_t tl = 0; tl < elemsof(L##_tests); tl++) {		\
		/*hack*/const typeof(L##_tests[0]) *t = &L##_tests[tl];	\
		/*hack*/size_t ti = tl;					\
		const ip_##L *l = L##_tests[tl].L;			\
		if (l == NULL)						\
			continue;					\
		for (size_t tr = 0; tr < elemsof(R##_tests); tr++) {	\
			const ip_##R *r = R##_tests[tr].R;		\
			if (r == NULL)					\
				continue;				\
			bool expected = false;				\
			for (size_t to = 0; to < elemsof(L##_op_##R); to++) { \
				const typeof(L##_op_##R[0]) *op = &L##_op_##R[to]; \
				if (l == op->l && r == op->r) {		\
					expected = op->OP;		\
					break;				\
				}					\
			}						\
			bool b = L##_##OP##_##R(*l, *r);		\
			/* work with int *cmp() */			\
			if (b != expected) {				\
				L##_buf lb;				\
				R##_buf rb;				\
				FAIL(#L "_" #OP "_" #R "(%s,%s) returned %s, expected %s", \
				     str_##L(l, &lb), str_##R(r, &rb),	\
				     bool_str(b), bool_str(expected));	\
			}						\
		}							\
	}

#define CHECK_FROM_ZERO(TO,FROM)					\
		if (FROM != NULL) {					\
			ip_##TO TO = TO##_from_##FROM(*FROM);		\
			bool from_is_zero = (!FROM##_is_unset(FROM) &&	\
					     !FROM##_is_specified(*FROM)); \
			bool to_is_zero = TO##_is_zero(TO);		\
			if (from_is_zero != to_is_zero) {		\
				FROM##_buf b;				\
				FAIL(#TO"_is_zero("#TO"_from_"#FROM"(%s)) returned %s, expecting %s", \
				     str_##FROM(FROM, &b),		\
				     bool_str(to_is_zero),		\
				     bool_str(from_is_zero));		\
			}						\
		}

#define CHECK_FROM(TO,FROM)						\
		if (FROM != NULL) {					\
			ip_##TO to = TO##_from_##FROM(*FROM);		\
			bool all_from = FROM##_is_all(*FROM); \
			bool all_to = TO##_is_all(to);	\
			if (all_from != all_to) {				\
				FROM##_buf b;				\
				FAIL(#TO"_is_all("#TO"_from_"#FROM"(%s)) returned %s, expecting %s", \
				     str_##FROM(FROM, &b),		\
				     bool_str(all_to), bool_str(all_from)); \
			}						\
		}

static const struct address_test {
	int line;
	const struct ip_info *afi;
	const ip_address *address;
	const char *str;
	bool is_unset;
	bool is_specified;
	bool is_loopback;
} address_tests[] = {
	{ LN, NULL, NULL,                        "<null-address>", .is_unset = true, },
	{ LN, NULL, &unset_address,              "<unset-address>", .is_unset = true, },
	{ LN, &ipv4_info, &ipv4_info.address.unspec,   "0.0.0.0",         .is_unset = false },
	{ LN, &ipv6_info, &ipv6_info.address.unspec,   "::",              .is_unset = false },
	{ LN, &ipv4_info, &ipv4_info.address.loopback, "127.0.0.1",       .is_specified = true, .is_loopback = true, },
	{ LN, &ipv6_info, &ipv6_info.address.loopback, "::1",             .is_specified = true, .is_loopback = true, },
};

static const struct endpoint_test {
	int line;
	const struct ip_info *afi;
	const ip_endpoint *endpoint;
	const char *str;
	bool is_unset;
	bool is_specified;
	bool is_any;
	int hport;
} endpoint_tests[] = {
	{ LN, NULL, NULL,                     "<null-endpoint>",   .is_unset = true, .hport = -1, },
	{ LN, NULL, &unset_endpoint,          "<unset-endpoint>",  .is_unset = true, .hport = -1, },
};

static const struct subnet_test {
	int line;
	const struct ip_info *afi;
	const ip_subnet *subnet;
	const char *str;
	bool is_unset;
	uintmax_t size;
	bool is_all;
	bool is_zero;
} subnet_tests[] = {
	{ LN, NULL, NULL,                    "<null-subnet>",  .is_unset = true, },
	{ LN, NULL, &unset_subnet,           "<unset-subnet>", .is_unset = true, },
	{ LN, &ipv4_info, &ipv4_info.subnet.zero,  "0.0.0.0/32",     .is_zero = true, .size = 1, },
	{ LN, &ipv6_info, &ipv6_info.subnet.zero,  "::/128",         .is_zero = true, .size = 1, },
	{ LN, &ipv4_info, &ipv4_info.subnet.all,   "0.0.0.0/0",      .is_all = true, .size = (uintmax_t)1 << 32, },
	{ LN, &ipv6_info, &ipv6_info.subnet.all,   "::/0",           .is_all = true, .size = UINTMAX_MAX, },
};

static const struct range_test {
	int line;
	const struct ip_info *afi;
	const ip_range *range;
	const char *str;
	bool is_unset;
	bool is_zero;
	bool is_all;
	uintmax_t size;
} range_tests[] = {
	{ LN, NULL, NULL,                  "<null-range>",       .is_unset = true, },
	{ LN, NULL, &unset_range,          "<unset-range>",      .is_unset = true, },
	{ LN, &ipv4_info, &ipv4_info.range.zero, "0.0.0.0/32",   .is_zero = true, .size = 1, },
	{ LN, &ipv6_info, &ipv6_info.range.zero, "::/128",             .is_zero = true, .size = 1, },
	{ LN, &ipv4_info, &ipv4_info.range.all,  "0.0.0.0/0",  .is_all = true,  .size = (uintmax_t)1<<32, },
	{ LN, &ipv6_info, &ipv6_info.range.all,  "::/0",       .is_all = true,  .size = UINTMAX_MAX, },
};

static const struct selector_test {
	int line;
	const struct ip_info *afi;
	const ip_selector *selector;
	const char *str;
	bool is_unset;
	bool is_zero;
	bool is_all;
	bool is_address;
	bool is_subnet;
} selector_tests[] = {
	{ LN, NULL,       NULL,                     "<null-selector>",  .is_unset = true, },
	{ LN, NULL,       &unset_selector,          "<unset-selector>", .is_unset = true, },
	{ LN, &ipv4_info, &ipv4_info.selector.zero, "0.0.0.0/32",       .is_zero = true, .is_subnet = true, },
	{ LN, &ipv6_info, &ipv6_info.selector.zero, "::/128",           .is_zero = true, .is_subnet = true, },
	{ LN, &ipv4_info, &ipv4_info.selector.all,  "0.0.0.0/0",        .is_all = true,  .is_subnet = true, },
	{ LN, &ipv6_info, &ipv6_info.selector.all,  "::/0",             .is_all = true,  .is_subnet = true, },
};

static void check_ip_info_address(void)
{
	for (size_t ti = 0; ti < elemsof(address_tests); ti++) {
		const struct address_test *t = &address_tests[ti];
		PRINT("%s", pri_afi(t->afi));

		const ip_address *address = t->address;

		CHECK_INFO(address);
		CHECK_STR2(address);
		CHECK_COND(address, is_unset);
		CHECK_COND2(address, is_specified);
		CHECK_COND2(address, is_loopback);

		CHECK_FROM_ZERO(subnet, address);
		CHECK_FROM_ZERO(range, address);
		CHECK_FROM_ZERO(selector, address);
	}

	static const struct {
		const ip_address *l;
		const ip_address *r;
		int eq;
	} address_op_address[] = {
		/* any */
		{ &unset_address,              &unset_address,        .eq = true, },
		{ &ipv4_info.address.unspec,   &ipv4_info.address.unspec, .eq = true, },
		{ &ipv6_info.address.unspec,   &ipv6_info.address.unspec, .eq = true, },
		{ &ipv4_info.address.loopback, &ipv4_info.address.loopback, .eq = true, },
		{ &ipv6_info.address.loopback, &ipv6_info.address.loopback, .eq = true, },
	};

	CHECK_OP(address, eq, address);
}

static void check_ip_info_endpoint(void)
{
	for (size_t ti = 0; ti < elemsof(endpoint_tests); ti++) {
		const struct endpoint_test *t = &endpoint_tests[ti];
		PRINT("%s", pri_afi(t->afi));

		const ip_endpoint *endpoint = t->endpoint;

		CHECK_INFO(endpoint);
		CHECK_STR2(endpoint);
		CHECK_COND(endpoint, is_unset);
		CHECK_COND2(endpoint, is_specified);

		if (!t->is_unset) {
			int hport = endpoint_hport(*endpoint);
			if (hport != t->hport) {
				FAIL(" endpoint_port() returned %d, expecting %d",
				     hport, t->hport);
			}
		}

		CHECK_FROM_ZERO(selector, endpoint);
	}

	static const struct {
		const ip_endpoint *l;
		const ip_endpoint *r;
		int eq;
	} endpoint_op_endpoint[] = {
		{ &unset_endpoint, &unset_endpoint, .eq = true, },
	};

	static const struct {
		const ip_endpoint *l;
		const ip_address *r;
		int address_eq;
	} endpoint_op_address[] = {
		{ &unset_endpoint, &unset_address, .address_eq = true, },
	};

	CHECK_OP(endpoint, eq, endpoint);
	CHECK_OP(endpoint, address_eq, address);
}

static void check_ip_info_subnet(void)
{
	for (size_t ti = 0; ti < elemsof(subnet_tests); ti++) {
		const struct subnet_test *t = &subnet_tests[ti];
		PRINT("%s unset=%s size=%ju zero=%s all=%s",
		      pri_afi(t->afi),
		      bool_str(t->is_unset),
		      t->size,
		      bool_str(t->is_zero),
		      bool_str(t->is_all));

		const ip_subnet *subnet = t->subnet;

		CHECK_INFO(subnet);
		CHECK_STR2(subnet);

		CHECK_COND(subnet, is_unset);
		CHECK_COND2(subnet, is_zero);
		CHECK_COND2(subnet, is_all);
		CHECK_UNOP(subnet, size, "%ju", /*NOP*/);

		CHECK_FROM(range, subnet);
		CHECK_FROM(selector, subnet);
	}

	static const struct {
		const ip_subnet *l;
		const ip_subnet *r;
		int eq;
		int in;
	} subnet_op_subnet[] = {
		/* any */
		{ &unset_subnet, &unset_subnet, .eq = true, },
		/* none in none */
		{ &ipv4_info.subnet.zero, &ipv4_info.subnet.zero, .eq = true, .in = true, },
		{ &ipv6_info.subnet.zero, &ipv6_info.subnet.zero, .eq = true, .in = true, },
		/* all in all */
		{ &ipv4_info.subnet.all,  &ipv4_info.subnet.all,  .eq = true, .in = true, },
		{ &ipv6_info.subnet.all,  &ipv6_info.subnet.all,  .eq = true, .in = true, },
		/* none in all */
		{ &ipv4_info.subnet.zero,  &ipv4_info.subnet.all,             .in = true, },
		{ &ipv6_info.subnet.zero,  &ipv6_info.subnet.all,             .in = true, },
	};

	static const struct {
		const ip_subnet *l;
		const ip_address *r;
		int eq;
	} subnet_op_address[] = {
		{ &ipv4_info.subnet.zero, &ipv4_info.address.unspec, .eq = true, },
		{ &ipv6_info.subnet.zero, &ipv6_info.address.unspec, .eq = true, },
	};

	static const struct {
		const ip_address *l;
		const ip_subnet *r;
		int in;
	} address_op_subnet[] = {
		{ &ipv4_info.address.unspec,   &ipv4_info.subnet.zero, .in = true, },
		{ &ipv6_info.address.unspec,   &ipv6_info.subnet.zero, .in = true, },
		{ &ipv4_info.address.unspec,   &ipv4_info.subnet.all, .in = true, },
		{ &ipv6_info.address.unspec,   &ipv6_info.subnet.all, .in = true, },
		{ &ipv4_info.address.loopback, &ipv4_info.subnet.all, .in = true, },
		{ &ipv6_info.address.loopback, &ipv6_info.subnet.all, .in = true, },
	};

	CHECK_OP(address, in, subnet);
	CHECK_OP(subnet, in, subnet);

	CHECK_OP(subnet, eq, address);
	CHECK_OP(subnet, eq, subnet);
}

static void check_ip_info_range(void)
{
	for (size_t ti = 0; ti < elemsof(range_tests); ti++) {
		const struct range_test *t = &range_tests[ti];
		PRINT("%s", pri_afi(t->afi));

		const ip_range *range = t->range;

		CHECK_INFO(range);
		CHECK_STR2(range);
		CHECK_COND(range, is_unset);
		CHECK_COND2(range, is_zero);
		CHECK_COND2(range, is_all);
		CHECK_UNOP(range, size, "%ju", );

		CHECK_FROM(selector, range);
	}

	static const struct {
		const ip_range *l;
		const ip_address *r;
		bool eq;
	} range_op_address[] = {
		{ &unset_range, &unset_address, .eq = true, },
		{ &ipv4_info.range.zero, &ipv4_info.address.unspec, .eq = true, },
		{ &ipv6_info.range.zero, &ipv6_info.address.unspec, .eq = true, },
	};

	static const struct {
		const ip_range *l;
		const ip_subnet *r;
		bool eq;
	} range_op_subnet[] = {
		{ &unset_range, &unset_subnet, .eq = true, },
		{ &ipv4_info.range.all, &ipv4_info.subnet.all, .eq = true, },
		{ &ipv6_info.range.all, &ipv6_info.subnet.all, .eq = true, },
		/* clearly subnet isn't "none" */
		{ &ipv4_info.range.zero, &ipv4_info.subnet.zero, .eq = true, },
		{ &ipv6_info.range.zero, &ipv6_info.subnet.zero, .eq = true, },
	};

	static const struct {
		const ip_range *l;
		const ip_range *r;
		bool eq;
		bool in;
		bool overlaps;
	} range_op_range[] = {
		{ &unset_range,                &unset_range,          .eq = true, },
		{ &ipv4_info.range.zero,       &ipv4_info.range.zero, .eq = true, .in = true, .overlaps = true, },
		{ &ipv6_info.range.zero,       &ipv6_info.range.zero, .eq = true, .in = true, .overlaps = true, },
		{ &ipv4_info.range.zero,       &ipv4_info.range.all,  .in = true, .overlaps = true, },
		{ &ipv6_info.range.zero,       &ipv6_info.range.all,  .in = true, .overlaps = true, },
		{ &ipv4_info.range.all,        &ipv4_info.range.zero, .overlaps = true, },
		{ &ipv6_info.range.all,        &ipv6_info.range.zero, .overlaps = true, },
		{ &ipv4_info.range.all,        &ipv4_info.range.all,  .eq = true, .in = true, .overlaps = true, },
		{ &ipv6_info.range.all,        &ipv6_info.range.all,  .eq = true, .in = true, .overlaps = true, },
	};

	static const struct {
		const ip_subnet *l;
		const ip_range *r;
		bool in;
	} subnet_op_range[] = {
		{ &ipv4_info.subnet.zero, &ipv4_info.range.zero, .in = true, },
		{ &ipv6_info.subnet.zero, &ipv6_info.range.zero, .in = true, },
		{ &ipv4_info.subnet.zero, &ipv4_info.range.all, .in = true, },
		{ &ipv6_info.subnet.zero, &ipv6_info.range.all, .in = true, },
		{ &ipv4_info.subnet.all,  &ipv4_info.range.all, .in = true, },
		{ &ipv6_info.subnet.all,  &ipv6_info.range.all, .in = true, },
	};

	static const struct {
		const ip_address *l;
		const ip_range *r;
		bool in;
	} address_op_range[] = {
		{ &ipv4_info.address.unspec, &ipv4_info.range.all, .in = true, },
		{ &ipv6_info.address.unspec, &ipv6_info.range.all, .in = true, },
		{ &ipv4_info.address.unspec, &ipv4_info.range.zero, .in = true, },
		{ &ipv6_info.address.unspec, &ipv6_info.range.zero, .in = true, },
		{ &ipv4_info.address.loopback, &ipv4_info.range.all, .in = true, },
		{ &ipv6_info.address.loopback, &ipv6_info.range.all, .in = true, },
	};

	CHECK_OP(range, eq, address);
	CHECK_OP(range, eq, subnet);
	CHECK_OP(range, eq, range);

	CHECK_OP(address, in, range);
	CHECK_OP(subnet, in, range);
	CHECK_OP(range, in, range);
	CHECK_OP(range, overlaps, range);
}

static void check_ip_info_selector(void)
{
	for (size_t ti = 0; ti < elemsof(selector_tests); ti++) {
		const struct selector_test *t = &selector_tests[ti];
		PRINT("%s", pri_afi(t->afi));

		const ip_selector *selector = t->selector;

		CHECK_INFO(selector);
		CHECK_STR2(selector);

		CHECK_COND(selector, is_unset);
		CHECK_COND2(selector, is_zero);
		CHECK_COND2(selector, is_all);
		CHECK_COND2(selector, is_address);
		CHECK_COND2(selector, is_subnet);
	}

	static const struct {
		const ip_selector *l;
		const ip_selector *r;
		int eq;
		int in;
		int overlaps;
	} selector_op_selector[] = {
		{ &unset_selector,             &unset_selector,          .eq = true, },
		{ &ipv4_info.selector.zero,    &ipv4_info.selector.zero, .eq = true, .in = true, .overlaps = true, },
		{ &ipv6_info.selector.zero,    &ipv6_info.selector.zero, .eq = true, .in = true, .overlaps = true, },
		{ &ipv4_info.selector.zero,    &ipv4_info.selector.all,  .in = true, .overlaps = true, },
		{ &ipv6_info.selector.zero,    &ipv6_info.selector.all,  .in = true, .overlaps = true, },
		{ &ipv4_info.selector.all,     &ipv4_info.selector.zero, .overlaps = true, },
		{ &ipv6_info.selector.all,     &ipv6_info.selector.zero, .overlaps = true, },
		{ &ipv4_info.selector.all,     &ipv4_info.selector.all,  .eq = true, .in = true, .overlaps = true, },
		{ &ipv6_info.selector.all,     &ipv6_info.selector.all,  .eq = true, .in = true, .overlaps = true, },
	};

	static const struct {
		const ip_selector *l;
		const ip_address *r;
		int eq;
	} selector_op_address[] = {
		{ &unset_selector, &unset_address, .eq = true, },
		{ &ipv4_info.selector.zero, &ipv4_info.address.unspec, .eq = true, },
		{ &ipv6_info.selector.zero, &ipv6_info.address.unspec, .eq = true, },
	};

	static const struct {
		const ip_selector *l;
		const ip_subnet *r;
		int eq;
	} selector_op_subnet[] = {
		{ &unset_selector, &unset_subnet, .eq = true, },
		{ &ipv4_info.selector.zero, &ipv4_info.subnet.zero, .eq = true, },
		{ &ipv6_info.selector.zero, &ipv6_info.subnet.zero, .eq = true, },
		{ &ipv4_info.selector.all, &ipv4_info.subnet.all, .eq = true, },
		{ &ipv6_info.selector.all, &ipv6_info.subnet.all, .eq = true, },
	};

	static const struct {
		const ip_selector *l;
		const ip_endpoint *r;
		int eq;
	} selector_op_endpoint[] = {
		{ &unset_selector, &unset_endpoint, .eq = true, },
	};

	static const struct {
		const ip_endpoint *l;
		const ip_selector *r;
		int in;
	} endpoint_op_selector[1];
	static const struct {
		const ip_subnet *l;
		const ip_selector *r;
		int in;
	} subnet_op_selector[] = {
		{ &ipv4_info.subnet.zero, &ipv4_info.selector.zero, .in = true, },
		{ &ipv6_info.subnet.zero, &ipv6_info.selector.zero, .in = true, },
		{ &ipv4_info.subnet.zero, &ipv4_info.selector.all, .in = true, },
		{ &ipv6_info.subnet.zero, &ipv6_info.selector.all, .in = true, },
		{ &ipv4_info.subnet.all, &ipv4_info.selector.all, .in = true, },
		{ &ipv6_info.subnet.all, &ipv6_info.selector.all, .in = true, },
	};

	static const struct {
		const ip_address *l;
		const ip_selector *r;
		int in;
	} address_op_selector[] = {
		{ &ipv4_info.address.unspec, &ipv4_info.selector.zero, .in = true, },
		{ &ipv6_info.address.unspec, &ipv6_info.selector.zero, .in = true, },
		{ &ipv4_info.address.unspec, &ipv4_info.selector.all, .in = true, },
		{ &ipv6_info.address.unspec, &ipv6_info.selector.all, .in = true, },
		{ &ipv4_info.address.loopback, &ipv4_info.selector.all, .in = true, },
		{ &ipv6_info.address.loopback, &ipv6_info.selector.all, .in = true, },
	};

	static const struct {
		const ip_range *l;
		const ip_selector *r;
		int in;
	} range_op_selector[] = {
		{ &ipv4_info.range.zero, &ipv4_info.selector.zero, .in = true, },
		{ &ipv6_info.range.zero, &ipv6_info.selector.zero, .in = true, },
		{ &ipv4_info.range.zero, &ipv4_info.selector.all, .in = true, },
		{ &ipv6_info.range.zero, &ipv6_info.selector.all, .in = true, },
		{ &ipv4_info.range.all, &ipv4_info.selector.all, .in = true, },
		{ &ipv6_info.range.all, &ipv6_info.selector.all, .in = true, },
	};

	static const struct {
		const ip_selector *l;
		const ip_range *r;
		int eq;
	} selector_op_range[] = {
		{ &unset_selector, &unset_range, .eq = true, },
		{ &ipv4_info.selector.zero, &ipv4_info.range.zero, .eq = true, },
		{ &ipv6_info.selector.zero, &ipv6_info.range.zero, .eq = true, },
		{ &ipv4_info.selector.all, &ipv4_info.range.all, .eq = true, },
		{ &ipv6_info.selector.all, &ipv6_info.range.all, .eq = true, },
	};

	CHECK_OP(address, in, selector);
	CHECK_OP(endpoint, in, selector);
	CHECK_OP(subnet, in, selector);
	CHECK_OP(range, in, selector);
	CHECK_OP(selector, in, selector);

	CHECK_OP(selector, eq, address);
	CHECK_OP(selector, eq, endpoint);
	CHECK_OP(selector, eq, subnet);
	CHECK_OP(selector, eq, range);
	CHECK_OP(selector, eq, selector);

	CHECK_OP(selector, overlaps, selector);
}

void ip_info_check(void)
{
	check_ip_info_address();
	check_ip_info_endpoint();
	check_ip_info_subnet();
	check_ip_info_range();
	check_ip_info_selector();
}
