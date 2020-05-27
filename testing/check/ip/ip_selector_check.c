/* test subnets, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2018, 2019, 2020  Andrew Cagney
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
#include "ip_selector.h"	/* should be in ip_selector_check.c */

struct selector {
	int family;
	const char *addresses;
	const char *protoport;
};

struct from_test {
	struct selector from;
	const char *range;
	unsigned ipproto;
	unsigned hport;
};

static void check_selector_from(const struct from_test *tests, unsigned nr_tests,
				const char *what,
				err_t (*to_selector)(const struct selector *from,
						     ip_selector *out))
{
#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s %s=%s protoport=%s"FMT,				\
	      pri_family(t->from.family), what, t->from.addresses,	\
	      t->from.protoport,					\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < nr_tests; ti++) {
		const struct from_test *t = &tests[ti];
		OUT(stdout, "");

		ip_selector selector;
		err_t err = to_selector(&t->from, &selector);
		if (err != NULL) {
			FAIL(OUT, "to_selector() failed: %s", err);
		}

		CHECK_FAMILY(OUT, t->from.family, selector_type(&selector));

		ip_range range = selector_range(&selector);
		range_buf rb;
		str_range(&range, &rb);
		if (!streq(rb.buf, t->range)) {
			FAIL(OUT, "range was %s, expected %s", rb.buf, t->range);
		}

		unsigned ipproto = selector_ipproto(&selector);
		if (ipproto != t->ipproto) {
			FAIL(OUT, "ipproto was %u, expected %u", ipproto, t->ipproto);
		}

		unsigned hport = selector_hport(&selector);
		if (hport != t->hport) {
			FAIL(OUT, "hport was %u, expected %u", hport, t->hport);
		}
	}
#undef OUT
}

static err_t to_selector_address(const struct selector *s,
				 ip_selector *selector)
{
		err_t err;

		ip_address address;
		err = numeric_to_address(shunk1(s->addresses), IP_TYPE(s->family), &address);
		if (err != NULL) {
			return err;
		}

		ip_protoport protoport;
		err = ttoprotoport(s->protoport, &protoport);
		if (err != NULL) {
			return err;
		}

		*selector = selector_from_address(&address, &protoport);
		return NULL;
}

static void check_selector_from_address(void)
{
	static const struct from_test tests[] = {
		{ { 4, "128.0.0.0", "0/0", }, "128.0.0.0-128.0.0.0", 0,0, },
		{ { 6, "8000::", "16/10", }, "8000::-8000::", 16, 10, },
	};
	check_selector_from(tests, elemsof(tests), "address",
			    to_selector_address);
}

static err_t to_selector_subnet(const struct selector *s,
				ip_selector *selector)
{
		err_t err;

		ip_subnet subnet;
		err = ttosubnet(s->addresses, 0, SA_FAMILY(s->family), '6', &subnet);
		if (err != NULL) {
			return err;
		}

		ip_protoport protoport;
		err = ttoprotoport(s->protoport, &protoport);
		if (err != NULL) {
			return err;
		}

		*selector = selector_from_subnet(&subnet, &protoport);
		return NULL;
}

static void check_selector_from_subnet(void)
{
	static const struct from_test tests[] = {
		{ { 4, "128.0.0.0/32", "0/0", }, "128.0.0.0-128.0.0.0", 0,0, },
		{ { 6, "8000::/128", "16/10", }, "8000::-8000::", 16, 10, },

		{ { 4, "128.0.0.0/31", "0/0", }, "128.0.0.0-128.0.0.1", 0,0, },
		{ { 6, "8000::0/127", "16/10", }, "8000::-8000::1", 16, 10, },
	};
	check_selector_from(tests, elemsof(tests), "subnet",
			    to_selector_subnet);
}

static err_t to_selector_range(const struct selector *s,
			       ip_selector *selector)
{
		err_t err;

		ip_range range;
		err = ttorange(s->addresses, IP_TYPE(s->family), &range);
		if (err != NULL) {
			return err;
		}

		ip_protoport protoport;
		err = ttoprotoport(s->protoport, &protoport);
		if (err != NULL) {
			return err;
		}

		err = range_to_selector(&range, &protoport, selector);
		return err;
}

static void check_selector_from_range(void)
{
	static const struct from_test tests[] = {
		{ { 4, "128.0.0.0-128.0.0.0", "0/0", }, "128.0.0.0-128.0.0.0", 0,0, },
		{ { 4, "128.0.0.0-128.0.0.1", "0/0", }, "128.0.0.0-128.0.0.1", 0,0, },
		{ { 6, "8000::-8000::1", "16/10", }, "8000::-8000::1", 16, 10, },
	};
	check_selector_from(tests, elemsof(tests), "range",
			    to_selector_range);
}

static void check_selector_has(void)
{
	static const struct test {
		struct selector from;
		bool all;
		bool one;
		bool no;
	} tests[] = {
		/* all */
		{ { 4, "0.0.0.0/0", "0/0", }, true, false, false, },
		{ { 6, "::/0", "0/0", }, true, false, false, },
		/* one */
		{ { 4, "127.0.0.1/32", "0/0", }, false, true, false, },
		{ { 6, "8000::/128", "0/0", }, false, true, false, },
		/* no */
		{ { 4, "0.0.0.0/32", "0/0", }, false, false, true, },
		{ { 6, "::/128", "0/0", }, false, false, true, },
	};

#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s subnet=%s protoport=%s"FMT,			\
	      pri_family(t->from.family), t->from.addresses, t->from.protoport,	\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		err_t err;
		const struct test *t = &tests[ti];
		OUT(stdout, " -> all=%s one=%s no=%s",
		    bool_str(t->all), bool_str(t->one), bool_str(t->no));

		ip_selector selector;
		err = to_selector_subnet(&t->from, &selector);
		if (err != NULL) {
			FAIL(OUT, "to_selector() failed: %s", err);
		}

		bool all = selector_has_all_addresses(&selector);
		if (all != t->all) {
			FAIL(OUT, "all() returned %s, expected %s",
			     bool_str(all), bool_str(t->all));
		}

		bool one = selector_has_one_address(&selector);
		if (one != t->one) {
			FAIL(OUT, "one() returned %s, expected %s",
			     bool_str(one), bool_str(t->one));
		}

		bool no = selector_has_no_addresses(&selector);
		if (no != t->no) {
			FAIL(OUT, "no() returned %s, expected %s",
			     bool_str(no), bool_str(t->no));
		}

	}
#undef OUT
}

static void check_in_selector(void)
{

#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s subnet=%s protoport=%s in %s subnet=%s protoport=%s"FMT, \
	      pri_family(t->in.family), t->in.addresses, t->in.protoport, \
	      pri_family(t->from.family), t->from.addresses, t->from.protoport,	\
	      ##__VA_ARGS__)

	static const struct test {
		struct selector in;
		struct selector from;
		bool selector_in;
		bool start_in;
		bool end_in;
	} tests[] = {
		/* all */
		{ { 4, "0.0.0.0/0", "0/0", }, { 4, "0.0.0.0/0", "0/0", }, true, true, true, },
		{ { 6, "::/0", "0/0", },      { 6, "::/0", "0/0", }, true,true, true, },
		/* one */
		{ { 4, "127.0.0.1/32", "0/0", }, { 4, "127.0.0.1/32", "0/0", }, true,true, true, },
		{ { 6, "8000::/128", "0/0", },   { 6, "8000::/128", "0/0", }, true, true, true, },
		/* no? */
		{ { 4, "127.0.0.0/32", "0/0", }, { 4, "0.0.0.0/31", "0/0", }, false, false, false, },
		{ { 4, "127.0.0.0/32", "0/0", }, { 4, "0.0.0.0/32", "0/0", }, false, false, false, },
		{ { 6, "::1/128", "0/0", },      { 6, "::/128", "0/0", },     false, false, false, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		err_t err;
		const struct test *t = &tests[ti];

		ip_selector selector;
		err = to_selector_subnet(&t->from, &selector);
		if (err != NULL) {
			FAIL(OUT, "from-selector failed: %s", err);
		}

		ip_selector in;
		err = to_selector_subnet(&t->in, &in);
		if (err != NULL) {
			FAIL(OUT, "comp-selector failed: %s", err);
		}

		OUT(stdout, " selector_in=%s", bool_str(t->selector_in));
		bool selector_in = selector_in_selector(&in, &selector);
		if (selector_in != t->selector_in) {
			FAIL(OUT, "selector_in returned %s, expecting %s",
			     bool_str(selector_in), bool_str(t->selector_in));
		}

		ip_range range = selector_range(&in);

		OUT(stdout, " start_in=%s", bool_str(t->start_in));
		bool start_in = address_in_selector(&range.start, &selector);
		if (start_in != t->start_in) {
			FAIL(OUT, "address_in_selector(first) returned %s, expecting %s",
			     bool_str(start_in), bool_str(t->start_in));
		}

		OUT(stdout, " end_in=%s", bool_str(t->end_in));
		bool end_in = address_in_selector(&range.end, &selector);
		if (end_in != t->end_in) {
			FAIL(OUT, "address_in_selector(last) returned %s, expecting %s",
			     bool_str(end_in), bool_str(t->end_in));
		}

	}

#undef OUT
}

void ip_selector_check(void)
{
	check_selector_from_address();
	check_selector_from_subnet();
	check_selector_from_range();
	check_selector_has();
	check_in_selector();
}
