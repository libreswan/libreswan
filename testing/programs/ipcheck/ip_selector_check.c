/* test selectors, for libreswan
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
	uint16_t hport;
	uint8_t nport[2];
};

static void check_selector_from(const struct from_test *tests, unsigned nr_tests,
				const char *what,
				err_t (*to_selector)(const struct selector *from,
						     ip_selector *out, struct logger *logger),
				struct logger *logger)
{
#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s %s=%s protoport=%s range=%s ipproto=%u hport=%u nport=%02x%02x"FMT, \
	      pri_family(t->from.family), what,				\
	      t->from.addresses != NULL ? t->from.addresses : "N/A",	\
	      t->from.protoport != NULL ? t->from.protoport : "N/A",	\
	      t->range != NULL ? t->range : "N/A",			\
	      t->ipproto,						\
	      t->hport,							\
	      t->nport[0], t->nport[1],					\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < nr_tests; ti++) {
		const struct from_test *t = &tests[ti];
		OUT(stdout, "");

		ip_selector selector;
		err_t err = to_selector(&t->from, &selector, logger);
		if (t->range != NULL) {
			if (err != NULL) {
				FAIL(OUT, "to_selector() failed: %s", err);
			}
		} else if (err == NULL) {
			FAIL(OUT, "to_selector() should have failed");
		} else {
			continue;
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

		ip_port port = selector_port(&selector);

		uint16_t hp = hport(port);
		if (!memeq(&hp, &t->hport, sizeof(hport))) {
			FAIL(OUT, "selector_hport() returned '%d', expected '%d'",
			     hp, t->hport);
		}

		uint16_t np = nport(port);
		if (!memeq(&np, &t->nport, sizeof(nport))) {
			FAIL(OUT, "selector_nport() returned '%04x', expected '%02x%02x'",
			     np, t->nport[0], t->nport[1]);
		}
	}
#undef OUT
}

static err_t do_selector_from_address(const struct selector *s,
				      ip_selector *selector,
				      struct logger *logger_unused UNUSED)
{
	if (s->family == 0) {
		*selector = unset_selector;
		return NULL;
	}

	ip_address address;
	err_t err = numeric_to_address(shunk1(s->addresses), IP_TYPE(s->family), &address);
	if (err != NULL) {
		return err;
	}

	ip_protoport protoport;
	err = ttoprotoport(s->protoport, &protoport);
	if (err != NULL) {
		return err;
	}

	*selector = selector_from_address_protoport(&address, &protoport);
	return NULL;
}

static void check_selector_from_address(struct logger *logger)
{
	static const struct from_test tests[] = {
		{ { 4, "128.0.0.0", "0/0", }, "128.0.0.0-128.0.0.0", 0, 0, { 0, 0, }, },
		{ { 6, "8000::", "16/10", }, "8000::-8000::", 16, 10, { 0, 10, }, },
	};
	check_selector_from(tests, elemsof(tests), "address",
			    do_selector_from_address, logger);
}

static err_t do_selector_from_subnet_protoport(const struct selector *s,
					       ip_selector *selector,
					       struct logger *logger)
{
	if (s->family == 0) {
		*selector = unset_selector;
		return NULL;
	}

	ip_subnet subnet;
	err_t err = ttosubnet(shunk1(s->addresses), IP_TYPE(s->family), '6',
			      &subnet, logger);
	if (err != NULL) {
		return err;
	}

	ip_protoport protoport;
	err = ttoprotoport(s->protoport, &protoport);
	if (err != NULL) {
		return err;
	}

	*selector = selector_from_subnet_protoport(&subnet, &protoport);
	return NULL;
}

static void check_selector_from_subnet_protoport(struct logger *logger)
{
	static const struct from_test tests[] = {
		/* zero port implied */
		{ { 4, "0.0.0.0/0", "0/0", }, "0.0.0.0-255.255.255.255", 0, 0, { 0, 0, }, },
		{ { 6, "::0/0", "0/0", }, "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0, 0, { 0, 0, }, },
		{ { 4, "101.102.0.0/16", "0/0", }, "101.102.0.0-101.102.255.255", 0, 0, { 0, 0, }, },
		{ { 6, "1001:1002:1003:1004::/64", "0/0", }, "1001:1002:1003:1004::-1001:1002:1003:1004:ffff:ffff:ffff:ffff", 0, 0, { 0, 0, }, },
		{ { 4, "101.102.103.104/32", "0/0", }, "101.102.103.104-101.102.103.104", 0, 0, { 0, 0, }, },
		{ { 6, "1001:1002:1003:1004:1005:1006:1007:1008/128", "0/0", }, "1001:1002:1003:1004:1005:1006:1007:1008-1001:1002:1003:1004:1005:1006:1007:1008", 0, 0, { 0, 0, }, },
		/* "reserved" zero port specified; reject? */
		{ { 4, "0.0.0.0/0", "0/0", }, "0.0.0.0-255.255.255.255", 0, 0, { 0, 0, }, },
		{ { 6, "::0/0", "0/0", }, "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0, 0, { 0, 0, }, },
		{ { 4, "101.102.0.0/16", "0/0", }, "101.102.0.0-101.102.255.255", 0, 0, { 0, 0, }, },
		{ { 6, "1001:1002:1003:1004::/64", "0/0", }, "1001:1002:1003:1004::-1001:1002:1003:1004:ffff:ffff:ffff:ffff", 0, 0, { 0, 0, }, },
		{ { 4, "101.102.103.104/32", "0/0", }, "101.102.103.104-101.102.103.104", 0, 0, { 0, 0, }, },
		{ { 6, "1001:1002:1003:1004:1005:1006:1007:1008/128", "0/0", }, "1001:1002:1003:1004:1005:1006:1007:1008-1001:1002:1003:1004:1005:1006:1007:1008", 0, 0, { 0, 0, }, },
		/* non-zero port mixed with mask; only allow when /32/128? */
		{ { 4, "0.0.0.0/0", "16/65534", }, "0.0.0.0-255.255.255.255", 16, 65534, { 255, 254, }, },
		{ { 6, "::0/0", "16/65534", }, "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 16, 65534, { 255, 254, }, },
		{ { 4, "101.102.0.0/16", "16/65534", }, "101.102.0.0-101.102.255.255", 16, 65534, { 255, 254, }, },
		{ { 6, "1001:1002:1003:1004::/64", "16/65534", }, "1001:1002:1003:1004::-1001:1002:1003:1004:ffff:ffff:ffff:ffff", 16, 65534, { 255, 254, }, },
		{ { 4, "101.102.103.104/32", "16/65534", }, "101.102.103.104-101.102.103.104", 16, 65534, { 255, 254, }, },
		{ { 6, "1001:1002:1003:1004:1005:1006:1007:1008/128", "16/65534", }, "1001:1002:1003:1004:1005:1006:1007:1008-1001:1002:1003:1004:1005:1006:1007:1008", 16, 65534, { 255, 254, }, },
	};
	check_selector_from(tests, elemsof(tests), "subnet",
			    do_selector_from_subnet_protoport, logger);
}

static err_t do_range_to_selector(const struct selector *s,
				  ip_selector *selector,
				  struct logger *logger UNUSED)
{
	if (s->family == 0) {
		*selector = unset_selector;
		return NULL;
	}

	ip_range range;
	err_t err = ttorange(s->addresses, IP_TYPE(s->family), &range);
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

static void check_range_to_selector(struct logger *logger)
{
	static const struct from_test tests[] = {
		{ { 4, "128.0.0.0-128.0.0.0", "0/0", }, "128.0.0.0-128.0.0.0", 0, 0, { 0, 0, }, },
		{ { 4, "128.0.0.0-128.0.0.1", "0/0", }, "128.0.0.0-128.0.0.1", 0,0, { 0, 0, }, },
		{ { 6, "8000::-8000::1", "16/10", }, "8000::-8000::1", 16, 10, { 0, 10, }, },
	};
	check_selector_from(tests, elemsof(tests), "range",
			    do_range_to_selector, logger);
}

static err_t do_numeric_to_selector(const struct selector *s,
				    ip_selector *selector,
				    struct logger *logger_ UNUSED)
{
	if (s->family == 0) {
		*selector = unset_selector;
		return NULL;
	}

	return numeric_to_selector(shunk1(s->addresses), IP_TYPE(s->family), selector);
}

static void check_numeric_to_selector(struct logger *logger)
{
	static const struct from_test tests[] = {
		/* zero port implied */
		{ { 4, "0.0.0.0/0", NULL, }, "0.0.0.0-255.255.255.255", 0, 0, { 0, 0, }, },
		{ { 6, "::0/0", NULL, }, "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0, 0, { 0, 0, }, },
		{ { 4, "101.102.0.0/16", NULL, }, "101.102.0.0-101.102.255.255", 0, 0, { 0, 0, }, },
		{ { 6, "1001:1002:1003:1004::/64", NULL, }, "1001:1002:1003:1004::-1001:1002:1003:1004:ffff:ffff:ffff:ffff", 0, 0, { 0, 0, }, },
		{ { 4, "101.102.103.104/32", NULL, }, "101.102.103.104-101.102.103.104", 0, 0, { 0, 0, }, },
		{ { 6, "1001:1002:1003:1004:1005:1006:1007:1008/128", NULL, }, "1001:1002:1003:1004:1005:1006:1007:1008-1001:1002:1003:1004:1005:1006:1007:1008", 0, 0, { 0, 0, }, },
		/* "reserved" zero port specified; reject? */
		{ { 4, "0.0.0.0/0:0", NULL, }, "0.0.0.0-255.255.255.255", 0, 0, { 0, 0, }, },
		{ { 6, "::0/0:0", NULL, }, "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0, 0, { 0, 0, }, },
		{ { 4, "101.102.0.0/16:0", NULL, }, "101.102.0.0-101.102.255.255", 0, 0, { 0, 0, }, },
		{ { 6, "1001:1002:1003:1004::/64:0", NULL, }, "1001:1002:1003:1004::-1001:1002:1003:1004:ffff:ffff:ffff:ffff", 0, 0, { 0, 0, }, },
		{ { 4, "101.102.103.104/32:0", NULL, }, "101.102.103.104-101.102.103.104", 0, 0, { 0, 0, }, },
		{ { 6, "1001:1002:1003:1004:1005:1006:1007:1008/128:0", NULL, }, "1001:1002:1003:1004:1005:1006:1007:1008-1001:1002:1003:1004:1005:1006:1007:1008", 0, 0, { 0, 0, }, },
		/* non-zero port mixed with mask; only allow when /32/128? */
		{ { 4, "0.0.0.0/0:65534", NULL, }, "0.0.0.0-255.255.255.255", 0, 65534, { 255, 254, }, },
		{ { 6, "::0/0:65534", NULL, }, "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0, 65534, { 255, 254, }, },
		{ { 4, "101.102.0.0/16:65534", NULL, }, "101.102.0.0-101.102.255.255", 0, 65534, { 255, 254, }, },
		{ { 6, "1001:1002:1003:1004::/64:65534", NULL, }, "1001:1002:1003:1004::-1001:1002:1003:1004:ffff:ffff:ffff:ffff", 0, 65534, { 255, 254, }, },
		{ { 4, "101.102.103.104/32:65534", NULL, }, "101.102.103.104-101.102.103.104", 0, 65534, { 255, 254, }, },
		{ { 6, "1001:1002:1003:1004:1005:1006:1007:1008/128:65534", NULL, }, "1001:1002:1003:1004:1005:1006:1007:1008-1001:1002:1003:1004:1005:1006:1007:1008", 0, 65534, { 255, 254, }, },
		/* hex/octal */
		{ { 4, "101.102.0.0/16:0xfffe", NULL, }, "101.102.0.0-101.102.255.255", 0, 65534, { 255, 254, }, },
		{ { 6, "1001:1002:1003:1004::/64:0177776", NULL, }, "1001:1002:1003:1004::-1001:1002:1003:1004:ffff:ffff:ffff:ffff", 0, 65534, { 255, 254, }, },
		/* invalid */
		{ { 4, "1.2.3.0/24:-1", NULL, }, NULL, 0, 0, { 0, 0, }, },
		{ { 4, "1.2.3.0/24:none", NULL, }, NULL, 0, 0, { 0, 0, }, },
		{ { 4, "1.2.3.0/24:", NULL, }, NULL, 0, 0, { 0, 0, }, },
	};

	check_selector_from(tests, elemsof(tests), "subnet-port",
			    do_numeric_to_selector, logger);
}

static void check_selector_contains(struct logger *logger)
{
	static const struct test {
		struct selector from;
		bool is_unset;
		bool contains_all_addresses;
		bool contains_some_addresses;
		bool contains_one_address;
		bool contains_no_addresses;
	} tests[] = {
		/* all */
		{ { 0, NULL, NULL, },            true, false, false, false, false, },
		/* all */
		{ { 4, "0.0.0.0/0", "0/0", },    false, true, false, false, false, },
		{ { 6, "::/0", "0/0", },         false, true, false, false, false, },
		/* some */
		{ { 4, "127.0.0.0/31", "0/0", }, false, false, true, false, false, },
		{ { 6, "8000::/127", "0/0", },   false, false, true, false, false, },
		/* one */
		{ { 4, "127.0.0.1/32", "0/0", }, false, false, true, true, false, },
		{ { 6, "8000::/128", "0/0", },   false, false, true, true, false, },
		/* none */
		{ { 4, "0.0.0.0/32", "0/0", },   false, false, false, false, true, },
		{ { 6, "::/128", "0/0", },       false, false, false, false, true, },
	};

#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "%s subnet=%s protoport=%s unset=%s all=%s some=%s one=%s none=%s"FMT, \
	      pri_family(t->from.family), \
	      t->from.addresses != NULL ? t->from.addresses : "<unset>", \
	      t->from.protoport != NULL ? t->from.protoport : "<unset>", \
	      bool_str(t->is_unset),					\
	      bool_str(t->contains_all_addresses),			\
	      bool_str(t->contains_some_addresses),			\
	      bool_str(t->contains_one_address),			\
	      bool_str(t->contains_no_addresses),			\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		err_t err;
		const struct test *t = &tests[ti];
		OUT(stdout, "");

		ip_selector selector;
		err = do_numeric_to_selector(&t->from, &selector, logger);
		if (err != NULL) {
			FAIL(OUT, "to_selector() failed: %s", err);
		}

#define T(COND)								\
		bool COND = selector_##COND(&selector);			\
		if (COND != t->COND) {					\
			FAIL(OUT, "selector_"#COND"() returned %s, expected %s", \
			     bool_str(COND), bool_str(t->COND));	\
		}
		T(is_unset);
		T(contains_all_addresses);
		T(contains_one_address);
		T(contains_no_addresses);
	}
#undef OUT
}

static void check_in_selector(struct logger *logger)
{

	static const struct test {
		struct selector inner;
		struct selector outer;
		bool selector;
		bool address;
		bool endpoint;
	} tests[] = {

		/* all */

		{ { 4, "0.0.0.0/0", "0/0", }, { 4, "0.0.0.0/0", "0/0", },             true, true, true, },
		{ { 6, "::/0", "0/0", },      { 6, "::/0", "0/0", },                  true, true, true, },

		{ { 4, "0.0.0.0/0", "0/0", }, { 4, "0.0.0.0/0", "udp/10", },          false, true, false, },
		{ { 6, "::/0", "0/0", },      { 6, "::/0", "udp/10", },               false, true, false, },

		{ { 4, "0.0.0.0/0", "udp/10", }, { 4, "0.0.0.0/0", "0/0", },          true, true, true, },
		{ { 6, "::/0", "udp/10", },      { 6, "::/0", "0/0", },               true, true, true, },

		{ { 4, "0.0.0.0/0", "udp/10", }, { 4, "0.0.0.0/0", "udp/10", },       true, true, true, },
		{ { 6, "::/0", "udp/10", },      { 6, "::/0", "udp/10", },            true, true, true, },

		{ { 4, "0.0.0.0/0", "udp/10", }, { 4, "0.0.0.0/0", "udp/11", },       false, true, false, },
		{ { 6, "::/0", "udp/10", },      { 6, "::/0", "udp/11", },            false, true, false, },

		{ { 4, "0.0.0.0/0", "udp/10", }, { 4, "0.0.0.0/0", "tcp/10", },       false, true, false, },
		{ { 6, "::/0", "udp/10", },      { 6, "::/0", "tcp/10", },            false, true, false, },

		/* some */

		{ { 4, "127.0.0.1/32", "0/0", }, { 4, "127.0.0.0/31", "0/0", },       true,true, true, },
		{ { 6, "8000::/128", "0/0", },   { 6, "8000::/127", "0/0", },         true, true, true, },

		{ { 4, "127.0.0.1/32", "0/0", }, { 4, "127.0.0.0/31", "tcp/10", },    false, true, false, },
		{ { 6, "8000::/128", "0/0", },   { 6, "8000::/127", "tcp/10", },      false, true, false, },

		{ { 4, "127.0.0.1/32", "tcp/10", }, { 4, "127.0.0.0/31", "0/0", },    true, true, true, },
		{ { 6, "8000::/128", "tcp/10", },   { 6, "8000::/127", "0/0", },      true, true, true, },

		{ { 4, "127.0.0.1/32", "tcp/10", }, { 4, "127.0.0.0/31", "tcp/10", }, true, true, true, },
		{ { 6, "8000::/128", "tcp/10", },   { 6, "8000::/127", "tcp/10", },   true, true, true, },

		{ { 4, "127.0.0.1/32", "tcp/10", }, { 4, "127.0.0.0/31", "tcp/11", }, false, true, false, },
		{ { 6, "8000::/128", "tcp/10", },   { 6, "8000::/127", "tcp/11", },   false, true, false, },

		{ { 4, "127.0.0.1/32", "tcp/10", }, { 4, "127.0.0.0/31", "udp/10", }, false, true, false, },
		{ { 6, "8000::/128", "tcp/10", },   { 6, "8000::/127", "udp/10", },   false, true, false, },

		/* one */

		{ { 4, "127.0.0.1/32", "0/0", }, { 4, "127.0.0.1/32", "0/0", },       true, true, true, },
		{ { 6, "8000::/128", "0/0", },   { 6, "8000::/128", "0/0", },         true, true, true, },

		{ { 4, "127.0.0.1/32", "0/0", }, { 4, "127.0.0.1/32", "udp/10", },    false, true, false, },
		{ { 6, "8000::/128", "0/0", },   { 6, "8000::/128", "udp/10", },      false, true, false, },

		{ { 4, "127.0.0.1/32", "udp/10", }, { 4, "127.0.0.1/32", "0/0", },    true, true, true, },
		{ { 6, "8000::/128", "udp/10", },   { 6, "8000::/128", "0/0", },      true, true, true, },

		{ { 4, "127.0.0.1/32", "udp/10", }, { 4, "127.0.0.1/32", "udp/10", }, true, true, true, },
		{ { 6, "8000::/128", "udp/10", },   { 6, "8000::/128", "udp/10", },   true, true, true, },

		{ { 4, "127.0.0.1/32", "udp/10", }, { 4, "127.0.0.1/32", "udp/11", }, false, true, false, },
		{ { 6, "8000::/128", "udp/10", },   { 6, "8000::/128", "udp/11", },   false, true, false, },

		{ { 4, "127.0.0.1/32", "udp/10", }, { 4, "127.0.0.1/32", "tcp/10", }, false, true, false, },
		{ { 6, "8000::/128", "udp/10", },   { 6, "8000::/128", "tcp/10", },   false, true, false, },

		/* none - so nothing can match */

		{ { 4, "127.0.0.0/32", "0/0", }, { 4, "0.0.0.0/32", "0/0", },         false, false, false, },
		{ { 6, "::1/128", "0/0", },      { 6, "::/128", "0/0", },             false, false, false, },

		{ { 4, "127.0.0.0/32", "udp/10", }, { 4, "0.0.0.0/32", "0/0", },      false, false, false, },
		{ { 6, "::1/128", "udp/10", },      { 6, "::/128", "0/0", },          false, false, false, },

		{ { 4, "0.0.0.0/32", "0/0", }, { 4, "0.0.0.0/32", "0/0", },           false, false, false, },
		{ { 6, "::/128", "0/0", },      { 6, "::/128", "0/0", },              false, false, false, },

		{ { 4, "0.0.0.0/32", "udp/10", }, { 4, "0.0.0.0/32", "0/0", },        false, false, false, },
		{ { 6, "::/128", "udp/10", },      { 6, "::/128", "0/0", },           false, false, false, },

		/* these a non-sensical - rhs has no addresses yet udp */

		{ { 4, "127.0.0.0/32", "0/0", }, { 4, "0.0.0.0/32", "udp/10", },      false, false, false, },
		{ { 6, "::1/128", "0/0", },      { 6, "::/128", "udp/10", },          false, false, false, },

		{ { 4, "127.0.0.0/32", "udp/10", }, { 4, "0.0.0.0/32", "udp/10", },   false, false, false, },
		{ { 6, "::1/128", "udp/10", },      { 6, "::/128", "udp/10", },       false, false, false, },

		/* these a non-sensical - rhs has zero addresses */

		{ { 4, "127.0.0.0/32", "0/0", }, { 4, "0.0.0.0/31", "0/0", },         false, false, false, },
		{ { 6, "::1/128", "0/0", },      { 6, "::/127", "0/0", },             false, false, false, },

		{ { 4, "127.0.0.0/32", "udp/10", }, { 4, "0.0.0.0/31", "udp/10", },   false, false, false, },
		{ { 6, "::1/128", "udp/10", },      { 6, "::/127", "udp/10", },       false, false, false, },

	};
#define OUT(FILE, FMT, ...)						\
	PRINT(FILE, "{ %s subnet=%s protoport=%s } in { %s subnet=%s protoport=%s } selector=%s address=%s endpoint=%s"FMT, \
	      pri_family(t->inner.family), t->inner.addresses, t->inner.protoport, \
	      pri_family(t->outer.family), t->outer.addresses, t->outer.protoport, \
	      bool_str(t->selector),					\
	      bool_str(t->address),					\
	      bool_str(t->endpoint),					\
	      ##__VA_ARGS__)

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		err_t err;
		const struct test *t = &tests[ti];
		OUT(stdout, "");

		ip_selector outer_selector;
		err = do_selector_from_subnet_protoport(&t->outer, &outer_selector, logger);
		if (err != NULL) {
			FAIL(OUT, "outer-selector failed: %s", err);
		}

		ip_selector inner_selector;
		err = do_selector_from_subnet_protoport(&t->inner, &inner_selector, logger);
		if (err != NULL) {
			FAIL(OUT, "inner-selector failed: %s", err);
		}
		bool selector = selector_in_selector(&inner_selector, &outer_selector);
		if (selector != t->selector) {
			FAIL(OUT, "selector_in_selector() returned %s, expecting %s",
			     bool_str(selector), bool_str(t->selector));
		}

		ip_address inner_address = selector_prefix(&inner_selector);
		bool address = address_in_selector(&inner_address, &outer_selector);
		if (address != t->address) {
			FAIL(OUT, "address_in_selector() returned %s, expecting %s",
			     bool_str(address), bool_str(t->address));
		}

		const ip_protocol *protocol = selector_protocol(&inner_selector);
		ip_port port = selector_port(&inner_selector);
		ip_endpoint inner_endpoint = endpoint_from_address_protocol_port(&inner_address, protocol, port);
		bool endpoint = endpoint_in_selector(&inner_endpoint, &outer_selector);
		if (endpoint != t->endpoint) {
			FAIL(OUT, "endpoint_in_selector() returned %s, expecting %s",
			     bool_str(endpoint), bool_str(t->endpoint));
		}
	}

#undef OUT
}

void ip_selector_check(struct logger *logger)
{
	check_selector_from_address(logger);
	check_selector_from_subnet_protoport(logger);
	check_range_to_selector(logger);
	check_selector_contains(logger);
	check_in_selector(logger);
	check_numeric_to_selector(logger);
}
