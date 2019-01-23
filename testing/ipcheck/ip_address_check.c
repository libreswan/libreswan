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

#include "stdio.h"

#include "constants.h"		/* for elemsof() */
#include "ip_address.h"

#include "ipcheck.h"

static void check_str_address_raw(void)
{
	struct test {
		const char *input;
		const char sep;
		const char *output;
	};
	static const struct test tests[] = {
		/* basic */
		{ "127.0.0.1", 0, "127.0.0.1", },
		{ "1:2::7:8", 0, "1:2:0:0:0:0:7:8", },
		/* different sepc */
		{ "127.0.0.1", '/', "127/0/0/1", },
		{ "1:2::7:8", '/', "1/2/0/0/0/0/7/8", },
		/* buffer overflow */
		{ "255.255.255.255", 0, "255.255.255.255", },
		{ "1111:2222:3333:4444:5555:6666:7777:8888", 0, "1111:2222:3333:4444:5555:6666:7777:8888", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		if (t->sep == 0) {
			IPRINT(stdout, "0 -> '%s'", t->output);
		} else {
			IPRINT(stdout, "'%c' -> '%s'", t->sep, t->output);
		}

		/* convert it *to* internal format */
		ip_address a;
		err_t err = ttoaddr(t->input, strlen(t->input), AF_UNSPEC, &a);
		if (err != NULL) {
			IFAIL("ttoaddr failed: %s", err);
			continue;
		}

		/* now convert it back */
		ip_address_buf buf;
		const char *out = str_address_raw(&a, t->sep, &buf);
		if (out == NULL) {
			IFAIL("failed");
		} else if (!strcaseeq(t->output, out)) {
			IFAIL("returned '%s', expected '%s'",
			      out, t->output);
		}
	}
}

static void check_str_address_cooked(void)
{
	struct test {
		const char *input;
		const char *output;
	};
	static const struct test tests[] = {
		/* anything else? */
		{ "1.2.3.4",			"1.2.3.4" },

		/* suppress leading zeros - 01 vs 1 */
		{ "1:12:3:14:5:16:7:18",	"1:12:3:14:5:16:7:18" },
		/* drop leading 0:0: */
		{ "0:0:3:4:5:6:7:8",		"::3:4:5:6:7:8" },
		/* drop middle 0:...:0 */
		{ "1:2:0:0:0:0:7:8",		"1:2::7:8" },
		/* drop trailing :0..:0 */
		{ "1:2:3:4:5:0:0:0",		"1:2:3:4:5::" },
		/* drop first 0:..:0 */
		{ "1:2:0:0:3:4:0:0",		"1:2::3:4:0:0" },
		/* drop logest 0:..:0 */
		{ "0:0:3:0:0:0:7:8",		"0:0:3::7:8" },
		/* need two 0 */
		{ "0:2:0:4:0:6:0:8",		"0:2:0:4:0:6:0:8" },
		/* edge cases */
		{ "0:0:0:0:0:0:0:1",		"::1" },
		{ "0:0:0:0:0:0:0:0",		"::" },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		IPRINT(stdout, "-> '%s'", t->output);

		/* convert it *to* internal format */
		ip_address a;
		err_t err = ttoaddr(t->input, strlen(t->input), AF_UNSPEC, &a);
		if (err != NULL) {
			IFAIL("%s", err);
			continue;
		}

		/* now convert it back */
		ip_address_buf buf;
		const char *out = str_address_cooked(&a, &buf);
		if (out == NULL) {
			IFAIL("failed");
		} else if (!strcaseeq(t->output, out)) {
			IFAIL("returned '%s', expected '%s'",
			      out, t->output);
		}
	}
}

static void check_str_address_sensitive(void)
{
	struct test {
		const char *input;
		const char *output;
	};
	static const struct test tests[] = {
		{ "1.2.3.4",			"<ip-address>" },
		{ "1:12:3:14:5:16:7:18",	"<ip-address>" },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		IPRINT(stdout, "-> '%s'", t->output);

		/* convert it *to* internal format */
		ip_address a;
		err_t err = ttoaddr(t->input, strlen(t->input), AF_UNSPEC, &a);
		if (err != NULL) {
			IFAIL("%s", err);
			continue;
		}

		/* now convert it back */
		ip_address_buf buf;
		const char *out = str_address_sensitive(&a, &buf);
		if (out == NULL) {
			IFAIL("failed");
		} else if (!strcaseeq(t->output, out)) {
			IFAIL("returned '%s', expected '%s'",
			      out, t->output);
		}
	}
}


/*
 * From addrtot.c
 */

#ifdef NOT_YET
int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s {addr|net/mask|begin...end|-r}\n",
			argv[0]);
		exit(2);
	}

	if (streq(argv[1], "-r")) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}
	exit(0);
}
#endif

static void check_str_address_reversed(void)
{
	struct test {
		const char *input;
		const char *output;                   /* NULL means error expected */
	};
	static const struct test tests[] = {

		{ "1.2.3.4", "4.3.2.1.IN-ADDR.ARPA." },
		/* 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f */
		{ "0123:4567:89ab:cdef:1234:5678:9abc:def0",
		  "0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.IP6.ARPA.", }
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		IPRINT(stdout, "-> '%s", t->output);

		/* convert it *to* internal format */
		ip_address a;
		err_t err = ttoaddr(t->input, strlen(t->input), AF_UNSPEC, &a);
		if (err != NULL) {
			IFAIL("%s", err);
			continue;
		}

		address_reversed_buf buf;
		const char *out = str_address_reversed(&a, &buf);
		if (!strcaseeq(t->output, out)) {
			IFAIL("str_address_reversed returned '%s', expected '%s'",
			      out, t->output);
		}
	}
}

/*
 * From ttoaddr.c
 */

#ifdef NOT_YET
int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s {addr|net/mask|begin...end|-r}\n",
			argv[0]);
		exit(2);
	}

	if (streq(argv[1], "-r")) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}
	exit(0);
}
#endif

static void check_ttoaddr_dns(void)
{
	struct test {
		const char *input;
		bool numonly;
		int af;
		bool expectfailure;
		const char *output;	/* NULL means error expected */
	};

	static const struct test tests[] = {
		{ "www.libreswan.org", false, 4, false, "188.127.201.229" },
		{ "www.libreswan.org", true, 0, true, "1.2.3.4" },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		IPRINT(stdout, "%s%s -> '%s",
		       t->numonly ? "" : " DNS",
		       t->expectfailure ? " fail" : "",
		       t->output);
		int af = (t->af == 0 ? AF_UNSPEC :
			  t->af == 4 ? AF_INET :
			  t->af == 6 ? AF_INET6 :
			  -1);

		ip_address a;
		memset(&a, 0, sizeof(a));

		if (t->numonly) {
			/* convert it *to* internal format (no DNS) */
			oops = ttoaddr_num(t->input, strlen(t->input), af, &a);
		} else {
			/* convert it *to* internal format */
			oops = ttoaddr(t->input, strlen(t->input), af, &a);
		}

		if (t->expectfailure && oops == NULL) {
			IFAIL("expected failure, but it succeeded");
			continue;
		}

		if (oops != NULL) {
			if (!t->expectfailure) {
				IFAIL("failed to parse: %s", oops);
			}
			continue;
		}

		/* now convert it back */
		ip_address_buf buf;
		const char *out = str_address_cooked(&a, &buf);
		if (!strcaseeq(t->output, out)) {
			IFAIL("addrtoc returned '%s', expected '%s'",
			      out, t->output);
		}
	}
}

void ip_address_check(void)
{
	check_str_address_raw();
	check_str_address_cooked();
	check_str_address_sensitive();
	check_str_address_reversed();
	check_ttoaddr_dns();
}
