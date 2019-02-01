/* ip range tests, for libreswan
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

#include "constants.h"		/* for elemsof() */
#include "ip_range.h"
#include "ip_subnet.h"
#include "ipcheck.h"

#ifdef NOT_YET
int main(int argc, char *argv[])
{
	ip_address start;
	ip_address stop;
	ip_subnet sub;
	char buf[100];
	const char *oops;
	size_t n;
	int af;
	int i;

	if (argc == 2 && streq(argv[1], "-r")) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-6] start stop\n", argv[0]);
		fprintf(stderr, "   or: %s -r\n", argv[0]);
		exit(2);
	}

	af = AF_INET;
	i = 1;
	if (streq(argv[i], "-6")) {
		af = AF_INET6;
		i++;
	}

	oops = ttoaddr(argv[i], 0, af, &start);
	if (oops != NULL) {
		fprintf(stderr, "%s: start conversion failed: %s\n", argv[0],
			oops);
		exit(1);
	}
	oops = ttoaddr(argv[i + 1], 0, af, &stop);
	if (oops != NULL) {
		fprintf(stderr, "%s: stop conversion failed: %s\n", argv[0],
			oops);
		exit(1);
	}
	oops = rangetosubnet(&start, &stop, &sub);
	if (oops != NULL) {
		fprintf(stderr, "%s: rangetosubnet failed: %s\n", argv[0],
			oops);
		exit(1);
	}
	n = subnettot(&sub, 0, buf, sizeof(buf));
	if (n > sizeof(buf)) {
		fprintf(stderr, "%s: reverse conversion", argv[0]);
		fprintf(stderr, " failed: need %zd bytes, have only %zd\n",
			n, sizeof(buf));
		exit(1);
	}
	printf("%s\n", buf);

	exit(0);
}
#endif

static void check_rangetosubnet(void)
{
	struct test {
		int family;
		const char *start;
		const char *stop;
		const char *output;	/* NULL means error expected */
	};
	static const struct test tests[] = {
		{ 4, "1.2.3.0", "1.2.3.255", "1.2.3.0/24" },
		{ 4, "1.2.3.0", "1.2.3.7", "1.2.3.0/29" },
		{ 4, "1.2.3.240", "1.2.3.255", "1.2.3.240/28" },
		{ 4, "0.0.0.0", "255.255.255.255", "0.0.0.0/0" },
		{ 4, "1.2.3.4", "1.2.3.4", "1.2.3.4/32" },
		{ 4, "1.2.3.0", "1.2.3.254", NULL },
		{ 4, "1.2.3.0", "1.2.3.126", NULL },
		{ 4, "1.2.3.0", "1.2.3.125", NULL },
		{ 4, "1.2.0.0", "1.2.255.255", "1.2.0.0/16" },
		{ 4, "1.2.0.0", "1.2.0.255", "1.2.0.0/24" },
		{ 4, "1.2.255.0", "1.2.255.255", "1.2.255.0/24" },
		{ 4, "1.2.255.0", "1.2.254.255", NULL },
		{ 4, "1.2.255.1", "1.2.255.255", NULL },
		{ 4, "1.2.0.1", "1.2.255.255", NULL },
		{ 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:ffff", "1:2:3:4:5:6:7:0/112" },
		{ 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:fff", "1:2:3:4:5:6:7:0/116" },
		{ 6, "1:2:3:4:5:6:7:f0", "1:2:3:4:5:6:7:ff", "1:2:3:4:5:6:7:f0/124" },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		if (t->output != NULL) {
			SSPRINT(stdout, "-> '%s'", t->output);
		} else {
			SSPRINT(stdout, "-> <error>");
		}
		int af = (t->family == 4) ? AF_INET : AF_INET6;
		const char *oops = NULL;

		ip_address start;
		oops = ttoaddr(t->start, 0, af, &start);
		if (oops != NULL) {
			SSFAIL("ttoaddr(start) failed: %s", oops);
			continue;
		}
		ip_address stop;
		oops = ttoaddr(t->stop, 0, af, &stop);
		if (oops != NULL) {
			SSFAIL("ttoaddr(stop) failed: %s", oops);
			continue;
		}
		ip_subnet sub;
		oops = rangetosubnet(&start, &stop, &sub);
		if (oops != NULL && t->output == NULL) {
			/* okay, error expected */
		} else if (oops != NULL) {
			SSFAIL("rangetosubnet failed: %s", oops);
			continue;
		} else if (t->output == NULL) {
			SSFAIL("rangetosubnet succeeded unexpectedly");
			continue;
		} else {
			ip_subnet_buf buf;
			const char *out = str_subnet(&sub, &buf);
			if (!streq(t->output, out)) {
				SSFAIL("gave `%s', expected `%s'",
				      out, t->output);
				continue;
			}
		}
	}
}

#ifdef NOT_YET
int main(int argc, char *argv[])
{
	ip_address high;
	ip_address low;
	char bh[100], bl[100];
	const char *oops;
	int n;
	int af;
	int i;

	if (argc == 2 && streq(argv[1], "-r")) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-6] high low\n", argv[0]);
		fprintf(stderr, "   or: %s -r\n", argv[0]);
		exit(2);
	}

	af = AF_INET;
	i = 1;
	if (streq(argv[i], "-6")) {
		af = AF_INET6;
		i++;
	}

	oops = ttoaddr(argv[i], 0, af, &high);
	if (oops != NULL) {
		fprintf(stderr, "%s: high conversion failed: %s\n", argv[0],
			oops);
		exit(1);
	}
	oops = ttoaddr(argv[i + 1], 0, af, &low);
	if (oops != NULL) {
		fprintf(stderr, "%s: low conversion failed: %s\n", argv[0],
			oops);
		exit(1);
	}

	n = iprange_bits(high, low);

	addrtot(&high, 0, bh, sizeof(bh));
	addrtot(&low, 0, bl, sizeof(bl));

	printf("iprange between %s and %s => %d\n", bh, bl, n);

	exit(0);
}

#endif

static void check_iprange_bits(void)
{
	struct test {
		int family;
		const char *low;
		const char *high;
		int range;
	};
	static const struct test tests[] = {
		{ 4, "1.2.255.0", "1.2.254.255", 1 },
		{ 4, "1.2.3.0", "1.2.3.7", 3 },
		{ 4, "1.2.3.0", "1.2.3.255", 8 },
		{ 4, "1.2.3.240", "1.2.3.255", 4 },
		{ 4, "0.0.0.0", "255.255.255.255", 32 },
		{ 4, "1.2.3.4", "1.2.3.4", 0 },
		{ 4, "1.2.3.0", "1.2.3.254", 8 },
		{ 4, "1.2.3.0", "1.2.3.126", 7 },
		{ 4, "1.2.3.0", "1.2.3.125", 7 },
		{ 4, "1.2.0.0", "1.2.255.255", 16 },
		{ 4, "1.2.0.0", "1.2.0.255", 8 },
		{ 4, "1.2.255.0", "1.2.255.255", 8 },
		{ 4, "1.2.255.1", "1.2.255.255", 8 },
		{ 4, "1.2.0.1", "1.2.255.255", 16 },
		{ 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:ffff", 16 },
		{ 6, "1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:fff", 12 },
		{ 6, "1:2:3:4:5:6:7:f0", "1:2:3:4:5:6:7:ff", 4 },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		LHPRINT(stdout, "IPv%d -> %d", t->family, t->range);

		int af = (t->family == 4) ? AF_INET : AF_INET6;

		ip_address low;
		oops = ttoaddr(t->low, 0, af, &low);
		if (oops != NULL) {
			LHFAIL("ttoaddr failed converting '%s'", t->low);
			continue;
		}

		ip_address high;
		oops = ttoaddr(t->high, 0, af, &high);
		if (oops != NULL) {
			LHFAIL("ttoaddr failed converting '%s'", t->high);
			continue;
		}

		int n = iprange_bits(high, low);
		if (n != -1 && t->range == -1) {
			/* okay, error expected */
		} else if (n == -1) {
			LHFAIL("iprangediff failed");
		} else if (t->range == -1) {
			LHFAIL("iprangediff succeeded unexpectedly");
		} else if (t->range != n) {
			LHFAIL("returned '%d', expected '%d'", n, t->range);
		}
	}
}

#ifdef NOT_YET
int main(int argc, char *argv[])
{
	ip_range r;
	ip_range r1;
	char buf1[100];
	char buf2[100];
	char buf3[100];
	const char *oops;
	int af;
	char *p;
	uint32_t pool_size;
	uint32_t pool_size1;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s range\n", argv[0]);
		fprintf(stderr, "   or: %s -r\n", argv[0]);
		exit(2);
	}

	if (streq(argv[1], "-r")) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	af = AF_INET;
	p = argv[1];
	oops = ttorange(p, 0, af, &r, FALSE);
	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}

	pool_size = (uint32_t)ntohl(r.end.u.v4.sin_addr.s_addr) -
		(uint32_t)ntohl(r.start.u.v4.sin_addr.s_addr);
	pool_size++;

	addrtot(&r.start, 0, buf1, sizeof(buf1));
	addrtot(&r.end, 0, buf2, sizeof(buf2));
	snprintf(buf3, sizeof(buf3), "%s-%s", buf1, buf2);
	oops = ttorange(buf3, 0, af, &r1, FALSE);
	if (oops != NULL) {
		fprintf(stderr, "%s: verification conversion failed: %s\n",
			buf3, oops);
		exit(1);
	}

	pool_size1 = (uint32_t)ntohl(r1.end.u.v4.sin_addr.s_addr) -
		(uint32_t)ntohl(r1.start.u.v4.sin_addr.s_addr);
	pool_size1++;
	if (pool_size != pool_size1) {
		fprintf(stderr,
			"%s: reverse conversion of sizes mismatch %u : %u ",
			argv[0], pool_size, pool_size1);
		exit(1);
	}
	printf("%s %u\n", buf3, pool_size);

	exit(0);
}
#endif

static void check_ttorange(void)
{
	printf("skipping %s\n", __func__);
	struct test {
		int family;
		const char *input;
		long output;
	};

	static const struct test tests[] = {
		/* er, pick one! */
		{ 4, "1.2.3.0-1.2.3.9", 10 },
		/* { 4, "1.2.3.0-1.2.3.9", 9 }, */
		{ 4, "1.2.3.0-nonenone", -1 },
		{ 4, "1.2.3.0/255.255.255.0", -1 },
		{ 4, "_", -1 },
		{ 4, "_/_", -1 },
		/* not implemented */
		{ 6, "1:0:3:0:0:0:0:2/128", -1 /*"1:0:3::2/128"*/, },
		{ 6, "abcd:ef01:2345:6789:0:00a:000:20/128",
		  -1 /*"abcd:ef01:2345:6789:0:a:0:20/128"*/ },
		{ 6, "%default", -1 /*"NULL"*/ },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		if (t->output >= 0) {
			IPRINT(stdout, "-> %ld", t->output);
		} else {
			IPRINT(stdout, "-> <error>");
		}
		const char *oops = NULL;
		int af = (t->family == 4) ? AF_INET : AF_INET6;

		ip_range s;
		oops = ttorange(t->input, 0, af, &s, false);
		if (oops != NULL && t->output < 0) {
			/* Error was expected, do nothing */
			continue;
		}
		if (oops != NULL && t->output >= 0) {
			/* Error occurred, but we didn't expect one  */
			IFAIL("ttorange failed: %s", oops);
			continue;
		}

		/* er, isn't the point of this a function? */
		unsigned pool_size = (uint32_t)ntohl(s.end.u.v4.sin_addr.s_addr) -
			(uint32_t)ntohl(s.start.u.v4.sin_addr.s_addr);
		pool_size++;
		if (t->output != (long)pool_size) {
			IFAIL("pool_size gave %u, expecting %ld",
			      pool_size, t->output);
		}
	}
}

void ip_range_check(void)
{
	check_rangetosubnet();
	check_iprange_bits();
	check_ttorange();
}
