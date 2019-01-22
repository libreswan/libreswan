/*
 * convert from text form of subnet specification to binary
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2018  Andrew Cagney
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

#include "ipcheck.h"
#include "ip_subnet.h"
#include "constants.h"		/* for elemsof() */

/*
 * from ttosubnet.c
 */

#ifdef NOT_YET
int main(int argc, char *argv[])
{
	ip_subnet s;
	char buf[100];
	char buf2[100];
	const char *oops;
	size_t n;
	int af;
	char *p;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-6] addr/mask\n", argv[0]);
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
	if (streq(argv[1], "-6")) {
		af = AF_INET6;
		p = argv[2];
	} else if (strchr(argv[1], ':') != NULL) {
		af = AF_INET6;
	}
	oops = ttosubnet(p, 0, af, &s);
	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	n = subnettot(&s, 0, buf, sizeof(buf));
	if (n > sizeof(buf)) {
		fprintf(stderr, "%s: reverse conversion of ", argv[0]);
		(void) addrtot(&s.addr, 0, buf2, sizeof(buf2));
		fprintf(stderr, "%s/", buf2);
		fprintf(stderr, "%d", s.maskbits);
		fprintf(stderr, " failed: need %zd bytes, have only %zd\n",
			n, sizeof(buf));
		exit(1);
	}
	printf("%s\n", buf);

	exit(0);
}
#endif

static void check_str_subnet(void)
{
	struct test {
		int family;
		char *input;
		char *output;	/* NULL means error expected */
	};
	static const struct test tests[] = {
		{ 4, "1.2.3.0/255.255.255.0", "1.2.3.0/24" },
		{ 4, "1.2.3.0/24", "1.2.3.0/24" },
#if 0
		{ 4, "1.2.3.0/24:10", "1.2.3.0/24:10" },
		{ 4, "1.2.3.0/24:-1", NULL },
		{ 4, "1.2.3.0/24:none", NULL },
		{ 4, "1.2.3.0/24:", NULL },
		{ 4, "1.2.3.0/24:0x10", "1.2.3.0/24:16" },
		{ 4, "1.2.3.0/24:0X10", "1.2.3.0/24:16" },
		{ 4, "1.2.3.0/24:010", "1.2.3.0/24:8" },
#endif
		{ 4, "1.2.3.1/255.255.255.240", "1.2.3.0/28" },
		{ 4, "1.2.3.1/32", "1.2.3.1/32" },
		{ 4, "1.2.3.1/0", "0.0.0.0/0" },
/*	{4, "1.2.3.1/255.255.127.0",	"1.2.3.0/255.255.127.0"}, */
		{ 4, "1.2.3.1/255.255.127.0", NULL },
		{ 4, "128.009.000.032/32", "128.9.0.32/32" },
		{ 4, "128.0x9.0.32/32", NULL },
		{ 4, "0x80090020/32", "128.9.0.32/32" },
		{ 4, "0x800x0020/32", NULL },
		{ 4, "128.9.0.32/0xffFF0000", "128.9.0.0/16" },
		{ 4, "128.9.0.32/0xff0000FF", NULL },
		{ 4, "128.9.0.32/0x0000ffFF", NULL },
		{ 4, "128.9.0.32/0x00ffFF0000", NULL },
		{ 4, "128.9.0.32/0xffFF", NULL },
		{ 4, "128.9.0.32.27/32", NULL },
		{ 4, "128.9.0k32/32", NULL },
		{ 4, "328.9.0.32/32", NULL },
		{ 4, "128.9..32/32", NULL },
		{ 4, "10/8", "10.0.0.0/8" },
		{ 4, "10.0/8", "10.0.0.0/8" },
		{ 4, "10.0.0/8", "10.0.0.0/8" },
		{ 4, "10.0.1/24", "10.0.1.0/24" },
		{ 4, "_", NULL },
		{ 4, "_/_", NULL },
		{ 4, "1.2.3.1", NULL },
		{ 4, "1.2.3.1/_", NULL },
		{ 4, "1.2.3.1/24._", NULL },
		{ 4, "1.2.3.1/99", NULL },
		{ 4, "localhost/32", NULL },
		{ 4, "%default", "0.0.0.0/0" },
		{ 6, "3049:1::8007:2040/0", "::/0" },
		{ 6, "3049:1::8007:2040/128", "3049:1::8007:2040/128" },
		{ 6, "3049:1::192.168.0.1/128", NULL },	/*"3049:1::c0a8:1/128",*/
		{ 6, "3049:1::8007::2040/128", NULL },
		{ 6, "3049:1::8007:2040/ffff:0", NULL },
		{ 6, "3049:1::8007:2040/64", "3049:1::/64" },
#if 0
		{ 6, "3049:1::8007:2040/64:53", "3049:1::/64:53" },
#endif
		{ 6, "3049:1::8007:2040/ffff:", NULL },
		{ 6, "3049:1::8007:2040/0000:ffff::0", NULL },
		{ 6, "3049:1::8007:2040/ff1f:0", NULL },
		{ 6, "3049:1::8007:x:2040/128", NULL },
		{ 6, "3049:1t::8007:2040/128", NULL },
		{ 6, "3049:1::80071:2040/128", NULL },
		{ 6, "::/21", "::/21" },
		{ 6, "::1/128", "::1/128" },
		{ 6, "1::/21", "1::/21" },
		{ 6, "1::2/128", "1::2/128" },
		{ 6, "1:0:0:0:0:0:0:2/128", "1::2/128" },
		{ 6, "1:0:0:0:3:0:0:2/128", "1::3:0:0:2/128" },
		{ 6, "1:0:0:3:0:0:0:2/128", "1:0:0:3::2/128" },
		{ 6, "1:0:3:0:0:0:0:2/128", "1:0:3::2/128" },
		{ 6, "abcd:ef01:2345:6789:0:00a:000:20/128",
		  "abcd:ef01:2345:6789:0:a:0:20/128" },
		{ 6, "3049:1::8007:2040/ffff:ffff:", NULL },
		{ 6, "3049:1::8007:2040/ffff:88:", NULL },
		{ 6, "3049:12::9000:3200/ffff:fff0", NULL },
		{ 6, "3049:12::9000:3200/28", "3049:10::/28" },
		{ 6, "3049:12::9000:3200/ff00:", NULL },
		{ 6, "3049:12::9000:3200/ffff:", NULL },
		{ 6, "3049:12::9000:3200/128_", NULL },
		{ 6, "3049:12::9000:3200/", NULL },
		{ 6, "%default", "::/0" },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		IPRINT(stdout, "IPv%d -> '%s'", t->family, t->output);

		int af = (t->family == 4) ? AF_INET : AF_INET6;

		ip_subnet s;
		oops = ttosubnet(t->input, 0, af, &s);
		if (oops != NULL && t->output == NULL) {
			/* Error was expected, do nothing */
			continue;
		} else if (oops != NULL && t->output != NULL) {
			/* Error occurred, but we didn't expect one  */
			IFAIL("ttosubnet failed: %s", oops);
			continue;
		} else if (oops == NULL && t->output == NULL) {
			/* If no errors, but we expected one */
			IFAIL("ttosubnet succeeded unexpectedly");
			continue;
		}

		ip_subnet_buf buf;
		const char *out = str_subnet(&s, &buf);
		if (!streq(t->output, out)) {
			IFAIL("subnetporttot returned '%s', expected '%s'",
			      out, t->output);
			continue;
		}
	}
}

void ip_subnet_check(void)
{
	check_str_subnet();
}
