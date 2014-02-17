/*
 * convert from text form of IP address range specification to binary
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2013  Antony Antony <antony@phenome.org>
 *
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */
#include "internal.h"
#include "libreswan.h"
#define  RANGE_MIN_LEN 15 /* 1.2.3.4-5.6.7.8 */

/*
 * ttorange - convert text "addr1-addr2" to address start address_end
 */
err_t ttorange(src, srclen, af, dst)
const char *src;
size_t srclen;	/* 0 means "apply strlen" */
int af;	/* AF_INET.  AF_INET6 not supported yet. */
ip_range *dst;
{
	const char *dash;
	const char *high;
	size_t hlen;
	const char *oops;

	ip_address addr_start_tmp;
	ip_address addr_end_tmp;

	if (src == NULL)
		return "src is empty";

	if (srclen == 0)
		srclen = strlen(src);

	if (srclen == 0)
		return "src is an empty string";

	if (af != AF_INET)
		return "support only AF_INET v4.";

	if (srclen < RANGE_MIN_LEN)
		return "range is too short min RANGE_MIN_LEN e.g 1.2.3.4-5.6.7.8";

	dash = memchr(src, '-', srclen);
	if (dash == NULL)
		return "no - in ip address range specification";

	high = dash + 1;
	hlen = srclen - (dash - src) - 1;
	oops = ttoaddr(src, dash - src, af, &addr_start_tmp);
	if (oops != NULL)
		return oops;

	if (af == 0)
		af = ip_address_family(&addr_start_tmp);

	switch (af) {
	case AF_INET:
		break;
	case AF_INET6:
		return "address family (AF_INET6) is not supported in ttorange start";

	default:
		return "unknown address family in ttorange start";

		break;
	}

	/*extract end ip address*/
	oops = ttoaddr(high, hlen, af, &addr_end_tmp);
	if (oops != NULL)
		return oops;

	if (af == 0)
		af = ip_address_family(&addr_end_tmp);

	switch (af) {
	case AF_INET:
		break;
	case AF_INET6:
		return "address family (AF_INET6) is not supported in ttiporange end";

	default:
		return "unknown address family in ttorange end";

		break;
	}
	if (ntohl(addr_end_tmp.u.v4.sin_addr.s_addr) <
		ntohl(addr_start_tmp.u.v4.sin_addr.s_addr))
		return "range size is -ve. start is grater than the end";

	/* we validated the range. no put them in dst */
	dst->start = addr_start_tmp;
	dst->end = addr_end_tmp;
	return FALSE;
}

#ifdef TTORANGE_MAIN

#include <stdio.h>

void regress(void);

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
	u_int32_t pool_size;
	u_int32_t pool_size1;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s range\n", argv[0]);
		fprintf(stderr, "   or: %s -r\n", argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	af = AF_INET;
	p = argv[1];
	oops = ttorange(p, 0, af, &r);
	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}

	pool_size = (u_int32_t)ntohl(r.end.u.v4.sin_addr.s_addr) -
		(u_int32_t)ntohl(r.start.u.v4.sin_addr.s_addr);
	pool_size++;

	addrtot(&r.start, 0, buf1, sizeof(buf1));
	addrtot(&r.end, 0, buf2, sizeof(buf2));
	snprintf(buf3, sizeof(buf3), "%s-%s", buf1, buf2);
	oops = ttorange(buf3, 0, af, &r1);
	if (oops != NULL) {
		fprintf(stderr, "%s: verification conversion failed: %s\n",
			buf3, oops);
		exit(1);
	}

	pool_size1 = (u_int32_t)ntohl(r1.end.u.v4.sin_addr.s_addr) -
		(u_int32_t)ntohl(r1.start.u.v4.sin_addr.s_addr);
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

struct rtab {
	int family;
	char *input;
	char *output;	/* NULL means error expected */
} rtab[] = {
	{ 4, "1.2.3.0-1.2.3.9", "10" },
	{ 4, "1.2.3.0-1.2.3.9", "9" },
	{ 4, "1.2.3.0-nonenone", NULL },
	{ 4, "1.2.3.0/255.255.255.0", NULL },
	{ 4, "_", NULL },
	{ 4, "_/_", NULL },
	{ 6, "1:0:3:0:0:0:0:2/128", "1:0:3::2/128" },
	{ 6, "abcd:ef01:2345:6789:0:00a:000:20/128",
		"abcd:ef01:2345:6789:0:a:0:20/128" },
	{ 6, "%default", "NULL" },
	{ 4, NULL, NULL }
};

void regress(void)
{
	struct rtab *r;
	int status = 0;
	ip_range s;
	char in[100];
	char buf[100];
	char buf1[100];
	u_int32_t pool_size;
	const char *oops;
	size_t n;
	int af;

	for (r = rtab; r->input != NULL; r++) {
		af = (r->family == 4) ? AF_INET : AF_INET6;
		strcpy(in, r->input);
		printf("Testing `%s' ... ", in);
		oops = ttorange(in, 0, af, &s);
		if (oops != NULL && r->output == NULL)
			/* Error was expected, do nothing */
			printf("OK (%s)\n", oops);
		if (oops != NULL && r->output != NULL) {
			/* Error occurred, but we didn't expect one  */
			printf("`%s' ttorange failed: %s\n", r->input, oops);
			status = 1;
		}

		pool_size = (u_int32_t)ntohl(s.end.u.v4.sin_addr.s_addr) -
			(u_int32_t)ntohl(s.start.u.v4.sin_addr.s_addr);
		pool_size++;
		snprintf(buf1, sizeof(buf1), "%u", pool_size);

		if (oops == NULL && r->output != NULL) {
			/* No error, no error expected */
			if (strcmp(r->output, buf1) == 0) {
				printf(" %s OK\n", r->output);
			} else {
				status = 1;
				printf("FAIL expecting %s and got %s\n",
					r->output, buf1);
			}
		}
		if (oops == NULL && r->output == NULL) {
			/* If no errors, but we expected one */
			printf("`%s %s' ttosubnet succeeded unexpectedly\n",
				r->input, buf1);
			status = 1;
		}
	}
	exit(status);
}

#endif	/* TTORANGE_MAIN */
