/* ip_range type, for libreswan
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2013  Antony Antony <antony@phenome.org>
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

/*
 * convert from text form of IP address range specification to binary;
 * and more minor utilities for mask length calculations for IKEv2
 */

#include "ip_range.h"

#include "libreswan.h"		/* for random stuff that should be elsewhere */

/*
 * Calculate the number of significant bits in the size of the range.
 * floor(lg(|high-low| + 1))
 *
 * ??? this really should use ip_range rather than a pair of ip_address values
 */

int iprange_bits(ip_address low, ip_address high)
{
	if (addrtypeof(&high) != addrtypeof(&low))
		return -1;

	const unsigned char *hp;
	size_t n = addrbytesptr_read(&high, &hp);
	if (n == 0)
		return -1;

	const unsigned char *lp;
	size_t n2 = addrbytesptr_read(&low, &lp);
	if (n != n2)
		return -1;

	ip_address diff = low;	/* initialize all the contents to sensible values */
	unsigned char *dp;
	addrbytesptr_write(&diff, &dp);

	unsigned lastnz = n;

	/* subtract: d = h - l */
	int carry = 0;
	unsigned j;
	for (j = n; j > 0; ) {
		j--;
		int val = hp[j] - lp[j] - carry;
		if (val < 0) {
			val += 0x100u;
			carry = 1;
		} else {
			carry = 0;
		}
		dp[j] = val;
		if (val != 0)
			lastnz = j;
	}

	/* if the answer was negative, complement it */
	if (carry != 0) {
		lastnz = n;	/* redundant, but not obviously so */
		for (j = n; j > 0; ) {
			j--;
			int val = 0xFFu - dp[j] + carry;
			if (val >= 0x100) {
				val -= 0x100;
				carry = 1;	/* redundant, but not obviously so */
			} else {
				carry = 0;
			}
			dp[j] = val;
			if (val != 0)
				lastnz = j;
		}
	}

	/* find leftmost bit in dp[lastnz] */
	unsigned bo = 0;
	if (lastnz != n) {
		bo = 0;
		for (unsigned m = 0x80u; (m & dp[lastnz]) == 0;  m >>=1)
			bo++;
	}
	return (n - lastnz) * 8 - bo;
}

#ifdef IPRANGE_MAIN

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "constants.h"

void regress(void);

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

struct rtab {
	int family;
	char *low;
	char *high;
	int range;
} rtab[] = {
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
	{ 4, NULL, NULL, 0 },
};

void regress(void)
{
	struct rtab *r;
	int status = 0;
	ip_address high;
	ip_address low;
	const char *oops;
	int n;
	int af;

	for (r = rtab; r->high != NULL; r++) {
		af = (r->family == 4) ? AF_INET : AF_INET6;
		oops = ttoaddr(r->high, 0, af, &high);
		if (oops != NULL) {
			printf("surprise failure converting `%s'\n", r->high);
			exit(1);
		}
		oops = ttoaddr(r->low, 0, af, &low);
		if (oops != NULL) {
			printf("surprise failure converting `%s'\n", r->low);
			exit(1);
		}
		n = iprange_bits(high, low);
		if (n != -1 && r->range == -1) {
			/* okay, error expected */
		} else if (n == -1) {
			printf("`%s'-`%s' iprangediff failed.\n",
				r->high, r->low);
			status = 1;
		} else if (r->range == -1) {
			printf("`%s'-`%s' iprangediff succeeded unexpectedly\n",
				r->high, r->low);
			status = 1;
		} else if (r->range != n) {
			printf("`%s'-`%s' gave `%d', expected `%d'\n",
				r->high, r->low, n, r->range);
			status = 1;
		}
	}
	exit(status);
}

#endif /* IPRANGE_MAIN */

/*
 * ttorange - convert text "addr1-addr2" to address_start address_end
 */
err_t ttorange(const char *src,
	       size_t srclen /* 0 means "apply strlen" */,
	       int af /* AF_INET only.  AF_INET6 not supported yet. */,
	       ip_range *dst,
	       bool non_zero /* is 0.0.0.0 allowed? */)
{
	const char *dash;
	const char *high;
	size_t hlen;
	const char *oops;

	ip_address addr_start_tmp;
	ip_address addr_end_tmp;

	/* this should be a passert */
	if (af != AF_INET)
		return "ttorange only supports IPv4 addresses";

	if (srclen == 0)
		srclen = strlen(src);

	dash = memchr(src, '-', srclen);
	if (dash == NULL)
		return "missing '-' in ip address range";

	high = dash + 1;
	hlen = srclen - (high - src);
	oops = ttoaddr_num(src, dash - src, af, &addr_start_tmp);
	if (oops != NULL)
		return oops;

	/*
	 * If we allowed af == AF_UNSPEC,
	 * set it to addrtypeof(&addr_start_tmp)
	 */

	/* extract end ip address */
	oops = ttoaddr_num(high, hlen, af, &addr_end_tmp);
	if (oops != NULL)
		return oops;

	if (ntohl(addr_end_tmp.u.v4.sin_addr.s_addr) <
		ntohl(addr_start_tmp.u.v4.sin_addr.s_addr))
		return "start of range must not be greater than end";

	if (non_zero) {
		uint32_t addr  = ntohl(addr_start_tmp.u.v4.sin_addr.s_addr);

		if (addr == 0)
			return "'0.0.0.0' not allowed in range";
	}

	/* We have validated the range. Now put bounds in dst. */
	dst->start = addr_start_tmp;
	dst->end = addr_end_tmp;
	return NULL;
}

size_t rangetot(const ip_range *src, char format, char *dst, size_t dstlen)
{
	size_t l, m;

	/* start address: */
	l = addrtot(&src->start, format, dst, dstlen) - 1;
	/* l is offset of '\0' at end, at least notionally. */

	/* separator '-' */
	/* If there is room for '-' and '\0', drop in '-'. */
	if (dstlen > 0 && l < dstlen - 1)
		dst[l] = '-';
	/* count space for '-' */
	l++;
	/* where to stuff second address (not past end of buffer) */
	m = l < dstlen? l : dstlen;
	l += addrtot(&src->end, format, dst + m, dstlen - m);
	return l;	/* length needed, including '\0' */
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
	uint32_t pool_size;
	const char *oops;
	size_t n;
	int af;

	for (r = rtab; r->input != NULL; r++) {
		af = (r->family == 4) ? AF_INET : AF_INET6;
		strcpy(in, r->input);
		printf("Testing `%s' ... ", in);
		oops = ttorange(in, 0, af, &s, FALSE);
		if (oops != NULL && r->output == NULL)
			/* Error was expected, do nothing */
			printf("OK (%s)\n", oops);
		if (oops != NULL && r->output != NULL) {
			/* Error occurred, but we didn't expect one  */
			printf("`%s' ttorange failed: %s\n", r->input, oops);
			status = 1;
		}

		pool_size = (uint32_t)ntohl(s.end.u.v4.sin_addr.s_addr) -
			(uint32_t)ntohl(s.start.u.v4.sin_addr.s_addr);
		pool_size++;
		snprintf(buf1, sizeof(buf1), "%u", pool_size);

		if (oops == NULL && r->output != NULL) {
			/* No error, no error expected */
			if (streq(r->output, buf1)) {
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
