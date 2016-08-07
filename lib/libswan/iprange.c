/*
 * more minor utilities for mask length calculations for IKEv2
 * header: include/libswan.h
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
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
#include <stdlib.h>

#include "libswan.h"

/*
 * this is stupid implementation, see goodmask.c for ideas
 * on doing it better, but note that this counts zero bits, not
 * 1 bits, and it doesn't assume that the mask is properly formed.
 *
 * BUG: the function name is clearly a lie.
 * For example, an all 0 address yields 0, not 32 or 128.
 * For example, an all 1 address yields 32 or 128, not 0.
 */
int ikev2_highorder_zerobits(ip_address b)
{
	unsigned char *bp;
	unsigned int i, j;
	size_t n;
	int zerobits = 0;

	n = addrbytesptr(&b, &bp);
	if (n == 0)
		return -1;

	zerobits = 0;
	for (j = 0; j < n; j++) {
		unsigned char mask = 1UL << 7;

		if (*bp) {
			for (i = 0; i < 8; i++) {
				if (*bp & mask)
					return (8 * n) - (zerobits + i);

				mask >>= 1;
			}
		}
		bp++;
		zerobits += 8;
	}
	return 0;
}

int ikev2_calc_iprangediff(ip_address low, ip_address high)
{
	unsigned char *hp;
	unsigned char *lp, *t;
	unsigned char *dp;
	ip_address diff;
	size_t n;
	size_t n2;
	int i;
	int carry = 0;

	/* initialize all the contents to sensible values */
	diff = low;

	if (addrtypeof(&high) != addrtypeof(&low))
		return -1;

	n = addrbytesptr(&high, &hp);
	if (n == 0)
		return -1;

	n2 = addrbytesptr(&low, &lp);
	if (n != n2)
		return -1;

	addrbytesptr_write(&diff, &dp);
	for (i = 0; i < (int)n; i++) {
		if (hp[i] == lp[i]) {
			dp[i] = 0;
			continue;
		}
		break;
	}

	/* two values are the same -- no diff */
	if (i == (int)n)
		return 0;

	if (hp[i] < lp[i]) {
		/* need to swap! */
		t = hp;
		hp = lp;
		lp = t;
	}

	for (i = n - 1; i >= 0; i--) {
		int val = hp[i] - lp[i] - carry;
		if (val < 0) {
			val += 256;
			carry = 1;
		} else {
			carry = 0;
		}
		dp[i] = val;
	}

	return ikev2_highorder_zerobits(diff);
}

#ifdef IPRANGE_MAIN

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

	n = ikev2_calc_iprangediff(high, low);

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
		n = ikev2_calc_iprangediff(high, low);
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
