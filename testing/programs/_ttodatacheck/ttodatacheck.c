/*
 * convert from text form of arbitrary data (e.g., keys) to binary
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2023, Andrew Cagney
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

#include <stdlib.h>
#include <stdio.h>

#include "err.h"
#include "constants.h"
#include "ttodata.h"

struct artab;
static void check(struct artab *r, char *buf, size_t n, err_t oops,
		  int *status);
static void regress(void);
static void hexout(const char *s, size_t len, FILE *f);

/*
 * main - convert first argument to hex, or run regression
 */
int main(int argc, char *argv[])
{
	char buf[1024];
	char buf2[1024];
	size_t n;
	char *p = buf;
	char *p2 = buf2;
	char *pgm = argv[0];

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {0x<hex>|0s<base64>|-r}\n", pgm);
		exit(2);
	}

	if (streq(argv[1], "-r")) {
		regress();	/* should not return */
		fprintf(stderr, "%s: regress() returned?!?\n", pgm);
		exit(1);
	}

	err_t oops = ttodata(argv[1], strlen(argv[1]), 0,
			     buf, sizeof(buf), &n);
	if (oops != NULL) {
		fprintf(stderr, "%s: ttodata error `%s' in `%s'\n", pgm,
			oops, argv[1]);
		exit(1);
	}

	if (n > sizeof(buf)) {
		p = (char *)malloc((size_t)n);
		if (p == NULL) {
			fprintf(stderr,
				"%s: unable to malloc %zu bytes for result\n",
				pgm, n);
			exit(1);
		}
		oops = ttodata(argv[1], strlen(argv[1]), 0, p, n, &n);
		if (oops != NULL) {
			fprintf(stderr, "%s: error `%s' in ttodata retry?!?\n",
				pgm, oops);
			exit(1);
		}
	}

	hexout(p, n, stdout);
	printf("\n");

	size_t i = datatot(buf, n, 'h', buf2, sizeof(buf2));
	if (i == 0) {
		fprintf(stderr, "%s: datatot reports error in `%s'\n", pgm,
			argv[1]);
		exit(1);
	}

	if (i > sizeof(buf2)) {
		p2 = (char *)malloc((size_t)i);
		if (p == NULL) {
			fprintf(stderr,
				"%s: unable to malloc %zu bytes for result\n",
				pgm, i);
			exit(1);
		}
		i = datatot(buf, n, 'h', p2, i);
		if (i == 0) {
			fprintf(stderr, "%s: error in datatot retry?!?\n",
				pgm);
			exit(1);
		}
	}

	printf("%s\n", p2);

	exit(0);
}

/*
 * hexout - output an arbitrary-length string in hex
 */
static void hexout(const char *s,
		   size_t len,
		   FILE *f)
{
	size_t i;

	fprintf(f, "0x");
	for (i = 0; i < len; i++)
		fprintf(f, "%02x", (unsigned char)s[i]);
}

struct artab {
	int base;
	char *ascii;	/* NULL for end */
	char *data;	/* NULL for error expected */
} atodatatab[] = {
	{ 0, "", NULL, },
	{ 0, "0", NULL, },
	{ 0, "0x", NULL, },
	{ 0, "0xa", NULL, },
	{ 0, "0xab", "\xab", },
	{ 0, "0xabc", NULL, },
	{ 0, "0xabcd", "\xab\xcd", },
	{ 0, "0x0123456789", "\x01\x23\x45\x67\x89", },
	{ 0, "0x01x", NULL, },
	{ 0, "0xabcdef", "\xab\xcd\xef", },
	{ 0, "0xABCDEF", "\xab\xcd\xef", },
	{ 0, "0XaBc0eEd81f", "\xab\xc0\xee\xd8\x1f", },
	{ 0, "0XaBc0_eEd8", "\xab\xc0\xee\xd8", },
	{ 0, "0XaBc0_", NULL, },
	{ 0, "0X_aBc0", NULL, },
	{ 0, "0Xa_Bc0", NULL, },
	{ 16, "aBc0eEd8", "\xab\xc0\xee\xd8", },
	{ 0, "0s", NULL, },
	{ 0, "0sA", NULL, },
	{ 0, "0sBA", NULL, },
	{ 0, "0sCBA", NULL, },
	{ 0, "0sDCBA", "\x0c\x20\x40", },
	{ 0, "0SDCBA", "\x0c\x20\x40", },
	{ 0, "0sDA==", "\x0c", },
	{ 0, "0sDC==", NULL, },
	{ 0, "0sDCA=", "\x0c\x20", },
	{ 0, "0sDCB=", NULL, },
	{ 0, "0sDCAZ", "\x0c\x20\x19", },
	{ 0, "0sDCAa", "\x0c\x20\x1a", },
	{ 0, "0sDCAz", "\x0c\x20\x33", },
	{ 0, "0sDCA0", "\x0c\x20\x34", },
	{ 0, "0sDCA9", "\x0c\x20\x3d", },
	{ 0, "0sDCA+", "\x0c\x20\x3e", },
	{ 0, "0sDCA/", "\x0c\x20\x3f", },
	{ 0, "0sAbraCadabra+", "\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ 0, "0t", NULL, },
	{ 0, "0tabc_xyz", "abc_xyz", },
	{ 256, "abc_xyz", "abc_xyz", },
	{ 0, NULL, NULL, },
};

struct drtab {
	char *data;	/* input; NULL for end */
	char format;
	int buflen;	/* -1 means big buffer */
	int outlen;	/* -1 means strlen(ascii)+1 */
	char *ascii;	/* NULL for error expected */
} datatoatab[] = {
	{ "", 'x', -1, -1, NULL, },
	{ "", 'X', -1, -1, NULL, },
	{ "", 'n', -1, -1, NULL, },
	{ "0", 'x', -1, -1, "0x30", },
	{ "0", 'x', 0, 5, "---", },
	{ "0", 'x', 1, 5, "", },
	{ "0", 'x', 2, 5, "0", },
	{ "0", 'x', 3, 5, "0x", },
	{ "0", 'x', 4, 5, "0x3", },
	{ "0", 'x', 5, 5, "0x30", },
	{ "0", 'x', 6, 5, "0x30", },
	{ "\xab\xcd", 'x', -1, -1, "0xabcd", },
	{ "\x01\x23\x45\x67\x89", 'x', -1, -1, "0x0123456789",
	},
	{ "\xab\xcd\xef", 'x', -1, -1, "0xabcdef", },
	{ "\xab\xc0\xee\xd8\x1f", 'x', -1, -1, "0xabc0eed81f",
	},
	{ "\x01\x02", 'h', -1, -1, "0x0102", },
	{ "\x01\x02\x03\x04\x05\x06", 'h', -1, -1, "0x01020304_0506", },
	{ "\xab\xc0\xee\xd8\x1f", 16, -1, -1, "abc0eed81f",
	},
	{ "\x0c\x20\x40", 's', -1, -1, "0sDCBA", },
	{ "\x0c\x20\x40", 's', 0, 7, "---", },
	{ "\x0c\x20\x40", 's', 1, 7, "", },
	{ "\x0c\x20\x40", 's', 2, 7, "0", },
	{ "\x0c\x20\x40", 's', 3, 7, "0s", },
	{ "\x0c\x20\x40", 's', 4, 7, "0sD", },
	{ "\x0c\x20\x40", 's', 5, 7, "0sDC", },
	{ "\x0c\x20\x40", 's', 6, 7, "0sDCB", },
	{ "\x0c\x20\x40", 's', 7, 7, "0sDCBA", },
	{ "\x0c\x20\x40", 's', 8, 7, "0sDCBA", },
	{ "\x0c", 's', -1, -1, "0sDA==", },
	{ "\x0c\x20", 's', -1, -1, "0sDCA=", },
	{ "\x0c\x20\x19", 's', -1, -1, "0sDCAZ", },
	{ "\x0c\x20\x1a", 's', -1, -1, "0sDCAa", },
	{ "\x0c\x20\x33", 's', -1, -1, "0sDCAz", },
	{ "\x0c\x20\x34", 's', -1, -1, "0sDCA0", },
	{ "\x0c\x20\x3d", 's', -1, -1, "0sDCA9", },
	{ "\x0c\x20\x3e", 's', -1, -1, "0sDCA+", },
	{ "\x0c\x20\x3f", 's', -1, -1, "0sDCA/", },
	{ "\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", 's', -1, -1, "0sAbraCadabra+", },
	{ "\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", 64, -1, -1, "AbraCadabra+", },
	{ NULL, 'x', -1, -1, NULL, },
};

/*
 * regress - regression-test ttodata() and datatot()
 */
static void check(struct artab *r, char *buf, size_t n, err_t oops, int *status)
{
	if (oops != NULL && r->data == NULL) {
		/* error expected */
	} else if (oops != NULL) {
		printf("`%s' gave error `%s', expecting %zu `", r->ascii,
			oops, strlen(r->data));
		hexout(r->data, strlen(r->data), stdout);
		printf("'\n");
		*status = 1;
	} else if (r->data == NULL) {
		printf("`%s' gave %zu `", r->ascii, n);
		hexout(buf, n, stdout);
		printf("', expecting error\n");
		*status = 1;
	} else if (n != strlen(r->data)) {
		printf("length wrong in `%s': got %zu `", r->ascii, n);
		hexout(buf, n, stdout);
		printf("', expecting %zu `", strlen(r->data));
		hexout(r->data, strlen(r->data), stdout);
		printf("'\n");
		*status = 1;
	} else if (!memeq(buf, r->data, n)) {
		printf("`%s' gave %zu `", r->ascii, n);
		hexout(buf, n, stdout);
		printf("', expecting %zu `", strlen(r->data));
		hexout(r->data, strlen(r->data), stdout);
		printf("'\n");
		*status = 1;
	}
	fflush(stdout);
}

static void regress(void)
{
	struct artab *r;
	struct drtab *dr;
	char buf[100];
	size_t n;
	int status = 0;

	for (r = atodatatab; r->ascii != NULL; r++) {
		int base = r->base;
		int xbase = 0;

		if (base == 0 && r->ascii[0] == '0') {
			switch (r->ascii[1]) {
			case 'x':
			case 'X':
				xbase = 16;
				break;
			case 's':
			case 'S':
				xbase = 64;
				break;
			case 't':
			case 'T':
				xbase = 256;
				break;
			}
		}

		check(r, buf, n,
		      ttodata(r->ascii, 0, base, buf, sizeof(buf), &n),
		      &status);
		if (base == 64 || xbase == 64)
			check(r, buf, n,
			      ttodata(r->ascii, strlen(r->ascii), base, buf, sizeof(buf), &n),
			      &status);

		if (xbase != 0) {
			check(r, buf, n,
			      ttodata(r->ascii + 2, 0, xbase, buf, sizeof(buf), &n),
			      &status);
			if (base == 64 || xbase == 64)
				check(r, buf, n,
				      ttodata(r->ascii + 2, 0, xbase, buf, sizeof(buf), &n),
				      &status);
		}
	}

	for (dr = datatoatab; dr->data != NULL; dr++) {
		strcpy(buf, "---");
		n = datatot(dr->data, strlen(dr->data), dr->format, buf,
			    (dr->buflen == -1) ? sizeof(buf) : (size_t)dr->buflen);
		size_t should = (dr->ascii == NULL) ? 0 : strlen(dr->ascii) + 1;
		if (dr->outlen != -1)
			should = dr->outlen;
		if (n == 0 && dr->ascii == NULL) {
			/* error expected */
		} else if (n == 0) {
			printf("`");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("' %c gave error, expecting %zu `%s'\n",
			       dr->format, should, dr->ascii);
			status = 1;
		} else if (dr->ascii == NULL) {
			printf("`");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("' %c gave %zu `%.*s', expecting error\n",
			       dr->format, n, (int)n, buf);
			status = 1;
		} else if (n != should) {
			printf("length wrong in `");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("': got %zu `%s'", n, buf);
			printf(", expecting %zu `%s'\n", should, dr->ascii);
			status = 1;
		} else if (!streq(buf, dr->ascii)) {
			printf("`");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("' gave %zu `%s'", n, buf);
			printf(", expecting %zu `%s'\n", should, dr->ascii);
			status = 1;
		}
		fflush(stdout);
	}
	exit(status);
}
