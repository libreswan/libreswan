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

#define LN __LINE__

struct artab;
static void check_ttodata(unsigned line, const struct artab *r,
			  shunk_t ascii, int base,
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

	err_t oops = ttodata(shunk1(argv[1]), 0,
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
		oops = ttodata(shunk1(argv[1]), 0, p, n, &n);
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

const struct artab {
	unsigned line;
	int base;
	char *ascii;	/* NULL for end */
	char *data;	/* NULL for error expected */
} atodatatab[] = {
	{ LN, 0, "", NULL, },
	{ LN, 0, "0", NULL, },
	{ LN, 0, "0x", NULL, },
	{ LN, 0, "0xa", NULL, },
	{ LN, 0, "0xab", "\xab", },
	{ LN, 0, "0xabc", NULL, },
	{ LN, 0, "0xabcd", "\xab\xcd", },
	{ LN, 0, "0x0123456789", "\x01\x23\x45\x67\x89", },
	{ LN, 0, "0x01x", NULL, },
	{ LN, 0, "0xabcdef", "\xab\xcd\xef", },
	{ LN, 0, "0xABCDEF", "\xab\xcd\xef", },
	{ LN, 0, "0XaBc0eEd81f", "\xab\xc0\xee\xd8\x1f", },
	{ LN, 0, "0XaBc0_eEd8", "\xab\xc0\xee\xd8", },
	{ LN, 0, "0XaBc0_", NULL, },
	{ LN, 0, "0X_aBc0", NULL, },
	{ LN, 0, "0Xa_Bc0", NULL, },
	{ LN, 16, "aBc0eEd8", "\xab\xc0\xee\xd8", },
	{ LN, 0, "0s", NULL, },
	{ LN, 0, "0sA", NULL, },
	{ LN, 0, "0sBA", NULL, },
	{ LN, 0, "0sCBA", NULL, },
	{ LN, 0, "0sDCBA", "\x0c\x20\x40", },
	{ LN, 0, "0SDCBA", "\x0c\x20\x40", },
	{ LN, 0, "0sDA==", "\x0c", },
	{ LN, 0, "0sDC==", NULL, },
	{ LN, 0, "0sDCA=", "\x0c\x20", },
	{ LN, 0, "0sDCB=", NULL, },
	{ LN, 0, "0sDCAZ", "\x0c\x20\x19", },
	{ LN, 0, "0sDCAa", "\x0c\x20\x1a", },
	{ LN, 0, "0sDCAz", "\x0c\x20\x33", },
	{ LN, 0, "0sDCA0", "\x0c\x20\x34", },
	{ LN, 0, "0sDCA9", "\x0c\x20\x3d", },
	{ LN, 0, "0sDCA+", "\x0c\x20\x3e", },
	{ LN, 0, "0sDCA/", "\x0c\x20\x3f", },
	{ LN, 0, "0sAbraCadabra+", "\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", },
	{ LN, 0, "0t", NULL, },
	{ LN, 0, "0tabc_xyz", "abc_xyz", },
	{ LN, 256, "abc_xyz", "abc_xyz", },
	{ LN, 0, NULL, NULL, },
};

const struct drtab {
	unsigned line;
	char *data;	/* input; NULL for end */
	char format;
	int buflen;	/* -1 means big buffer */
	int outlen;	/* -1 means strlen(ascii)+1 */
	char *ascii;	/* NULL for error expected */
} datatoatab[] = {
	{ LN, "", 'x', -1, -1, NULL, },
	{ LN, "", 'X', -1, -1, NULL, },
	{ LN, "", 'n', -1, -1, NULL, },
	{ LN, "0", 'x', -1, -1, "0x30", },
	{ LN, "0", 'x', 0, 5, "---", },
	{ LN, "0", 'x', 1, 5, "", },
	{ LN, "0", 'x', 2, 5, "0", },
	{ LN, "0", 'x', 3, 5, "0x", },
	{ LN, "0", 'x', 4, 5, "0x3", },
	{ LN, "0", 'x', 5, 5, "0x30", },
	{ LN, "0", 'x', 6, 5, "0x30", },
	{ LN, "\xab\xcd", 'x', -1, -1, "0xabcd", },
	{ LN, "\x01\x23\x45\x67\x89", 'x', -1, -1, "0x0123456789",
	},
	{ LN, "\xab\xcd\xef", 'x', -1, -1, "0xabcdef", },
	{ LN, "\xab\xc0\xee\xd8\x1f", 'x', -1, -1, "0xabc0eed81f",
	},
	{ LN, "\x01\x02", 'h', -1, -1, "0x0102", },
	{ LN, "\x01\x02\x03\x04\x05\x06", 'h', -1, -1, "0x01020304_0506", },
	{ LN, "\xab\xc0\xee\xd8\x1f", 16, -1, -1, "abc0eed81f",
	},
	{ LN, "\x0c\x20\x40", 's', -1, -1, "0sDCBA", },
	{ LN, "\x0c\x20\x40", 's', 0, 7, "---", },
	{ LN, "\x0c\x20\x40", 's', 1, 7, "", },
	{ LN, "\x0c\x20\x40", 's', 2, 7, "0", },
	{ LN, "\x0c\x20\x40", 's', 3, 7, "0s", },
	{ LN, "\x0c\x20\x40", 's', 4, 7, "0sD", },
	{ LN, "\x0c\x20\x40", 's', 5, 7, "0sDC", },
	{ LN, "\x0c\x20\x40", 's', 6, 7, "0sDCB", },
	{ LN, "\x0c\x20\x40", 's', 7, 7, "0sDCBA", },
	{ LN, "\x0c\x20\x40", 's', 8, 7, "0sDCBA", },
	{ LN, "\x0c", 's', -1, -1, "0sDA==", },
	{ LN, "\x0c\x20", 's', -1, -1, "0sDCA=", },
	{ LN, "\x0c\x20\x19", 's', -1, -1, "0sDCAZ", },
	{ LN, "\x0c\x20\x1a", 's', -1, -1, "0sDCAa", },
	{ LN, "\x0c\x20\x33", 's', -1, -1, "0sDCAz", },
	{ LN, "\x0c\x20\x34", 's', -1, -1, "0sDCA0", },
	{ LN, "\x0c\x20\x3d", 's', -1, -1, "0sDCA9", },
	{ LN, "\x0c\x20\x3e", 's', -1, -1, "0sDCA+", },
	{ LN, "\x0c\x20\x3f", 's', -1, -1, "0sDCA/", },
	{ LN, "\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", 's', -1, -1, "0sAbraCadabra+", },
	{ LN, "\x01\xba\xda\x09\xa7\x5a\x6e\xb6\xbe", 64, -1, -1, "AbraCadabra+", },
	{ LN, NULL, 'x', -1, -1, NULL, },
};

/*
 * regress - regression-test ttodata() and datatot()
 */
static void check_ttodata(unsigned line, const struct artab *r,
			  shunk_t ascii, int base,
			  int *status)
{
	char buf[100];
	size_t n;
	err_t oops = ttodata(ascii, base, buf, sizeof(buf), &n);

	if (oops != NULL && r->data == NULL) {
		/* error expected */
	} else if (oops != NULL) {
		printf("+%u +%u %s: ", r->line, line, __FILE__);
		printf("`%s' gave error `%s', expecting %zu `", r->ascii,
		       oops, strlen(r->data));
		hexout(r->data, strlen(r->data), stdout);
		printf("'\n");
		*status = 1;
	} else if (r->data == NULL) {
		printf("+%u +%u %s: ", r->line, line, __FILE__);
		printf("`%s' gave %zu `", r->ascii, n);
		hexout(buf, n, stdout);
		printf("', expecting error\n");
		*status = 1;
	} else if (n != strlen(r->data)) {
		printf("+%u +%u %s: ", r->line, line, __FILE__);
		printf("length wrong in `%s': got %zu `", r->ascii, n);
		hexout(buf, n, stdout);
		printf("', expecting %zu `", strlen(r->data));
		hexout(r->data, strlen(r->data), stdout);
		printf("'\n");
		*status = 1;
	} else if (!memeq(buf, r->data, n)) {
		printf("+%u +%u %s: ", r->line, line, __FILE__);
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
	int status = 0;

	for (const struct artab *r = atodatatab; r->ascii != NULL; r++) {
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

		check_ttodata(LN, r, shunk1(r->ascii),
			      base, &status);
		if (base == 64 || xbase == 64) {
			check_ttodata(LN, r, shunk1(r->ascii),
				      base, &status);
		}

		if (xbase == 0) {
			continue;
		}

		check_ttodata(LN, r, shunk1(r->ascii + 2),
			      xbase, &status);
		if (base == 64 || xbase == 64) {
			check_ttodata(LN, r, shunk1(r->ascii + 2),
				      xbase, &status);
		}
	}

	char buf[100];
	size_t n;

	for (const struct drtab *dr = datatoatab; dr->data != NULL; dr++) {
		strcpy(buf, "---");
		n = datatot(dr->data, strlen(dr->data), dr->format, buf,
			    (dr->buflen == -1) ? sizeof(buf) : (size_t)dr->buflen);
		size_t should = (dr->ascii == NULL) ? 0 : strlen(dr->ascii) + 1;
		if (dr->outlen != -1)
			should = dr->outlen;
		if (n == 0 && dr->ascii == NULL) {
			/* error expected */
		} else if (n == 0) {
			printf("+%u %s: ", dr->line, __FILE__);
			printf("`");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("' %c gave error, expecting %zu `%s'\n",
			       dr->format, should, dr->ascii);
			status = 1;
		} else if (dr->ascii == NULL) {
			printf("+%u %s: ", dr->line, __FILE__);
			printf("`");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("' %c gave %zu `%.*s', expecting error\n",
			       dr->format, n, (int)n, buf);
			status = 1;
		} else if (n != should) {
			printf("+%u %s: ", dr->line, __FILE__);
			printf("length wrong in `");
			hexout(dr->data, strlen(dr->data), stdout);
			printf("': got %zu `%s'", n, buf);
			printf(", expecting %zu `%s'\n", should, dr->ascii);
			status = 1;
		} else if (!streq(buf, dr->ascii)) {
			printf("+%u %s: ", dr->line, __FILE__);
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
