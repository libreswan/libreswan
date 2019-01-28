/* test fmtbuf_t, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "fmtbuf.h" /* fmtbuf_t */

unsigned fails;

static void check_fmtbuf(const char *expect, bool ok, ...)
{
	const char *oks =  ok ? "true" : "false";
	for (int i = 0; i < 2; i++) {
		const char *op = i == 0 ? "fmt" : "fmt_string";
		printf("%s: %s '%s' %s\n", __func__, op, expect, oks);
		char array[12]; /* 10 characters + NUL + SENTINEL */
		fmtbuf_t buf = ARRAY_AS_FMTBUF(array);
		if (!fmtbuf_ok(&buf)) {
			fprintf(stderr, "%s: '%s' setup wrong\n",
				__func__, expect);
			fails++;
			return;
		}
		va_list ap;
		va_start(ap, ok);
		while (true) {
			const char *str = va_arg(ap, char *);
			if (str == NULL) break;
			switch (i) {
			case 0: fmt(&buf, "%s", str); break;
			case 1: fmt_string(&buf, str); break;
			}
			if (ok && !fmtbuf_ok(&buf)) {
				fprintf(stderr, "%s: %s '%s' %s unexpectedly failed writing '%s'\n",
					__func__, op, expect, oks, str);
				fails++;
				return;
			}
		}
		if (fmtbuf_ok(&buf) != ok) {
			fprintf(stderr, "%s: %s '%s' %s wrong\n",
				__func__, op, expect, oks);
			fails++;
			return;
		}
		if (strcmp(expect, array) != 0) {
			fprintf(stderr, "%s: %s '%s' %s but got string '%s'\n",
				__func__, op, expect, oks, array);
			fails++;
			return;
		}
		chunk_t c = fmtbuf_as_chunk(&buf);
		if (c.len != strlen(expect) + 1 ||
		    memcmp(expect, c.ptr, c.len) != 0) {
			fprintf(stderr, "%s: %s '%s' %s but got chunk '%s'\n",
				__func__, op, expect, oks, array);
			fails++;
			return;
		}
	}
}

int main(int argc UNUSED, char *argv[] UNUSED)
{
	check_fmtbuf("0", true, "0", NULL);
	check_fmtbuf("01", true, "0", "1", NULL);
	check_fmtbuf("012", true, "0", "1", "2", NULL);
	check_fmtbuf("0123", true, "0", "1", "2", "3", NULL);
	check_fmtbuf("01234", true, "0", "1", "2", "3", "4", NULL);
	check_fmtbuf("012345", true, "0", "1", "2", "3", "4", "5", NULL);
	check_fmtbuf("0123456", true, "0", "1", "2", "3", "4", "5", "6", NULL);
	check_fmtbuf("01234567", true, "0", "1", "2", "3", "4", "5", "6", "7", NULL);
	check_fmtbuf("012345678", true, "0", "1", "2", "3", "4", "5", "6", "7", "8", NULL);
	check_fmtbuf("0123456789", true, "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", NULL);

	check_fmtbuf("0123456789", true, "0123456789", NULL);
	check_fmtbuf("0123456789", true, "0123456789", "", NULL);
	check_fmtbuf("0123456789", true, "", "0123456789", NULL);
	check_fmtbuf("0123456789", true, "012345678", "9", NULL);
	check_fmtbuf("0123456789", true, "012345678", "9", "", NULL);
	check_fmtbuf("0123456789", true, "012345678", "", "9", NULL);

	check_fmtbuf("0123456...", false, "0123456789-", NULL);
	check_fmtbuf("0123456...", false, "0123456789-", "", NULL);
	check_fmtbuf("0123456...", false, "", "0123456789-", NULL);
	check_fmtbuf("0123456...", false, "0123456789", "-", NULL);
	check_fmtbuf("0123456...", false, "0123456789", "-", NULL);
	check_fmtbuf("0123456...", false, "0123456789", "-", "", NULL);
	check_fmtbuf("0123456...", false, "0123456789", "", "-", NULL);
	if (fails > 0) {
		return 1;
	} else {
		return 0;
	}
}
