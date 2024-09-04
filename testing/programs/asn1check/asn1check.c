/* Test ASN.1 code, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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
#include <stdint.h>

#include <cert.h>

#include "lswtool.h"		/* for tool_init_log() */

#include "x509.h"
#include "asn1.h"
#include "lswalloc.h"		/* for leak_detective; */

int fails = 0;

#define FAIL(FMT, ...)						\
	{							\
		PRINT(stderr, " FAIL: "FMT,##__VA_ARGS__);	\
		fails++;					\
		continue;					\
	}

static void is_asn1_printablestring_check(void)
{
	static /*const*/ struct test {
		bool ok;
		const char *str;
	} tests[] = {
		{ true, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?", },
		{ true, "", },
		/* 000-037 */
		{ false, "\001", },
		{ false, "\037", },
		/* 040-047 */
		{ true,  " ", },
		{ false, "!", },
		{ false, "\"", },
		{ false, "#", },
		{ false, "$", },
		{ false, "%", },
		{ false, "&", },
		/* 050-057 */
		{ true,  "(", },
		{ true,  ")", },
		{ false, "*", },
		{ true,  "+", },
		{ true,  ",", },
		{ true,  "-", },
		{ true,  ".", },
		{ true,  "/", },
		/* 060-067 */
		{ true,  "01234567", },
		/* 070-077 */
		{ true,  "8", },
		{ true,  "9", },
		{ true,  ":", },
		{ false, ";", },
		{ false, "<", },
		{ true,  "=", },
		{ false, ">", },
		{ true,  "?", },
		/* 100-137 */
		{ false, "@", },
		{ true,  "ABCDEFGHIJKLMNOPQRSTUVWXYZ", },
		{ false, "[", },
		{ false, "\\", },
		{ false, "]", },
		{ false, "^", },
		{ false, "_", },
		/* 140-177 */
		{ false, "`", },
		{ true,  "abcdefghijklmnopqrstuvwxyz", },
		{ false, "{", },
		{ false, "|", },
		{ false, "}", },
		{ false, "~", },
		{ false, "\177", },

		{ false, "\200", },
		{ false, "\377", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		/*const*/ struct test *t = &tests[ti];
#define PRINT(FILE, FMT, ...)						\
		{							\
			fprintf(FILE, "%s[%zu]:", __func__, ti);	\
			if (char_isprint(t->str[0])) {			\
				fprintf(FILE, " \"%s\"", t->str);	\
			} else {					\
				fprintf(FILE, "%4o", (unsigned char)t->str[0]);	\
			}						\
			fprintf(FILE, "->%s", bool_str(t->ok));		\
			fprintf(FILE, FMT"\n", ##__VA_ARGS__);		\
		}

		PRINT(stdout, "");
		shunk_t str = shunk1(t->str);

		bool ok = is_asn1_printablestring(str);
		if (ok != t->ok) {
			FAIL("returned %s", bool_str(ok));
		}
#undef PRINT
	}
}

static void unwrap_asn1_length_check(void)
{
	static /*const*/ struct test {
		bool ok;
		size_t length;
		struct {
			size_t len;
			uint8_t ptr[512];
		} hunk;
		size_t left;
	} tests[] = {
		/* 1+0 byte length is 0 */
		{ false, .hunk = { 0, { 0, }, }, .length = 0, .left = 0, },
		{ true,  .hunk = { 1, { 0, }, }, .length = 0, .left = 0, },
		{ true,  .hunk = { 2, { 0, }, }, .length = 0, .left = 1, },
		/* 1+0 byte length is 1 */
		{ false, .hunk = { 0, { 1, }, }, .length = 0, .left = 0, },
		{ false, .hunk = { 1, { 1, }, }, .length = 0, .left = 0, },
		{ true,  .hunk = { 2, { 1, }, }, .length = 1, .left = 1, },
		/* 1+0 byte length is 127 */
		{ false, .hunk = { 127, { 127, }, }, .length = 0, .left = 126, },
		{ true,  .hunk = { 128, { 127, }, }, .length = 127, .left = 127, },
		{ true,  .hunk = { 129, { 127, }, }, .length = 127, .left = 128, },
		/* 1+1 byte length is 1 */
		{ false, .hunk = { 1, { 0x81, 1, }, }, .length = 0, .left = 0, },
		{ false, .hunk = { 2, { 0x81, 1, }, }, .length = 0, .left = 0, },
		{ true,  .hunk = { 3, { 0x81, 1, }, }, .length = 1, .left = 1, },
		{ true,  .hunk = { 4, { 0x81, 1, }, }, .length = 1, .left = 2, },
		/* 1+1 byte length is 255 */
		{ false, .hunk = { 256, { 0x81, 255, }, }, .length = 0, .left = 254, },
		{ true,  .hunk = { 257, { 0x81, 255, }, }, .length = 255, .left = 255, },
		{ true,  .hunk = { 258, { 0x81, 255, }, }, .length = 255, .left = 256, },
		/* 1+2 byte length is 258 */
		{ false, .hunk = { 1, { 0x82, 1, 2, }, }, .length = 0, .left = 0, },
		{ false, .hunk = { 2, { 0x82, 1, 2, }, }, .length = 0, .left = 1, },
		{ false, .hunk = { 3, { 0x82, 1, 2, }, }, .length = 0, .left = 0, },
		{ false, .hunk = { 260, { 0x82, 1, 2, }, }, .length = 0, .left = 257, },
		{ true,  .hunk = { 261, { 0x82, 1, 2, }, }, .length = 258, .left = 258, },
		{ true,  .hunk = { 262, { 0x82, 1, 2, }, }, .length = 258, .left = 259, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		/*const*/ struct test *t = &tests[ti];

#define PRINT(FILE, FMT, ...)						\
		{							\
			fprintf(FILE, "%s[%zu]:", __func__, ti);	\
			fprintf(FILE, " ok=%s length=%zd left=%zd hunk(%zu):", \
				bool_str(t->ok), t->length, t->left, t->hunk.len); \
			for (unsigned u = 0; u < t->hunk.len; u++) {	\
				fprintf(FILE, " %02x", t->hunk.ptr[u]);	\
			}						\
			fprintf(FILE, FMT"\n", ##__VA_ARGS__);		\
		}

		PRINT(stdout, "");

		if (t->hunk.len > sizeof(t->hunk.ptr)) {
			FAIL("buffer overflow");
		}

		asn1_t bytes = { .ptr = t->hunk.ptr, .len = t->hunk.len, };

		size_t length;
		err_t e = unwrap_asn1_length(&bytes, &length);

		if (e != NULL) {
			if (t->ok) {
				FAIL("unexpected error: %s", e);
			} else {
				/* expected */
				continue;
			}
		} else if (!t->ok) {
			FAIL("unexpectedly succeeded");
		}

		if (t->left != bytes.len) {
			FAIL("returned left %zu, expecting %zu", bytes.len, t->left);
		}

		if (t->length != length) {
			FAIL("returned length %zu, expecting %zu", length, t->length);
		}


	}
}

int main(int argc UNUSED, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	is_asn1_printablestring_check();
	unwrap_asn1_length_check();

	if (report_leaks(logger)) {
		fails++;
	}

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	}

	return 0;
}
