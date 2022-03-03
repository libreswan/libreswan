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

int fails = 0;

#define FAIL(FMT, ...)				\
	PRINT(stderr, FMT,##__VA_ARGS__);	\
	fails++;				\
	continue;

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
			fprintf(FILE, "->%s"FMT"\n",			\
				bool_str(t->ok), ##__VA_ARGS__);	\
		}

		PRINT(stdout, "");
		shunk_t str = shunk1(t->str);

		bool ok = is_asn1_printablestring(str);
		if (ok != t->ok) {
			FAIL(" FAIL: returned %s", bool_str(ok));
		}
	}
}

int main(int argc UNUSED, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_init_log(argv[0]);

	is_asn1_printablestring_check();

	if (report_leaks(logger)) {
		fails++;
	}

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	}

	return 0;
}
