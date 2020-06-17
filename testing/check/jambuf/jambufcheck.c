/* test jambuf_t, for libreswan
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

#include "jambuf.h"		/* for jambuf_t */
#include "constants.h"		/* for streq() */

unsigned fails;

static void check_jambuf(const char *expect, bool ok, ...)
{
	const char *oks =  ok ? "true" : "false";
	for (int i = 0; i < 3; i++) {
		const char *op = (i == 0 ? "jam" :
				  i == 1 ? "jam_string" :
				  i == 2 ? "jam_char" :
				  "???");
		printf("%s: %s '%s' %s\n", __func__, op, expect, oks);
		/* 10 characters + NUL + SENTINEL */
		char array[12] = "abcdefghijkl";
		jambuf_t buf = ARRAY_AS_JAMBUF(array);
#define FAIL(FMT, ...) {						\
			fprintf(stderr, "%s: %s '%s' ", __func__, op, expect); \
			fprintf(stderr, FMT,##__VA_ARGS__);		\
			fprintf(stderr, "\n");				\
			fails++;					\
		}
		/*
		 * Buffer initialized ok?
		 */
		if (!jambuf_ok(&buf)) {
			FAIL("jambuf_ok() failed at start");
			return;
		}
		if (array[0] != '\0') {
			FAIL("array[0] is 0x%x but should be NUL at start\n",
			     array[0]);
			return;
		}
		const char *pos = jambuf_cursor(&buf);
		if (pos != array) {
			FAIL("jambuf_cursor() is %p but should be %p (aka array) at start",
			     pos, array);
			return;
		}
		shunk_t shunk = jambuf_as_shunk(&buf);
		if ((const char *)shunk.ptr != array ||
		    shunk.len != 0) {
			FAIL("jambuf_as_shunk() is "PRI_SHUNK" but should be %p/0 (aka array) at start",
			     pri_shunk(shunk), array);
			return;
		}
		/*
		 * Concat va_list.
		 *
		 * Terminated with NULL, it is a series of strings -
		 * and the string can be NULL!
		 */
		va_list ap;
		va_start(ap, ok);
		const char *str = va_arg(ap, const char *);
		do {
			if (str == NULL) {
				/* only valid op */
				jam_string(&buf, str);
			} else {
				switch (i) {
				case 0:
					jam(&buf, "%s", str);
					break;
				case 1:
					jam_string(&buf, str);
					break;
				case 2:
					for (const char *c = str; *c; c++) {
						jam_char(&buf, *c);
					}
					break;
				default:
					FAIL("bad case");
					return;
				}
			}
			if (ok && !jambuf_ok(&buf)) {
				FAIL("unexpectedly failed writing '%s'",
				     str == NULL ? "(null)" : str);
				return;
			}
			str = va_arg(ap, const char *);
		} while (str != NULL);
		va_end(ap);
		if (jambuf_ok(&buf) != ok) {
			FAIL("jambuf_ok() is not %s at end", oks);
			return;
		}
		if (strcmp(expect, array) != 0) {
			FAIL("array contains '%s' which is wrong", array);
			return;
		}
		shunk = jambuf_as_shunk(&buf);
		if ((const char *)shunk.ptr != array ||
		    shunk.len != strlen(expect) ||
		    memcmp(expect, shunk.ptr, shunk.len) != 0) {
			FAIL("jambuf_as_shunk() is "PRI_SHUNK" which is wrong",
			     pri_shunk(shunk));
			return;
		}
		pos = jambuf_cursor(&buf);
		if (pos != array + strlen(expect)) {
			FAIL("jambuf_cursor() is %p but should be %p",
			     pos, array + strlen(expect));
			return;
		}
	}
#undef FAIL
}

static void check_jambuf_pos(const char *pre, const char *pre_expect,
			     const char *post, const char *post_expect,
			     const char *set_expect)
{
	fprintf(stdout, "%s: %s -> '%s' + '%s' -> '%s' |-> '%s'",	\
		__func__,						\
		pre, pre_expect,					\
		post, post_expect, set_expect);
	fprintf(stdout, "\n");
#define FAIL(FMT, ...) {						\
		fprintf(stderr, "%s: %s -> '%s' + '%s' -> '%s' |-> '%s'", \
			__func__,					\
			pre, pre_expect,				\
			post, post_expect, set_expect);			\
		fprintf(stderr, FMT,##__VA_ARGS__);			\
		fprintf(stderr, "\n");					\
		fails++;						\
		return;							\
	}

	char array[5/*stuff*/+2/*NUL+CANARY*/];
	jambuf_t buf = ARRAY_AS_JAMBUF(array);

	jam_string(&buf, pre);
	if (!streq(array, pre_expect)) {
		FAIL(" pre failed '%s'", array);
	}

	jampos_t pos = jambuf_get_pos(&buf);

	jam_string(&buf, post);
	if (!streq(array, post_expect)) {
		FAIL(" post get_pos() failed '%s'", array);
	}

	jambuf_set_pos(&buf, &pos);
	if (!streq(array, set_expect)) {
		FAIL(" post set_pos() failed, '%s'", array);
	}
}

static void check_jam_bytes(const char *what, jam_bytes_fn *jam_bytes,
			    const char *in, size_t size,
			    const char *out)
{
	fprintf(stdout, "%s: %s('%s') -> '%s'\n", __func__, what, in, out);
	char outbuf[1024];
	jambuf_t buf = ARRAY_AS_JAMBUF(outbuf);
	jam_bytes(&buf, in, size);
	if (!streq(outbuf, out)) {
		fprintf(stderr, "%s: %s('%s') failed, expecting '%s' returned '%s'\n", __func__,
			what, in, out, outbuf);
	}
}

int main(int argc UNUSED, char *argv[] UNUSED)
{
	check_jambuf("(null)", true, NULL, NULL);
	check_jambuf("0", true, "0", NULL);
	check_jambuf("01", true, "0", "1", NULL);
	check_jambuf("012", true, "0", "1", "2", NULL);
	check_jambuf("0123", true, "0", "1", "2", "3", NULL);
	check_jambuf("01234", true, "0", "1", "2", "3", "4", NULL);
	check_jambuf("012345", true, "0", "1", "2", "3", "4", "5", NULL);
	check_jambuf("0123456", true, "0", "1", "2", "3", "4", "5", "6", NULL);
	check_jambuf("01234567", true, "0", "1", "2", "3", "4", "5", "6", "7", NULL);
	check_jambuf("012345678", true, "0", "1", "2", "3", "4", "5", "6", "7", "8", NULL);
	check_jambuf("0123456789", true, "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", NULL);

	check_jambuf("0123456789", true, "0123456789", NULL);
	check_jambuf("0123456789", true, "0123456789", "", NULL);
	check_jambuf("0123456789", true, "", "0123456789", NULL);
	check_jambuf("0123456789", true, "012345678", "9", NULL);
	check_jambuf("0123456789", true, "012345678", "9", "", NULL);
	check_jambuf("0123456789", true, "012345678", "", "9", NULL);

	check_jambuf("0123456...", false, "0123456789-", NULL);
	check_jambuf("0123456...", false, "0123456789-", "", NULL);
	check_jambuf("0123456...", false, "", "0123456789-", NULL);
	check_jambuf("0123456...", false, "0123456789", "-", NULL);
	check_jambuf("0123456...", false, "0123456789", "-", NULL);
	check_jambuf("0123456...", false, "0123456789", "-", "", NULL);
	check_jambuf("0123456...", false, "0123456789", "", "-", NULL);

	/* st... */

	check_jambuf_pos("", "", "", "", "");
	check_jambuf_pos("s", "s", "", "s", "s");
	check_jambuf_pos("st", "st", "", "st", "st");
	check_jambuf_pos("stu", "stu", "", "stu", "stu");
	check_jambuf_pos("stuf", "stuf", "", "stuf", "stuf");
	check_jambuf_pos("stuff", "stuff", "", "stuff", "stuff");

	check_jambuf_pos("", "", "o", "o", "");
	check_jambuf_pos("s", "s", "o", "so", "s");
	check_jambuf_pos("st", "st", "o", "sto", "st");
	check_jambuf_pos("stu", "stu", "o", "stuo", "stu");
	check_jambuf_pos("stuf", "stuf", "o", "stufo", "stuf");
	check_jambuf_pos("stuff", "stuff", "o", "st...", "st...");

	check_jambuf_pos("", "", "ov", "ov", "");
	check_jambuf_pos("s", "s", "ov", "sov", "s");
	check_jambuf_pos("st", "st", "ov", "stov", "st");
	check_jambuf_pos("stu", "stu", "ov", "stuov", "stu");
	check_jambuf_pos("stuf", "stuf", "ov", "st...", "st...");

	check_jambuf_pos("", "", "ove", "ove", "");
	check_jambuf_pos("s", "s", "ove", "sove", "s");
	check_jambuf_pos("st", "st", "ove", "stove", "st");
	check_jambuf_pos("stu", "stu", "ove", "st...", "st...");

	check_jambuf_pos("", "", "over", "over", "");
	check_jambuf_pos("s", "s", "over", "sover", "s");
	check_jambuf_pos("st", "st", "over", "st...", "st");
	check_jambuf_pos("stu", "stu", "over", "st...", "st...");

	check_jambuf_pos("", "", "overf", "overf", "");
	check_jambuf_pos("s", "s", "overf", "so...", "s");
	check_jambuf_pos("st", "st", "overf", "st...", "st");
	check_jambuf_pos("stu", "stu", "overf", "st...", "st...");

	check_jambuf_pos("", "", "overfl", "ov...", "");
	check_jambuf_pos("s", "s", "overf", "so...", "s");
	check_jambuf_pos("st", "st", "overf", "st...", "st");
	check_jambuf_pos("stu", "stu", "overf", "st...", "st...");

	check_jambuf_pos("", "", "overfull", "ov...", "");
	check_jambuf_pos("s", "s", "overfull", "so...", "s");
	check_jambuf_pos("st", "st", "overfull", "st...", "st");
	check_jambuf_pos("stu", "stu", "overfull", "st...", "st...");
	check_jambuf_pos("stuf", "stuf", "overfull", "st...", "st...");
	check_jambuf_pos("stuff", "stuff", "overfull", "st...", "st...");

	/* jam_bytes() */

	/* use sizeof so '\0' is included */
	static const char in[] = "\t !\"#$%&'()*+,-./:;<=>?@[\\^+`{|}~";
#define BYTES in, sizeof(in)
#define FN(X) #X, jam_##X##_bytes
	check_jam_bytes(FN(HEX), BYTES, "09202122232425262728292A2B2C2D2E2F3A3B3C3D3E3F405B5C5E2B607B7C7D7E00");
	check_jam_bytes(FN(hex), BYTES, "09202122232425262728292a2b2c2d2e2f3a3b3c3d3e3f405b5c5e2b607b7c7d7e00");
	check_jam_bytes(FN(dump), BYTES, "09 20 21 22  23 24 25 26  27 28 29 2a  2b 2c 2d 2e  2f 3a 3b 3c  3d 3e 3f 40  5b 5c 5e 2b  60 7b 7c 7d  7e 00");
	check_jam_bytes(FN(raw), BYTES, "\t !\"#$%&'()*+,-./:;<=>?@[\\^+`{|}~");
	check_jam_bytes(FN(sanitized), BYTES, "\\011 !\"#$%&'()*+,-./:;<=>?@[\\^+`{|}~\\000");
	check_jam_bytes(FN(meta_escaped), BYTES, "\\011 !\\042#\\044%&\\047()*+,-./:;<=>?@[\\134^+\\140{|}~\\000");
#undef FN
#undef BYTES

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	} else {
		return 0;
	}
}
