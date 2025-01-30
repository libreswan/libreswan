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

#include "jambuf.h"		/* for struct jambuf */
#include "constants.h"		/* for streq() */
#include "lswalloc.h"		/* for leaks */
#include "lswtool.h"		/* for tool_init_log() */

unsigned fails;

static void check_jambuf(bool ok, const char *expect, ...)
{
	const char *oks =  ok ? "true" : "false";
	for (int i = 0; i < 3; i++) {
		static const char *const ops[] = { "jam", "jam_str", "jam_char" };
		const char *op = ops[i];
		printf("%s: %s '%s' %s\n", __func__, op, expect, oks);
		/* 10 characters + NUL + SENTINEL */
		char array[12] = {
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
			'k', 'l'
		};
		struct jambuf buf = ARRAY_AS_JAMBUF(array);
#define FAIL(FMT, ...)							\
		{							\
			fprintf(stderr, "%s: %s '%s' ", __func__, op, expect); \
			fprintf(stderr, FMT,##__VA_ARGS__);		\
			fprintf(stderr, "\n");				\
			fails++;					\
			return;						\
		}

		/*
		 * XXX: because coverity can't see ARRAY_AS_JAMBUF()
		 * setting ARRAY[-2]=NUL and ARRAY[-1]=SENTINEL it
		 * complains that the ARRAY is overrun.
		 *
		 * This hopefully drops a hint.
		 */
		if (array[sizeof(array)-2] != '\0') {
			FAIL("array[-2] != NUL");
		}
		/*
		 * Buffer initialized ok?
		 */
		if (!jambuf_ok(&buf)) {
			FAIL("jambuf_ok() failed at start");
		}
		if (array[0] != '\0') {
			FAIL("array[0] is 0x%x but should be NUL at start\n",
			     array[0]);
		}
		const char *pos = jambuf_cursor(&buf);
		if (pos != array) {
			FAIL("jambuf_cursor() is %p but should be %p (aka array) at start",
			     pos, array);
		}
		shunk_t shunk = jambuf_as_shunk(&buf);
		if ((const char *)shunk.ptr != array ||
		    shunk.len != 0) {
			FAIL("jambuf_as_shunk() is "PRI_SHUNK" but should be %p/0 (aka array) at start",
			     pri_shunk(shunk), array);
		}
		/*
		 * Concat va_list.
		 *
		 * Terminated with NULL, it is a series of strings -
		 * and the string can be NULL!
		 */
		va_list ap;
		va_start(ap, expect);
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
	struct jambuf buf = ARRAY_AS_JAMBUF(array);

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
	struct jambuf buf = ARRAY_AS_JAMBUF(outbuf);
	jam_bytes(&buf, in, size);
	if (!streq(outbuf, out)) {
		fprintf(stderr, "%s: %s('%s') failed, expecting '%s' returned '%s'\n", __func__,
			what, in, out, outbuf);
	}
}

int main(int argc UNUSED, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	check_jambuf(true, "(null)", NULL, NULL);
	check_jambuf(true, "0", "0", NULL);
	check_jambuf(true, "01", "0", "1", NULL);
	check_jambuf(true, "012", "0", "1", "2", NULL);
	check_jambuf(true, "0123", "0", "1", "2", "3", NULL);
	check_jambuf(true, "01234", "0", "1", "2", "3", "4", NULL);
	check_jambuf(true, "012345", "0", "1", "2", "3", "4", "5", NULL);
	check_jambuf(true, "0123456", "0", "1", "2", "3", "4", "5", "6", NULL);
	check_jambuf(true, "01234567", "0", "1", "2", "3", "4", "5", "6", "7", NULL);
	check_jambuf(true, "012345678", "0", "1", "2", "3", "4", "5", "6", "7", "8", NULL);
	check_jambuf(true, "0123456789", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", NULL);

	check_jambuf(true, "0123456789", "0123456789", NULL);
	check_jambuf(true, "0123456789", "0123456789", "", NULL);
	check_jambuf(true, "0123456789", "", "0123456789", NULL);
	check_jambuf(true, "0123456789", "012345678", "9", NULL);
	check_jambuf(true, "0123456789", "012345678", "9", "", NULL);
	check_jambuf(true, "0123456789", "012345678", "", "9", NULL);

	check_jambuf(false, "0123456...", "0123456789-", NULL);
	check_jambuf(false, "0123456...", "0123456789-", "", NULL);
	check_jambuf(false, "0123456...", "", "0123456789-", NULL);
	check_jambuf(false, "0123456...", "0123456789", "-", NULL);
	check_jambuf(false, "0123456...", "0123456789", "-", NULL);
	check_jambuf(false, "0123456...", "0123456789", "-", "", NULL);
	check_jambuf(false, "0123456...", "0123456789", "", "-", NULL);

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
	check_jam_bytes(FN(sanitized), BYTES, "\\t !\"#$%&'()*+,-./:;<=>?@[\\^+`{|}~\\0");
	check_jam_bytes(FN(shell_quoted), BYTES, "\\011 !\\042#\\044%&\\047()*+,-./:;<=>?@[\\134^+\\140{|}~\\000");
#undef FN
#undef BYTES

#define check_sanitized(S, E) check_jam_bytes("sanitized", jam_sanitized_bytes, S, sizeof(S)-1, E)

	check_sanitized("\a\b\f\n\r\t\v", "\\a\\b\\f\\n\\r\\t\\v");
	check_sanitized("\001", "\\1");
	check_sanitized("\0019", "\\0019");
	check_sanitized("\001a", "\\1a");
	check_sanitized("\177", "\\177");
	check_sanitized("\1779", "\\1779");
	check_sanitized("\177a", "\\177a");

#define check_ucase(S, E) check_jam_bytes("ucase", jam_uppercase_bytes, S, sizeof(S)-1, E)

	check_ucase("aBc", "ABC");
	check_ucase("a_B", "A_B");

	if (report_leaks(logger)) {
		fails++;
	}

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	} else {
		return 0;
	}
}
