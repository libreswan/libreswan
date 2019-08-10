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

#include "jambuf.h" /* jambuf_t */

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
		const char *pos = jambuf_pos(&buf);
		if (pos != array) {
			FAIL("jambuf_pos() is %p but should be %p (aka array) at start",
			     pos, array);
			return;
		}
		chunk_t chunk = jambuf_as_chunk(&buf);
		if ((const char *)chunk.ptr != array ||
		    chunk.len != 1) {
			FAIL("jambuf_as_chunk() is "PRI_CHUNK" but should be %p/1 (aka array) at start",
			     pri_chunk(chunk), array);
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
		if (jambuf_ok(&buf) != ok) {
			FAIL("jambuf_ok() is not %s at end", oks);
			return;
		}
		if (strcmp(expect, array) != 0) {
			FAIL("array contains '%s' which is wrong", array);
			return;
		}
		chunk = jambuf_as_chunk(&buf);
		if ((const char *)chunk.ptr != array ||
		    chunk.len != strlen(expect) + 1 ||
		    memcmp(expect, chunk.ptr, chunk.len) != 0) {
			FAIL("jambuf_as_chunk() is "PRI_CHUNK" or '%s' which is wrong",
			     pri_chunk(chunk), chunk.ptr);
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
		pos = jambuf_pos(&buf);
		if (pos != array + strlen(expect)) {
			FAIL("jambuf_pos() is %p but should be %p",
			     pos, array + strlen(expect));
			return;
		}
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

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	} else {
		return 0;
	}
}
