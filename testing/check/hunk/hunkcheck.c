/* test shunk_t, for libreswan
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

#include "constants.h"		/* for str_bool() */
#include "lswcdefs.h"		/* for elemsof() */
#include "shunk.h"
#include "chunk.h"
#include "where.h"

unsigned fails;

#define PRINTLN(FILE, FMT, ...)						\
	fprintf(FILE, "%s[%zu]:"FMT"\n",				\
		__func__, ti,##__VA_ARGS__)

#define PRINT_LR(FILE, FMT, ...)					\
	fprintf(FILE, "%s[%zu]: '%s' vs '%s'" FMT "\n",			\
		__func__, ti,						\
		t->l == NULL ? "NULL" : t->l,				\
		t->r == NULL ? "NULL" : t->r,				\
		##__VA_ARGS__);

#define FAIL(FMT, ...)						\
	{							\
		fails++;					\
		PRINTLN(stderr, " "FMT,##__VA_ARGS__);		\
		continue;					\
	}

#define FAIL_LR(FMT, ...)					\
	{							\
		fails++;					\
		PRINT_LR(stderr, ": "FMT,##__VA_ARGS__);	\
		continue;					\
	}

#define PRINT_S(FILE, FMT, ...)						\
	fprintf(FILE, "%s[%zu]: '%s'" FMT "\n",				\
		__func__, ti,						\
		t->s == NULL ? "NULL" : t->s,				\
		##__VA_ARGS__);

#define FAIL_S(FMT, ...)					\
	{							\
		fails++;					\
		PRINT_S(stderr, ": "FMT,##__VA_ARGS__);	\
		continue;					\
	}

static void check_hunk_eq(void)
{
	static const struct test {
		const char *l;
		const char *r;
		bool empty;
		bool eq;
		bool caseeq;
		bool starteq;
		bool casestarteq;
		bool thingeq;
	} tests[] = {
		/*
		 * Like strings, NULL and EMPTY ("") shunks are
		 * considered different.
		 */
		{ NULL, NULL, .empty = false, .eq = true,  .caseeq = true,  .starteq = true,  .casestarteq = true,  .thingeq = false, },
		{ NULL, "",   .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, },
		{ "", NULL,   .empty = true,  .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, },
		{ "", "",     .empty = true,  .eq = true,  .caseeq = true,  .starteq = true,  .casestarteq = true,  .thingeq = false, },

		{ "", "a",    .empty = true,  .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, },
		{ "a", "",    .empty = false, .eq = false, .caseeq = false, .starteq = true,  .casestarteq = true,  .thingeq = false, },

		{ "a", "a",   .empty = false, .eq = true,  .caseeq = true,  .starteq = true,  .casestarteq = true,  .thingeq = false, },
		{ "a", "A",   .empty = false, .eq = false, .caseeq = true,  .starteq = false, .casestarteq = true,  .thingeq = false, },
		{ "A", "a",   .empty = false, .eq = false, .caseeq = true,  .starteq = false, .casestarteq = true,  .thingeq = false, },
		{ "a", "b",   .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, },

		{ "a", "aa",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, },
		{ "A", "aa",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, },
		{ "ab", "a",  .empty = false, .eq = false, .caseeq = false, .starteq = true,  .casestarteq = true,  .thingeq = false, },
		{ "AB", "a",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = true,  .thingeq = false, },
		{ "ab", "A",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = true,  .thingeq = false, },
		{ "ab", "b",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, },

		{ "thing", "a", .empty = false, .eq = false, .caseeq = false, .thingeq = true, },
	};

	static const struct {
		char t, h, i, n, g;
	} thing = { 't', 'h', 'i', 'n', 'g', };

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_LR(stdout, "");
		shunk_t l = shunk1(t->l);
		shunk_t r = shunk1(t->r);

		{
			bool t_null = hunk_eq(l, null_shunk);
			if ((t->l == NULL) != t_null) {
				FAIL_LR("hunk_eq(l, null_shunk) returned %s, expecting %s",
					bool_str(t_null), bool_str(t->l == NULL));
			}
		}

		{
			bool t_empty = hunk_eq(l, empty_shunk);
			if (t->empty != t_empty) {
				FAIL_LR("hunk_eq(l, empty_shunk) returned %s, expecting %s",
					bool_str(t_empty), bool_str(t->empty));
			}
		}

#define HUNK_EQ(OP)							\
		{							\
			bool eq = hunk_##OP(l, r);			\
			if (eq != t->OP) {				\
				FAIL_LR("hunk_"#OP"() returned %s, expecting %s", \
					bool_str(eq), bool_str(t->OP));	\
			}						\
		}							\
		{							\
			bool eq = hunk_str##OP(l, t->r);		\
			if (eq != t->OP) {				\
				FAIL_LR("hunk_str"#OP"() returned %s, expecting %s", \
					bool_str(eq), bool_str(t->OP));	\
			}						\
		}
		HUNK_EQ(eq);
		HUNK_EQ(caseeq);
		HUNK_EQ(starteq);
		HUNK_EQ(casestarteq);
#undef HUNK_EQ

		{
			bool t_memeq = hunk_memeq(l, r.ptr, r.len);
			if (t_memeq != t->eq) {
				FAIL_LR("hunk_memeq() returned %s, expecting %s",
					bool_str(t_memeq), bool_str(t->eq));
			}
		}

		{
			bool t_thing = hunk_thingeq(l, thing);
			if (t_thing != t->thingeq) {
				FAIL_LR("hunk_thingeq() returned %s, expecting %s",
					bool_str(t_thing), bool_str(t->thingeq));
			}
		}

	}
}

static void shunk_slice_check(void)
{
	static const struct test {
		const char *l;
		const char *r;
		int lo, hi;
	} tests[] = {
		{ "", "", 0, 0, },

		{ "012", "", 0, 0, },
		{ "012", "0", 0, 1, },
		{ "012", "01", 0, 2, },
		{ "012", "012", 0, 3, },

		{ "012", "", 1, 1, },
		{ "012", "1", 1, 2, },
		{ "012", "12", 1, 3, },

		{ "012", "", 2, 2, },
		{ "012", "2", 2, 3, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_LR(stdout, " lo=%d hi=%d", t->lo, t->hi);
		shunk_t l = shunk1(t->l);
		shunk_t r = shunk1(t->r);

		shunk_t t_slice = shunk_slice(l, t->lo, t->hi);
		if (!hunk_eq(r, t_slice)) {
			FAIL_LR("shunk_slice() returned '"PRI_SHUNK"', expecting '"PRI_SHUNK"'",
				pri_shunk(t_slice), pri_shunk(r));
		}
	}
}

static void shunk_token_check(void)
{
	static const struct test {
		const char *s;
		const char *token;
		char delim;
		const char *input;
		const char *delims;
	} tests[] = {
		/* termination */
		{ "", "", '\0', NULL, ",", },
		{ "a", "a", '\0', NULL, ",", },
		{ NULL, NULL, '\0', NULL, ",", },

		/* empty tokens */
		{ ",", "", ',', "", ",", },
		{ ",", "", ',', "", ":,", },
		{ ":", "", ':', "", ":,", },

		/* non empty tokens */
		{ "a,b", "a", ',', "b", ",", },
		{ "a,b", "a", ',', "b", ":,", },
		{ "a:b", "a", ':', "b", ":,", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_S(stdout, " token='%s' delim='%c' delims=%s (new)input=%s",
			t->token == NULL ? "NULL" : t->token,
			t->delim, t->delims,
			t->input == NULL ? "NULL" : t->input);
		shunk_t s = shunk1(t->s);
		shunk_t t_input = s;

		char t_delim = -1;
		shunk_t t_token = shunk_token(&t_input, &t_delim, t->delims);

		if (!hunk_eq(t_token, shunk1(t->token))) {
			FAIL_S("shunk_token() returned token '"PRI_SHUNK"', expecting '%s'",
				pri_shunk(t_token), t->token);
		}

		if (t_delim != t->delim) {
			FAIL_S("shunk_token() returned delim '%c', expecting '%c'",
			       t_delim, t->delim);
		}

		if (!hunk_eq(t_input, shunk1(t->input))) {
			FAIL_S("shunk_token() returned input '"PRI_SHUNK"', expecting '%s'",
				pri_shunk(t_input),
			       t->input == NULL ? "NULL" : t->input);
		}
	}
}

static void shunk_span_check(void)
{
	static const struct test {
		/* span(&old->new, delim, accept)->token */
		const char *old;
		const char *accept;
		const char *token;
		const char *new;
	} tests[] = {
		/* termination */
		{ "",   ",", "",   NULL, }, /* token=NULL instead? */
		{ "a",  "a", "a",  NULL, },
		{ NULL, ",", NULL, NULL, },

		/* empty spans */
		{ ",a",  "a",  "", ",a", },

		/* non empty spans */
		{ "a,b", "a",  "a",  ",b", },
		{ "a,b", "a,", "a,", "b", },
		{ "a,b", "ba", "a",  ",b", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINTLN(stdout, " old='%s' accept='%s' -> token='%s' new='%s'",
			t->old, t->accept, t->token, t->token);

		shunk_t t_input = shunk1(t->old);
		shunk_t t_token = shunk_span(&t_input, t->accept);

		if (!hunk_eq(t_token, shunk1(t->token))) {
			FAIL("shunk_span() returned token '"PRI_SHUNK"', expecting '%s'",
			     pri_shunk(t_token), t->token);
		}

		if (!hunk_eq(t_input, shunk1(t->new))) {
			FAIL("shunk_span() returned new input '"PRI_SHUNK"', expecting '%s'",
			     pri_shunk(t_input), t->new);
		}
	}
}

static void shunk_clone_check(void)
{
	static const struct test {
		const char *s;
	} tests[] = {
		/*
		 * Like strings, NULL and EMPTY ("") shunks are
		 * considered different.
		 */
		{ NULL, },
		{ "", },
		{ "a", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_S(stdout, "");
		shunk_t s = shunk1(t->s);
		chunk_t c = clone_hunk(s, "c");
		if (c.len != s.len) {
			FAIL_S("clone_hunk(s).len returned %zu, expecting %zu",
			       c.len, s.len);
		}
		if (c.ptr == NULL && s.ptr != NULL) {
			FAIL_S("clone_hunk(s).ptr returned NULL, expecting non-NULL");
		}
		if (c.ptr != NULL && s.ptr == NULL) {
			FAIL_S("clone_hunk(s).ptr returned non-NULL, expecting NULL");
		}
		free_chunk_content(&c);
	}
}

static void check_hunk_char(void)
{
	static const struct test {
		const char *s;
		size_t i;
		const char *c;
	} tests[] = {
		/* empty always same */
		{ "", 0, "\0", },
		{ "a", 0, "a", },
		{ "a", 1, "\0", },
		{ "ab", 0, "a", },
		{ "ab", 1, "b", },
		{ "ab", 2, "\0", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_S(stdout, "[%zu]", t->i);
		shunk_t s = shunk1(t->s);
		char c[2] = { hunk_char(s, t->i), };
		if (c[0] != t->c[0]) {
			FAIL_S("hunk_char(%zu) returned '%s', expecting '%s'",
			       t->i, c, t->c);
		}
	}
}

static void check_hunk_char_is(void)
{
	static const struct test {
		const char *s;
		bool print;
		bool digit;
		bool bdigit;
		bool odigit;
		bool xdigit;
	} tests[] = {
		{ "\037", .print = false, },
		{ " ", .print = true, },
		{ "/", .print = true, },
		{ "0", .print = true, .xdigit = true, .digit = true, .odigit = true, .bdigit = true, },
		{ "1", .print = true, .xdigit = true, .digit = true, .odigit = true, .bdigit = true, },
		{ "2", .print = true, .xdigit = true, .digit = true, .odigit = true, },
		{ "3", .print = true, .xdigit = true, .digit = true, .odigit = true, },
		{ "4", .print = true, .xdigit = true, .digit = true, .odigit = true, },
		{ "5", .print = true, .xdigit = true, .digit = true, .odigit = true, },
		{ "6", .print = true, .xdigit = true, .digit = true, .odigit = true, },
		{ "7", .print = true, .xdigit = true, .digit = true, .odigit = true, },
		{ "8", .print = true, .xdigit = true, .digit = true, },
		{ "9", .print = true, .xdigit = true, .digit = true, },
		{ ":", .print = true, },
		{ "a", .print = true, .xdigit = true, },
		{ "b", .print = true, .xdigit = true, },
		{ "c", .print = true, .xdigit = true, },
		{ "d", .print = true, .xdigit = true, },
		{ "e", .print = true, .xdigit = true, },
		{ "f", .print = true, .xdigit = true, },
		{ "g", .print = true, },
		{ "A", .print = true, .xdigit = true, },
		{ "B", .print = true, .xdigit = true, },
		{ "C", .print = true, .xdigit = true, },
		{ "D", .print = true, .xdigit = true, },
		{ "E", .print = true, .xdigit = true, },
		{ "F", .print = true, .xdigit = true, },
		{ "G", .print = true, },
		{ "\177", .print = false, },
		{ "", .print = false, },
	};

	/* this string matches above */
	const char string[] = "\037 /0123456789:abcdefgABCDEFG\177";
	shunk_t s = shunk2(string, sizeof(string)); /* include NUL */

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_S(stdout, "");

		char c = hunk_char(s, ti);
		if (c != t->s[0]) {
			FAIL_S("hunk_char('"PRI_SHUNK"', %zu) returned '%c' (%u), expecting '%c' (%u)",
			       pri_shunk(s), ti, c, c, t->s[0], t->s[0]);
		}

#define HUNK_IS(OP)							\
		{							\
			bool is = hunk_char_is##OP(s, ti);			\
			if (is != t->OP) {				\
				FAIL_S("hunk_char_is"#OP"() returned %s, expecting %s",	\
				       bool_str(is), bool_str(t->OP));	\
			}						\
		}
		HUNK_IS(print);
		HUNK_IS(bdigit);
		HUNK_IS(odigit);
		HUNK_IS(digit);
		HUNK_IS(xdigit);
	}
}

static void check_shunk_to_uint(void)
{
	static const struct test {
		const char *s;
		unsigned base;
		uintmax_t ceiling;
		uintmax_t u;
		const char *o;
	} tests[] = {

		/* empty */
		{ "",      0, 0, 0, NULL, },
		{ "",      2, 0, 0, NULL, },
		{ "",      8, 0, 0, NULL, },
		{ "",     10, 0, 0, NULL, },
		{ "",     16, 0, 0x0, NULL, },

		/* '0' - 1 */
		{ "/",     0, 0, 0, NULL, },
		{ "/",     2, 0, 0, NULL, },
		{ "/",     8, 0, 0, NULL, },
		{ "/",    10, 0, 0, NULL, },
		{ "/",    16, 0, 0x0, NULL, },

		/* base */
		{ ":",     0, 0, 0, NULL, },
		{ "2",     2, 0, 0, NULL, },
		{ "8",     8, 0, 0, NULL, },
		{ ":",     10, 0, 0, NULL, },
		{ "g",     16, 0, 0x0, NULL, },

		/* 0 because prefix isn't valid */
		{ "0:",    0, 0, 0, ":", },
		{ "08",    0, 0, 0, "8", },
		{ "0b",    0, 0, 0, "b", },
		{ "0B2",   0, 0, 0, "B2", },
		{ "0x",    0, 0, 0, "x", },
		{ "0Xg",   0, 0, 0, "Xg", },

		/* 0 */
		{ "0",     0, 0, 0, "", },
		{ "0",     2, 0, 00, "", },
		{ "0",     8, 0, 00, "", },
		{ "0",    10, 0, 0, "", },
		{ "0",    16, 0, 0x0, "", },

		/* 1 */
		{ "1",     0, 0, 1, "", },
		{ "1",     2, 0, 1, "", },
		{ "1",     8, 0, 1, "", },
		{ "1",    10, 0, 1, "", },
		{ "1",    16, 0, 1, "", },

		/* 1 .. base */
		{ "123456789:", 0, 0, UINTMAX_C(123456789), ":", },
		{ "12",   2, 0, UINTMAX_C(1), "2", },
		{ "12345678",   8, 0, UINTMAX_C(01234567), "8", },
		{ "123456789:",  10, 0, UINTMAX_C(123456789), ":", },
		{ "123456789abcdefg",   16, 0, UINTMAX_C(0x123456789abcdef), "g", },
		{ "123456789ABCDEFG",   16, 0, UINTMAX_C(0X123456789ABCDEF), "G", },

		/* base-1 .. / */
		{ "9876543210/", 0, 0, UINTMAX_C(9876543210), "/", },
		{ "10/",   2, 0, UINTMAX_C(2), "/", },
		{ "76543210/",   8, 0, UINTMAX_C(076543210), "/", },
		{ "9876543210/",  10, 0, UINTMAX_C(9876543210), "/", },
		{ "fedcba9876543210/", 16, 0, UINTMAX_C(0xfedcba9876543210), "/", },
		{ "FEDCBA9876543210/", 16, 0, UINTMAX_C(0XFEDCBA9876543210), "/", },

		/* auto select - stopchar */
		{ "0b012",    0, 0, 1, "2", },
		{ "012345678",    0, 0, UINTMAX_C(01234567), "8", },
		{ "0x0123f56789abcdefg",    0, 0, UINTMAX_C(0x0123f56789abcdef), "g", },

		/* limits */
		{ "1",     0, 1, 1, "", },
		{ "2",     0, 1, 0, NULL, },
		{ "18446744073709551615", 0, UINTMAX_MAX, UINTMAX_MAX, "", },
		/* overflow */
		{ "0177777777777777777777", 0, 0, UINTMAX_MAX/8, "", },
		{ "01777777777777777777777", 0, 0, UINTMAX_MAX, "", },
		{ "02000000000000000000000", 0, 0, 0, NULL, },
		{ "1844674407370955161", 0, 0, UINTMAX_MAX/10, "", },
		{ "18446744073709551615", 0, 0, UINTMAX_MAX, "", },
		{ "18446744073709551616", 0, 0, 0, NULL, },
		{ "0xfffffffffffffff", 0, 0, UINTMAX_MAX/16, "", },
		{ "0xffffffffffffffff", 0, 0, UINTMAX_MAX, "", },
		{ "0x10000000000000000", 0, 0, 0, NULL, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_S(stdout, " base=%u unsigned=%ju out=%s",
			t->base, t->u, t->o == NULL ? "<invalid>" : t->o);
		uintmax_t u;
		err_t err;

		shunk_t t_o = shunk1(t->o);
		shunk_t t_s = shunk1(t->s);

		/* must use entire buffer */
		err = shunk_to_uint(t_s, NULL, t->base, &u, t->ceiling);
		bool t_ok = t->o != NULL && t->o[0] == '\0';
		if ((err == NULL) != t_ok) {
			FAIL_S("shunk_to_uint(cursor==NULL) returned '%s', expecting '%s'",
			       err, bool_str(t_ok));
		}
		if (u != (t_ok ? t->u : 0)) {
			FAIL_S("shunk_to_uint(cursor==NULL) returned %ju (0x%jx), expecting %ju (0x%jx)",
			       u, u, t->u, t->u);
		}

		/* remainder left in O */
		shunk_t o;
		err = shunk_to_uint(t_s, &o, t->base, &u, t->ceiling);
		bool t_o_ok = t->o != NULL;
		if ((err == NULL) != t_o_ok) {
			FAIL_S("shunk_to_uint(&cursor) returned '%s', expecting '%s'",
			       err, bool_str(t_o_ok));
		}
		if (u != t->u) {
			FAIL_S("shunk_to_uint(&cursor) returned %ju (0x%jx), expecting %ju (0x%jx)",
			       u, u, t->u, t->u);
		}
		if (!hunk_eq(o, t_o)) {
			FAIL_S("shunk_to_uint(&cursor) returned '"PRI_SHUNK"', expecting '"PRI_SHUNK"'",
			       pri_shunk(o), pri_shunk(t_o));
		}
	}
}

static void check_ntoh_hton_hunk(void)
{
	static const struct test {
		uintmax_t i;
		uintmax_t o;
		size_t size;
		const uint8_t bytes[3]; /* oversize */
	} tests[] = {
		/* 00 */
		{ 0, 0, 0, { 0x01, 0x02, 0x03, }, },
		{ 0, 0, 1, { 0x00, 0x02, 0x03, }, },
		{ 0, 0, 2, { 0x00, 0x00, 0x03, }, },
		{ 0, 0, 3, { 0x00, 0x00, 0x00, }, },
		/* 0x1234 */
		{ 0x1234, 0x0000, 0, { 0x01, 0x02, 0x03, }, },
		{ 0x1234, 0x0034, 1, { 0x34, 0x02, 0x03, }, },
		{ 0x1234, 0x1234, 2, { 0x12, 0x34, 0x03, }, },
		{ 0x1234, 0x1234, 3, { 0x00, 0x12, 0x34, }, },
		/* 0x123456 */
		{ 0x123456, 0x000000, 0, { 0x01, 0x02, 0x03, }, },
		{ 0x123456, 0x000056, 1, { 0x56, 0x02, 0x03, }, },
		{ 0x123456, 0x003456, 2, { 0x34, 0x56, 0x03, }, },
		{ 0x123456, 0x123456, 3, { 0x12, 0x34, 0x56, }, },
		/* 0x12345678 */
		{ 0x12345678, 0x00000000, 0, { 0x01, 0x02, 0x03, }, },
		{ 0x12345678, 0x00000078, 1, { 0x78, 0x02, 0x03, }, },
		{ 0x12345678, 0x00005678, 2, { 0x56, 0x78, 0x03, }, },
		{ 0x12345678, 0x00345678, 3, { 0x34, 0x56, 0x78, }, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINTLN(stdout, " size=%zu i=%jx o=%jx", t->size, t->i, t->o);

		shunk_t t_shunk = shunk2(t->bytes, t->size);
		uintmax_t h = ntoh_hunk(t_shunk);
		if (h != t->o) {
			FAIL("hton_hunk() returned %jx, expecting %jx",
			     h, t->o);
		}

		uint8_t bytes[sizeof(t->bytes)] = { 0x01, 0x02, 0x03, };
		chunk_t n = chunk2(bytes, t->size);
		hton_chunk(t->i, n);
		if (!memeq(bytes, t->bytes, sizeof(bytes))) {
			FAIL("hton_chunk() returned %jx, expecting %jx",
			     ntoh_hunk(n), t->o);
		}
	}
}

int main(int argc UNUSED, char *argv[] UNUSED)
{
	check_hunk_eq();
	shunk_slice_check();
	shunk_token_check();
	shunk_span_check();
	shunk_clone_check();
	check_hunk_char();
	check_hunk_char_is();
	check_shunk_to_uint();
	check_ntoh_hton_hunk();

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	} else {
		return 0;
	}
}
