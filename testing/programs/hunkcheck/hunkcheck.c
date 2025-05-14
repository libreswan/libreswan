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
#include "passert.h"
#include "lswlog.h"		/* for cur_debugging */
#include "lswalloc.h"
#include "lswtool.h"		/* for tool_init_log() */

unsigned fails;

#define PRINT(FMT, ...)							\
	fprintf(stdout, "%s[%zu]:"FMT"\n",				\
		__func__, ti, ##__VA_ARGS__)

#define PRINTF(FILE, FMT, ...)						\
	fprintf(FILE, "%s[%zu]:"FMT"\n",				\
		__func__, ti, ##__VA_ARGS__)

#define PRINT_LR(FILE, FMT, ...)					\
	fprintf(FILE, "%s[%zu]: '%s' vs '%s'" FMT "\n",			\
		__func__, ti,						\
		t->l == NULL ? "NULL" : t->l,				\
		t->r == NULL ? "NULL" : t->r,				\
		##__VA_ARGS__);

#define FAIL(FMT, ...)						\
	{							\
		fails++;					\
		PRINTF(stderr, " "FMT, ##__VA_ARGS__);		\
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
		bool heq;
	} tests[] = {
		/*
		 * Like strings, NULL and EMPTY ("") shunks are
		 * considered different.
		 *
		 * Strangely, while NULL==NULL, NULL does not start
		 * NULL - it goes to *eat() which can't eat nothing.
		 */
		{ NULL, NULL, .empty = false, .eq = true,  .caseeq = true,  .starteq = false, .casestarteq = false, .thingeq = false, .heq = true,  },
		{ NULL, "",   .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = false, },
		{ "", NULL,   .empty = true,  .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = false, },
		{ "", "",     .empty = true,  .eq = true,  .caseeq = true,  .starteq = true,  .casestarteq = true,  .thingeq = false, .heq = true,  },

		{ "", "a",    .empty = true,  .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = false, },
		{ "a", "",    .empty = false, .eq = false, .caseeq = false, .starteq = true,  .casestarteq = true,  .thingeq = false, .heq = false, },

		{ "a", "a",   .empty = false, .eq = true,  .caseeq = true,  .starteq = true,  .casestarteq = true,  .thingeq = false, .heq = true,  },
		{ "a", "A",   .empty = false, .eq = false, .caseeq = true,  .starteq = false, .casestarteq = true,  .thingeq = false, .heq = true,  },
		{ "A", "a",   .empty = false, .eq = false, .caseeq = true,  .starteq = false, .casestarteq = true,  .thingeq = false, .heq = true,  },
		{ "a", "b",   .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = false, },

		{ "a", "aa",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = false, },
		{ "A", "aa",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = false, },
		{ "ab", "a",  .empty = false, .eq = false, .caseeq = false, .starteq = true,  .casestarteq = true,  .thingeq = false, .heq = false, },
		{ "AB", "a",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = true,  .thingeq = false, .heq = false, },
		{ "ab", "A",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = true,  .thingeq = false, .heq = false, },
		{ "ab", "b",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = false, },

		{ "a-b", "a_b",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = true, },
		{ "a_b", "a-b",  .empty = false, .eq = false, .caseeq = false, .starteq = false, .casestarteq = false, .thingeq = false, .heq = true, },

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
		HUNK_EQ(heq);
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

static void check_shunk_slice(void)
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

		shunk_t t_slice = hunk_slice(l, t->lo, t->hi);
		if (!hunk_eq(r, t_slice)) {
			FAIL_LR("shunk_slice() returned '"PRI_SHUNK"', expecting '"PRI_SHUNK"'",
				pri_shunk(t_slice), pri_shunk(r));
		}
	}
}

static void check_shunk_token(void)
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

static void check_shunk_span(void)
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
		PRINT(" old='%s' accept='%s' -> token='%s' new='%s'",
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

static void check_shunk_clone(void)
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

static void check__hunk_char__hunk_byte(void)
{
	static const struct test {
		const char *s;
		size_t i;
		char c;
		int b;
	} tests[] = {
		/* empty always same */
		{ "", 0, '\0', -1, },
		{ "a", 0, 'a', 'a', },
		{ "a", 1, '\0', -1, },
		{ "ab", 0, 'a', 'a', },
		{ "ab", 1, 'b', 'b', },
		{ "ab", 2, '\0', -1, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_S(stdout, "[%zu]", t->i);
		shunk_t s = shunk1(t->s);
		char c = hunk_char(s, t->i);
		if (c != t->c) {
			FAIL_S("hunk_char('%s', %zu) returned '%c', expecting '%c'",
			       t->s, t->i, c, t->c);
		}
		int b = hunk_byte(s, t->i);
		if (b != t->b) {
			FAIL_S("hunk_byte('%s', %zu) returned '%x', expecting '%x'",
			       t->s, t->i, b, t->b);
		}
	}
}

static void check__hunk_get__hunk_put(void)
{
	char src[] = "string"; /* includes NUL */
	char dst[sizeof(src)]; /* includes NUL */
	shunk_t s = shunk2(src, sizeof(dst) - 1); /* excludes NUL */
	chunk_t d = chunk2(dst, sizeof(dst) - 1); /* excludes NUL */
	for (size_t ti = 0; ti < sizeof(src); ti++) {
		char c = src[ti];
		char cc[] = { c, '\0', };
		PRINT("%s%s%s",
		      c > '\0' ? "'" : "",
		      c > '\0' ? cc : "-1",
		      c > '\0' ? "'" : "");
		char *sc = hunk_get_thing(&s, char);
		if (sc != NULL) {
			if (c == '\0') {
				FAIL("hunk_get() returned '%c', expecting end-of-hunk", *sc);
			} else if (*sc != c) {
				FAIL("hunk_get() returned '%c', expecting '%c'", *sc, c);
			}
		} else if (c != '\0') {
			FAIL("hunk_get() returned end-of-hunk, expecting '%c'", c);
		}
		/* danger, returns pointer */
		char *sp = hunk_put_thing(&d, c);
		if (sp != NULL) {
			if (c == '\0') {
				FAIL("hunk_put() should have returned end-of-hunk");
			} else if (dst[ti] != c) {
				FAIL("hunk_put() stored '%c', should have stored '%c'",
				     dst[ti], c);
			}
		} else if (c != '\0') {
			FAIL("hunk_put() returned end-of-hunk, expecting '%c'", c);
		}
	}
}

static void check__hunk_append(void)
{
	struct hunk_like {
		size_t len;
		uint8_t ptr[11];
	} dst = {
		.len = 0,
		.ptr = "0123456789", /* includes trailing NUL */
	};

	/* XXX: can't test overflow as it will abort!?! */
	struct test {
		size_t len;
		const char *val;
	} tests[3] = {
		{ 3, "str3456789" },
		{ 5, "strZZ56789" },
		{ 8, "strZZABC89" },
	};

	shunk_t str = shunk1("str");

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("val: %zu %s", t->len, t->val);

		switch (ti) {
		case 0:
			hunk_append_hunk(&dst, str);
			break;

		case 1:
			/* now try zero */
			hunk_append_byte(&dst, 'Z', 2);
			break;

		case 2:
			hunk_append_bytes(&dst, "ABC", 3);
			break;
		}

		if (dst.len != t->len) {
			FAIL("hunk_append_hunk() appended %zu characters, expecting %zu",
			     dst.len, t->len);
		}
		if (!memeq(dst.ptr, t->val, sizeof(dst.ptr))) {
			FAIL("hunk_append_hunk() value is %s, expecting %s",
			     dst.ptr, t->val);
		}
	}
}

static void check_hunk_char_is(void)
{
	static const struct test {
		bool bdigit;
		bool blank;
		bool digit;
		bool lower;
		bool odigit;
		bool print;
		bool space;
		bool upper;
		bool xdigit;
		char to_upper;
		char to_lower;
	} tests[256] = {
		['\t'] = { .space = true, .blank = true, },
		['\r'] = { .space = true, },
		['\v'] = { .space = true, },
		['\f'] = { .space = true, },
		['\n'] = { .space = true, },
		[' '] = { .print = true, .space = true, .blank = true, },
		['!'] = { .print = true, },
		['"'] = { .print = true, },
		['#'] = { .print = true, },
		['$'] = { .print = true, },
		['%'] = { .print = true, },
		['&'] = { .print = true, },
		['\''] = { .print = true, },
		['('] = { .print = true, },
		[')'] = { .print = true, },
		['*'] = { .print = true, },
		['+'] = { .print = true, },
		[','] = { .print = true, },
		['-'] = { .print = true, },
		['.'] = { .print = true, },
		['/'] = { .print = true, },
		['0'] = { .print = true, .xdigit = true, .digit = true, .odigit = true, .bdigit = true, },
		['1'] = { .print = true, .xdigit = true, .digit = true, .odigit = true, .bdigit = true, },
		['2'] = { .print = true, .xdigit = true, .digit = true, .odigit = true, },
		['3'] = { .print = true, .xdigit = true, .digit = true, .odigit = true, },
		['4'] = { .print = true, .xdigit = true, .digit = true, .odigit = true, },
		['5'] = { .print = true, .xdigit = true, .digit = true, .odigit = true, },
		['6'] = { .print = true, .xdigit = true, .digit = true, .odigit = true, },
		['7'] = { .print = true, .xdigit = true, .digit = true, .odigit = true, },
		['8'] = { .print = true, .xdigit = true, .digit = true, },
		['9'] = { .print = true, .xdigit = true, .digit = true, },
		[':'] = { .print = true, },
		[';'] = { .print = true, },
		['<'] = { .print = true, },
		['='] = { .print = true, },
		['>'] = { .print = true, },
		['?'] = { .print = true, },
		['@'] = { .print = true, },
		/* upper case */
		['A'] = { .print = true, .xdigit = true, .upper = true, .to_lower = 'a', },
		['B'] = { .print = true, .xdigit = true, .upper = true, .to_lower = 'b', },
		['C'] = { .print = true, .xdigit = true, .upper = true, .to_lower = 'c', },
		['D'] = { .print = true, .xdigit = true, .upper = true, .to_lower = 'd', },
		['E'] = { .print = true, .xdigit = true, .upper = true, .to_lower = 'e', },
		['F'] = { .print = true, .xdigit = true, .upper = true, .to_lower = 'f', },
		['G'] = { .print = true, .upper = true, .to_lower = 'g', },
		['H'] = { .print = true, .upper = true, .to_lower = 'h', },
		['I'] = { .print = true, .upper = true, .to_lower = 'i', },
		['J'] = { .print = true, .upper = true, .to_lower = 'j', },
		['K'] = { .print = true, .upper = true, .to_lower = 'k', },
		['L'] = { .print = true, .upper = true, .to_lower = 'l', },
		['M'] = { .print = true, .upper = true, .to_lower = 'm', },
		['N'] = { .print = true, .upper = true, .to_lower = 'n', },
		['O'] = { .print = true, .upper = true, .to_lower = 'o', },
		['P'] = { .print = true, .upper = true, .to_lower = 'p', },
		['Q'] = { .print = true, .upper = true, .to_lower = 'q', },
		['R'] = { .print = true, .upper = true, .to_lower = 'r', },
		['S'] = { .print = true, .upper = true, .to_lower = 's', },
		['T'] = { .print = true, .upper = true, .to_lower = 't', },
		['U'] = { .print = true, .upper = true, .to_lower = 'u', },
		['V'] = { .print = true, .upper = true, .to_lower = 'v', },
		['W'] = { .print = true, .upper = true, .to_lower = 'w', },
		['X'] = { .print = true, .upper = true, .to_lower = 'x', },
		['Y'] = { .print = true, .upper = true, .to_lower = 'y', },
		['Z'] = { .print = true, .upper = true, .to_lower = 'z', },
		/* misc */
		['['] = { .print = true, },
		['\\'] = { .print = true, },
		[']'] = { .print = true, },
		['^'] = { .print = true, },
		['_'] = { .print = true, },
		['`'] = { .print = true, },
		/* lower case */
		['a'] = { .print = true, .xdigit = true, .lower = true, .to_upper = 'A', },
		['b'] = { .print = true, .xdigit = true, .lower = true, .to_upper = 'B', },
		['c'] = { .print = true, .xdigit = true, .lower = true, .to_upper = 'C', },
		['d'] = { .print = true, .xdigit = true, .lower = true, .to_upper = 'D', },
		['e'] = { .print = true, .xdigit = true, .lower = true, .to_upper = 'E', },
		['f'] = { .print = true, .xdigit = true, .lower = true, .to_upper = 'F', },
		['g'] = { .print = true, .lower = true, .to_upper = 'G', },
		['h'] = { .print = true, .lower = true, .to_upper = 'H', },
		['i'] = { .print = true, .lower = true, .to_upper = 'I', },
		['j'] = { .print = true, .lower = true, .to_upper = 'J', },
		['k'] = { .print = true, .lower = true, .to_upper = 'K', },
		['l'] = { .print = true, .lower = true, .to_upper = 'L', },
		['m'] = { .print = true, .lower = true, .to_upper = 'M', },
		['n'] = { .print = true, .lower = true, .to_upper = 'N', },
		['o'] = { .print = true, .lower = true, .to_upper = 'O', },
		['p'] = { .print = true, .lower = true, .to_upper = 'P', },
		['q'] = { .print = true, .lower = true, .to_upper = 'Q', },
		['r'] = { .print = true, .lower = true, .to_upper = 'R', },
		['s'] = { .print = true, .lower = true, .to_upper = 'S', },
		['t'] = { .print = true, .lower = true, .to_upper = 'T', },
		['u'] = { .print = true, .lower = true, .to_upper = 'U', },
		['v'] = { .print = true, .lower = true, .to_upper = 'V', },
		['w'] = { .print = true, .lower = true, .to_upper = 'W', },
		['x'] = { .print = true, .lower = true, .to_upper = 'X', },
		['y'] = { .print = true, .lower = true, .to_upper = 'Y', },
		['z'] = { .print = true, .lower = true, .to_upper = 'Z', },
		/* misc */
		['{'] = { .print = true, },
		['|'] = { .print = true, },
		['}'] = { .print = true, },
		['~'] = { .print = true, },
	};

	/* this string matches above */
	char string[elemsof(tests) + 1] = "";
	shunk_t shunk = shunk2(string, sizeof(string)); /* include NUL */
	for (unsigned c = 0; c < elemsof(tests); c++) {
		string[c] = c;
	}

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("char %c", ti < 32 || ti >= 127 ? '?' : (char)ti);

		char c = hunk_char(shunk, ti);
		if (c != (char)ti) {
			FAIL("hunk_char('"PRI_SHUNK"', %zu) returned '%c' (%u), expecting '%c' (%zu)",
			     pri_shunk(shunk), ti, c, c, (char)ti, ti);
		}

#define IS(OP)								\
		{							\
			signed char c = hunk_char(shunk, ti);		\
			bool is = char_is##OP(c);			\
			if (is != t->OP) {				\
				FAIL("signed char_is"#OP"('%c') returned %s, expecting %s", \
				     c, bool_str(is), bool_str(t->OP));	\
			}						\
		}							\
		{							\
			unsigned char c = hunk_char(shunk, ti);		\
			bool is = char_is##OP(c);			\
			if (is != t->OP) {				\
				FAIL("unsigned char_is"#OP"('%c') returned %s, expecting %s", \
				     c, bool_str(is), bool_str(t->OP));	\
			}						\
		}
		IS(bdigit);
		IS(blank);
		IS(digit);
		IS(lower);
		IS(odigit);
		IS(print);
		IS(space);
		IS(upper);
		IS(xdigit);
#undef IS

#define TO(OP)								\
		{							\
			char to = char_to##OP(c);			\
			char e = t->to_##OP != '\0' ? t->to_##OP : c;	\
			if (e != to) {					\
				FAIL("char_to"#OP"('%c') returned %c, expecting %c lower:%s upper:%s", \
				     c, to, e,				\
				     bool_str(char_islower(c)),		\
				     bool_str(char_isupper(c)));	\
			}						\
		}
		TO(lower);
		TO(upper);
	}
}

static void check__shunk_to_uintmax(void)
{
	static const struct test {
		const char *s;
		unsigned base;
		uintmax_t u;
		const char *o;
	} tests[] = {

		/* empty */
		{ "",      0, 0, NULL, },
		{ "",      2, 0, NULL, },
		{ "",      8, 0, NULL, },
		{ "",     10, 0, NULL, },
		{ "",     16, 0, NULL, },

		/* '0' - 1 */
		{ "/",     0, 0, NULL, },
		{ "/",     2, 0, NULL, },
		{ "/",     8, 0, NULL, },
		{ "/",    10, 0, NULL, },
		{ "/",    16, 0, NULL, },

		/* base */
		{ ":",     0, 0, NULL, },
		{ "2",     2, 0, NULL, },
		{ "8",     8, 0, NULL, },
		{ ":",    10, 0, NULL, },
		{ "g",    16, 0, NULL, },

		/* 0 because prefix isn't valid */
		{ "0:",    0, 0, ":", },
		{ "08",    0, 0, "8", },
		{ "0b",    0, 0, "b", },
		{ "0B2",   0, 0, "B2", },
		{ "0x",    0, 0, "x", },
		{ "0Xg",   0, 0, "Xg", },

		/* 0 */
		{ "0",     0, 0, "", },
		{ "0",     2, 0, "", },
		{ "0",     8, 0, "", },
		{ "0",    10, 0, "", },
		{ "0",    16, 0, "", },

		/* 1 */
		{ "1",     0, 1, "", },
		{ "1",     2, 1, "", },
		{ "1",     8, 1, "", },
		{ "1",    10, 1, "", },
		{ "1",    16, 1, "", },

		/* 1 .. base */
		{ "123456789:",        0, UINTMAX_C(123456789), ":", },
		{ "12",                2, UINTMAX_C(1), "2", },
		{ "12345678",          8, UINTMAX_C(01234567), "8", },
		{ "123456789:",       10, UINTMAX_C(123456789), ":", },
		{ "123456789abcdefg", 16, UINTMAX_C(0x123456789abcdef), "g", },
		{ "123456789ABCDEFG", 16, UINTMAX_C(0X123456789ABCDEF), "G", },

		/* base-1 .. / */
		{ "9876543210/",        0, UINTMAX_C(9876543210), "/", },
		{ "10/",                2, UINTMAX_C(2), "/", },
		{ "76543210/",          8, UINTMAX_C(076543210), "/", },
		{ "9876543210/",       10, UINTMAX_C(9876543210), "/", },
		{ "fedcba9876543210/", 16, UINTMAX_C(0xfedcba9876543210), "/", },
		{ "FEDCBA9876543210/", 16, UINTMAX_C(0XFEDCBA9876543210), "/", },

		/* auto select - stopchar */
		{ "0b012",               0, 1, "2", },
		{ "012345678",           0, UINTMAX_C(01234567), "8", },
		{ "0012345678",          0, UINTMAX_C(01234567), "8", },
		{ "0x0123f56789abcdefg", 0, UINTMAX_C(0x0123f56789abcdef), "g", },

		/* overflow */
		{ "0177777777777777777777",  0, UINTMAX_MAX/8, "", },
		{ "01777777777777777777777", 0, UINTMAX_MAX, "", },
		{ "02000000000000000000000", 0, 0, NULL, },
		{ "1844674407370955161",     0, UINTMAX_MAX/10, "", },
		{ "18446744073709551615",    0, UINTMAX_MAX, "", },
		{ "18446744073709551616",    0, 0, NULL, },
		{ "0xfffffffffffffff",       0, UINTMAX_MAX/16, "", },
		{ "0xffffffffffffffff",      0, UINTMAX_MAX, "", },
		{ "0x10000000000000000",     0, 0, NULL, },
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
		err = shunk_to_uintmax(t_s, NULL, t->base, &u);
		/* OK when test expects entire buffer to be consumed */
		bool t_ok = t->o != NULL && t->o[0] == '\0';
		if (err != NULL) {
			if (t_ok) {
				FAIL("shunk_to_uintmax(%s,NULL) unexpectedly failed: %s", t->s, err);
			} else {
				PRINT("shunk_to_uintmax(%s,NULL) failed with: %s", t->s, err);
			}
		} else {
			if (!t_ok) {
				FAIL("shunk_to_uintmax(%s,NULL) unexpectedly succeeded", t->s);
			} else {
				PRINT("shunk_to_uintmax(%s,NULL) succeeded with %ju", t->s, u);
			}
		}
		if (u != (t_ok ? t->u : 0)) {
			FAIL_S("shunk_to_uintmax(cursor==NULL) returned %ju (0x%jx), expecting %ju (0x%jx)",
			       u, u, t->u, t->u);
		}

		/* remainder left in O */
		shunk_t o;
		bool t_o_ok = (t->o != NULL);
		err = shunk_to_uintmax(t_s, &o, t->base, &u);
		if (err != NULL) {
			if (t_o_ok) {
				FAIL_S("shunk_to_uintmax(cursor,&cursor) returned error '%s', expecting NULL", err);
			}
			/* error expected */
		} else {
			if (!t_o_ok) {
				FAIL_S("shunk_to_uintmax(cursor,&cursor) returned NULL, expecting error");
			}
			if (u != t->u) {
				FAIL_S("shunk_to_uintmax(cursor,&cursor) returned %ju (0x%jx), expecting %ju (0x%jx)",
				       u, u, t->u, t->u);
			}
			if (!hunk_eq(o, t_o)) {
				FAIL_S("shunk_to_uintmax(cursor,&cursor) returned cursor '"PRI_SHUNK"', expecting cursor '"PRI_SHUNK"'",
				       pri_shunk(o), pri_shunk(t_o));
			}
		}
	}
}

static void check__shunk_to_intmax(void)
{
	static const struct test {
		const char *s;
		unsigned base;
		intmax_t u;
		const char *o;
	} tests[] = {

		/* empty */
		{ "",   0, 0, NULL, },
		{ "-",  0, 0, NULL, },

		/* 1 .. base */
		{ "0",        0, INTMAX_C(0), "", },
		{ "1",        0, INTMAX_C(1), "", },
		{ "-0",        0, INTMAX_C(0), "", },
		{ "-1",        0, INTMAX_C(-1), "", },

		/* limit */
		{ "-9223372036854775808",    0, INTMAX_MIN, "", },
		{  "9223372036854775807",    0, INTMAX_MAX, "", },

		/* overflow/underflow */
		{ "-9223372036854775809",    0, 0, NULL, },
		{  "9223372036854775808",    0, 0, NULL, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_S(stdout, " base=%u unsigned=%ju out=%s",
			t->base, t->u, t->o == NULL ? "<invalid>" : t->o);
		intmax_t u;
		err_t err;

		shunk_t t_o = shunk1(t->o);
		shunk_t t_s = shunk1(t->s);

		/*
		 * Consume entire buffer, OK when test expects nothing
		 * at end of buffer.
		 */
		bool t_ok = (t->o != NULL && t->o[0] == '\0');
		err = shunk_to_intmax(t_s, NULL, t->base, &u);
		if (err != NULL) {
			if (t_ok) {
				FAIL("shunk_to_intmax(%s,NULL) unexpectedly failed: %s", t->s, err);
			} else {
				PRINT("shunk_to_intmax(%s,NULL) failed with: %s", t->s, err);
			}
		} else {
			if (!t_ok) {
				FAIL("shunk_to_intmax(%s,NULL) unexpectedly succeeded", t->s);
			} else {
				PRINT("shunk_to_intmax(%s,NULL) succeeded with %ju", t->s, u);
			}
		}
		if (u != (t_ok ? t->u : 0)) {
			FAIL_S("shunk_to_intmax(cursor==NULL) returned %ju (0x%jx), expecting %ju (0x%jx)",
			       u, u, t->u, t->u);
		}

		/* remainder left in O */
		shunk_t o;
		bool t_o_ok = (t->o != NULL);
		err = shunk_to_intmax(t_s, &o, t->base, &u);
		if (err != NULL) {
			if (t_o_ok) {
				FAIL_S("shunk_to_intmax(cursor,&cursor) returned error '%s', expecting NULL", err);
			}
			/* error expected */
		} else {
			if (!t_o_ok) {
				FAIL_S("shunk_to_intmax(cursor,&cursor) returned NULL, expecting error");
			}
			if (u != t->u) {
				FAIL_S("shunk_to_intmax(cursor,&cursor) returned %jd (0x%jx), expecting %jd (0x%jx)",
				       u, u, t->u, t->u);
			}
			if (!hunk_eq(o, t_o)) {
				FAIL_S("shunk_to_intmax(cursor,&cursor) returned cursor '"PRI_SHUNK"', expecting cursor '"PRI_SHUNK"'",
				       pri_shunk(o), pri_shunk(t_o));
			}
		}
	}
}

static void check_ntoh_hton_hunk(void)
{

	/*
	 * Each entry consists of:
	 *
	 *   <value> <sentinel>
	 *
	 * so if a read goes to far it picks up the <sentinel>
	 */
	static const struct test {
		uintmax_t hton;
		uintmax_t ntoh;
		size_t size;
#define MAX_BYTES sizeof(uintmax_t)
		const uint8_t bytes[MAX_BYTES+2]; /* oversize */
	} tests[] = {

		/* 00 */
		{ 0, 0, 0, { [0] = 1, }, },
		{ 0, 0, 1, { [1] = 2, }, },
		{ 0, 0, 2, { [2] = 3, }, },
		{ 0, 0, 3, { [3] = 4, }, },
		/* 0x1234 */
		{ 0x1234, 0x0000, 0, { [0] = 1, }, },
		{ 0x1234, 0x0034, 1, { 0x34, [1] = 2, }, },
		{ 0x1234, 0x1234, 2, { 0x12, 0x34, [2] = 3, }, },
		{ 0x1234, 0x1234, 3, { 0x00, 0x12, 0x34, [3] = 4}, },
		/* 0x123456 */
		{ 0x123456, 0x000000, 0, { [0] = 1, }, },
		{ 0x123456, 0x000056, 1, { 0x56, [1] = 2, }, },
		{ 0x123456, 0x003456, 2, { 0x34, 0x56, [2] = 3, }, },
		{ 0x123456, 0x123456, 3, { 0x12, 0x34, 0x56, [3] = 4, }, },
		/* 0x12345678 */
		{ 0x12345678, 0x00000000, 0, { [0] = 1, }, },
		{ 0x12345678, 0x00000078, 1, { 0x78, [1] = 2, }, },
		{ 0x12345678, 0x00005678, 2, { 0x56, 0x78, [2] = 3, }, },
		{ 0x12345678, 0x00345678, 3, { 0x34, 0x56, 0x78, [3] = 4, }, },

		/* largest */
		{ UINTMAX_MAX-1, UINTMAX_MAX-1, MAX_BYTES, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, [MAX_BYTES] = MAX_BYTES + 1, }, },
		{ UINTMAX_MAX,   UINTMAX_MAX,   MAX_BYTES, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, [MAX_BYTES] = MAX_BYTES + 1, }, },

		/* oversized but under valued */
		{ UINTMAX_MAX-1, UINTMAX_MAX-1, MAX_BYTES + 1, { 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, [MAX_BYTES + 1] = MAX_BYTES + 2, }, },
		{ UINTMAX_MAX,   UINTMAX_MAX,   MAX_BYTES + 1, { 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, [MAX_BYTES + 1] = MAX_BYTES + 2, }, },

		/* oversized and / or over valued */
		{ 0/*invalid*/, UINTMAX_MAX, MAX_BYTES + 1, { [0] = 0x01, [MAX_BYTES + 1] = MAX_BYTES + 2, }, },
		{ /*truncated*/UINTMAX_MAX, UINTMAX_MAX >> 8, MAX_BYTES - 1, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, [MAX_BYTES] = MAX_BYTES + 1, }, },
		{ /*truncated*/0x1234, 0x34, 1, { 0x34, [1] = 2, }, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT(" size=%zu ntoh=%jx hton=%jx", t->size, t->ntoh, t->hton);

		shunk_t t_shunk = shunk2(t->bytes, t->size);

		uintmax_t h = ntoh_hunk(t_shunk); /* aka ntoh_bytes() */
		if (h != t->ntoh) {
			FAIL("hton_hunk() returned %jx, expecting %jx",
			     h, t->ntoh);
		}

		/* hton() broken when oversize */
		if (t->size > MAX_BYTES) {
			continue;
		}

		uint8_t bytes[sizeof(t->bytes)]; /* = 1 2 3 4 ... */
		for (unsigned u = 0; u < sizeof(bytes); u++) {
			bytes[u] = u + 1;
		}

		chunk_t n = chunk2(bytes, t->size);
		hton_chunk(t->hton, n); /* aka hton_bytes() */
		if (!memeq(bytes, t->bytes, t->size)) {
			FAIL("hton_chunk() returned %jx, expecting %jx",
			     ntoh_hunk(n), t->hton);
		}
		for (unsigned u = t->size; u < sizeof(bytes); u++) {
			if (bytes[u] != u + 1) {
				FAIL("hton_chunk() byte[%u] is %02"PRIx8", expecting %02x",
				     u, bytes[u], u + 1);
			}
		}
	}
}

static void check_hunks(void)
{
	static const struct test {
		const char *input;
		const char *delims;
		enum shunks_opt opt;
		bool kept_empty_shunks;
		const char *output[10];
	} tests[] = {

		{ "",     ",",  KEEP_EMPTY_SHUNKS, true,  { "", } },
		{ "",     ",",  EAT_EMPTY_SHUNKS,  false, { } },

		{ "1",    ",",  KEEP_EMPTY_SHUNKS, false, { "1", } },
		{ "1",    ",",  EAT_EMPTY_SHUNKS,  false, { "1", } },

		{ "1,2",  ",",  KEEP_EMPTY_SHUNKS, false, { "1", "2", } },
		{ "1,2",  ",",  EAT_EMPTY_SHUNKS,  false, { "1", "2", } },

		{ "1,,2", ",",  KEEP_EMPTY_SHUNKS, true,  { "1", "", "2", } },
		{ "1,,2", ",",  EAT_EMPTY_SHUNKS,  false, { "1", "2", } },

		{ "1, ",  ", ", KEEP_EMPTY_SHUNKS, true,  { "1", "", "", } },
		{ "1, ",  ", ", EAT_EMPTY_SHUNKS,  false, { "1", } },

	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT(" input=%s delims=%s %s", t->input, t->delims,
		      (t->opt == KEEP_EMPTY_SHUNKS ? "KEEP_EMPTY_SHUNKS" :
		       t->opt == EAT_EMPTY_SHUNKS ? "EAT_EMPTY_SHUNKS" :
		       "???"));
		shunk_t input = shunk1(t->input);

		struct shunks *output = ttoshunks(input, t->delims, t->opt);
		unsigned len = 0;
		ITEMS_FOR_EACH(shunk, output) {
			if (t->output[len] == NULL) {
				FAIL("shunks(\"%s\",\"%s\") returned %u shunks, expecting %u",
				     t->input, t->delims, output->len, len);
			}
			shunk_t s = shunk1(t->output[len]);
			if (!hunk_eq(s, *shunk)) {
				FAIL("shunks(\"%s\",\"%s\")[%u]==\""PRI_SHUNK"\" does not match expected \""PRI_SHUNK"\"",
				     t->input, t->delims, len,
				     pri_shunk(output->item[len]),
				     pri_shunk(s));
			}
			len++;
		}

		if (t->output[len] != NULL) {
			FAIL("shunks(\"%s\",\"%s\")->len==%u is missing %s",
			     t->input, t->delims, output->len, t->output[len]);
		}

		if (t->kept_empty_shunks != output->kept_empty_shunks) {
			FAIL("shunks(\"%s\",\"%s\")->kept_empty_shunks==%s does not match expected %s",
			     t->input, t->delims,
			     bool_str(output->kept_empty_shunks),
			     bool_str(t->kept_empty_shunks));
		}

		pfree(output);
	}
}

static void check__clone_hunk_as_string(void)
{
	static const struct test {
		struct {
			size_t len;
			char ptr[5];
		} hunk;
		const char output[5];
	} tests[] = {

		{ { 0, "\0a\0", }, "", },
		{ { 1, "\0a\0", }, "", },
		{ { 2, "\0a\0", }, "", },
		{ { 3, "\0a\0", }, "", },

		{ { 0, "a\0bc", }, "",  },
		{ { 1, "a\0bc", }, "a", },
		{ { 2, "a\0bc", }, "a", },
		{ { 3, "a\0bc", }, "a", },
		{ { 4, "a\0bc", }, "a", },

		{ { 0, "ab\0c", }, "",  },
		{ { 1, "ab\0c", }, "a", },
		{ { 2, "ab\0c", }, "ab", },
		{ { 3, "ab\0c", }, "ab", },
		{ { 4, "ab\0c", }, "ab", },

	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT(" input='"PRI_SHUNK"' output='%s'", pri_shunk(t->hunk), t->output);
		char *output = clone_hunk_as_string(t->hunk, "test");
		if (!streq(t->output, output)) {
			FAIL("clone_hunk_as_string() output %s should be '%s'", output, t->output);
		}
		pfreeany(output);
	}
}

int main(int argc, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	if (argc > 1) {
		cur_debugging = -1;
	}

	check_hunk_eq();
	check_shunk_slice();
	check_shunk_token();
	check_shunk_span();
	check_shunk_clone();
	check__hunk_char__hunk_byte();
	check_hunk_char_is();
	check__shunk_to_uintmax();
	check__shunk_to_intmax();
	check_ntoh_hton_hunk();
	check__hunk_get__hunk_put();
	check_hunks();
	check__hunk_append();
	check__clone_hunk_as_string();

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
