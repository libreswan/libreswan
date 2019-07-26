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
#include "shunk.h" /* shunk_t */

unsigned fails;

#define PRINT_LR(FILE, FMT, ...)					\
	fprintf(FILE, "%s[%zu]: '%s' vs '%s'" FMT "\n",			\
		__func__, ti,						\
		t->l == NULL ? "NULL" : t->l,				\
		t->r == NULL ? "NULL" : t->r,				\
		##__VA_ARGS__);

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

static void shunk_eq_check(void)
{
	static const struct test {
		const char *l;
		const char *r;
		bool eq;
		bool caseeq;
		bool thingeq;
	} tests[] = {
		/*
		 * Like strings, NULL and EMPTY ("") shunks are
		 * considered different.
		 */
		{ NULL, NULL, true, true, false, },
		{ NULL, "", false, false, false, },
		{ "", NULL, false, false, false, },
		{ "", "", true, true, false, },

		{ "", "a", false, false, false, },
		{ "a", "", false, false, false, },

		{ "a", "a", true, true, false, },
		{ "a", "A", false, true, false, },
		{ "A", "a", false, true, false, },
		{ "a", "b", false, false, false, },

		{ "a", "aa", false, false, false, },
		{ "aa", "a", false, false, false, },
		{ "thing", "a", false, false, true, },
	};

	static const struct {
		char t, h, i, n, g;
	} thing = { 't', 'h', 'i', 'n', 'g', };

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_LR(stdout, "");
		shunk_t l = shunk1(t->l);
		shunk_t r = shunk1(t->r);

		bool t_null = shunk_eq(l, null_shunk);
		if ((t->l == NULL) != t_null) {
			FAIL_LR("shunk_eq(l, null_shunk) returned %s, expecting %s",
				bool_str(t_null), bool_str(t->l == NULL));
		}

		bool t_empty = shunk_eq(l, empty_shunk);
		if (shunk_strcaseeq(l, "") != t_empty) {
			FAIL_LR("shunk_eq(l, empty_shunk) returned %s, expecting %s",
				bool_str(t_empty), bool_str(shunk_strcaseeq(l, "")));
		}

		bool t_caseeq = shunk_caseeq(l, r);
		if (t_caseeq != t->caseeq) {
			FAIL_LR("shunk_caseeq() returned %s, expecting %s",
				bool_str(t_caseeq), bool_str(t->caseeq));
		}

		bool t_eq = shunk_eq(l, r);
		if (t_eq != t->eq) {
			FAIL_LR("shunk_eq() returned %s, expecting %s",
				bool_str(t_eq), bool_str(t->eq));
		}

		bool t_memeq = shunk_memeq(l, r.ptr, r.len);
		if (t_memeq != t->eq) {
			FAIL_LR("shunk_memeq() returned %s, expecting %s",
				bool_str(t_memeq), bool_str(t->eq));
		}

		bool t_thing = shunk_thingeq(l, thing);
		if (t_thing != t->thingeq) {
			FAIL_LR("shunk_thingeq() returned %s, expecting %s",
				bool_str(t_thing), bool_str(t->thingeq));
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
		if (!shunk_eq(r, t_slice)) {
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

		if (!shunk_eq(t_token, shunk1(t->token))) {
			FAIL_S("shunk_token() returned token '"PRI_SHUNK"', expecting '%s'",
				pri_shunk(t_token), t->token);
		}

		if (t_delim != t->delim) {
			FAIL_S("shunk_token() returned delim '%c', expecting '%c'",
			       t_delim, t->delim);
		}

		if (!shunk_eq(t_input, shunk1(t->input))) {
			FAIL_S("shunk_token() returned input '"PRI_SHUNK"', expecting '%s'",
				pri_shunk(t_input),
			       t->input == NULL ? "NULL" : t->input);
		}

	}
}

static void shunk_null_empty_check(void)
{
	static const struct test {
		const char *s;
		bool null;
		bool empty;
	} tests[] = {
		/*
		 * Like strings, NULL and EMPTY ("") shunks are
		 * considered different.
		 */
		{ NULL, true, false, },
		{ "", false, true, },
		{ "a", false, false, },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_S(stdout, "");
		shunk_t s = shunk1(t->s);

		bool t_null = shunk_eq(s, null_shunk);
		if (t->null != t_null) {
			FAIL_S("shunk_eq(s, null_shunk) returned %s, expecting %s",
			       bool_str(t_null), bool_str(t->null));
		}

		bool t_empty = shunk_eq(s, empty_shunk);
		if (t->empty != t_empty) {
			FAIL_S("shunk_eq(s, empty_shunk) returned %s, expecting %s",
			       bool_str(t_empty), bool_str(t->empty));
		}
	}
}

int main(int argc UNUSED, char *argv[] UNUSED)
{
	shunk_eq_check();
	shunk_null_empty_check();
	shunk_slice_check();
	shunk_token_check();
	if (fails > 0) {
		return 1;
	} else {
		return 0;
	}
}
