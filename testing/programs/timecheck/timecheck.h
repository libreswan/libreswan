/* test *time_t code, for libreswan
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

#ifndef TIMECHECK_H
#define TIMECHECK_H

extern int fails;

void check_deltatime(void);
void check_monotime(void);
void check_realtime(void);

extern const struct time_cmp {
	intmax_t l_ms, r_ms;
	bool lt;
	bool le;
	bool eq;
	bool ge;
	bool gt;
	bool ne;
	bool sentinel;
} time_cmp[];

#define CHECK_TIME_CMP_OP(T, O, OP, ...)				\
	{								\
		bool o = T##time_cmp(l, OP, r);				\
		FILE *out = (o == t->O) ? stdout : stderr;		\
		T##time_buf lb, rb;					\
		fprintf(out, #T"time_cmp(%s, %s, %s)) -> %s",		\
			str_##T##time(l, ##__VA_ARGS__, &lb),		\
			#OP,						\
			str_##T##time(r, ##__VA_ARGS__, &rb),		\
			bool_str(t->O));				\
		if (out == stderr) {					\
			fprintf(out, "; FAIL: returned %s",		\
				bool_str(o));				\
			fails++;					\
		}							\
		fprintf(out, "\n");					\
	}

#define CHECK_TIME_CMP(T, ...)						\
	for (const struct time_cmp *t = time_cmp; !t->sentinel; t++) {	\
		T##time_t l = T##time_ms(t->l_ms);			\
		T##time_t r = T##time_ms(t->r_ms);			\
		CHECK_TIME_CMP_OP(T, lt,  <, ##__VA_ARGS__);		\
		CHECK_TIME_CMP_OP(T, le, <=, ##__VA_ARGS__);		\
		CHECK_TIME_CMP_OP(T, eq, ==, ##__VA_ARGS__);		\
		CHECK_TIME_CMP_OP(T, ge, >=, ##__VA_ARGS__);		\
		CHECK_TIME_CMP_OP(T, gt,  >, ##__VA_ARGS__);		\
		CHECK_TIME_CMP_OP(T, ne, !=, ##__VA_ARGS__);		\
	}

#endif
