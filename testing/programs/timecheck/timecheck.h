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
	intmax_t l, r;
	bool lt;
	bool le;
	bool eq;
	bool ge;
	bool gt;
	bool ne;
	bool sentinel;
} time_cmp[];

#define CHECK_TIME_CMP_OP(TIME, CONVERT, O, OP)				\
	{								\
		TIME##_t l = CONVERT(t->l);				\
		TIME##_t r = CONVERT(t->r);				\
		bool o = TIME##_cmp(l, OP, r);				\
		FILE *out = (o == t->O) ? stdout : stderr;		\
		fprintf(out, #TIME"_cmp(%s(%jd), %s, %s(%jd))) -> %s",	\
			#CONVERT, t->l,					\
			#OP,						\
			#CONVERT, t->r,					\
			bool_str(t->O));				\
		if (out == stderr) {					\
			fprintf(out, "; FAIL: returned %s",		\
				bool_str(o));				\
			fails++;					\
		}							\
		fprintf(out, "\n");					\
	}

#define CHECK_TIME_CMP_CONVERT(TIME, CONVERT)				\
	for (const struct time_cmp *t = time_cmp; !t->sentinel; t++) {	\
		CHECK_TIME_CMP_OP(TIME, CONVERT, lt,  <); \
		CHECK_TIME_CMP_OP(TIME, CONVERT, le, <=); \
		CHECK_TIME_CMP_OP(TIME, CONVERT, eq, ==); \
		CHECK_TIME_CMP_OP(TIME, CONVERT, ge, >=); \
		CHECK_TIME_CMP_OP(TIME, CONVERT, gt,  >); \
		CHECK_TIME_CMP_OP(TIME, CONVERT, ne, !=); \
	}

#define CHECK_TIME_CMP_SECONDS(TIME, ...) \
	CHECK_TIME_CMP_CONVERT(TIME, TIME)

#define CHECK_TIME_CMP_MILLISECONDS(TIME, ...) \
	CHECK_TIME_CMP_CONVERT(TIME, TIME##_from_milliseconds)

#endif
