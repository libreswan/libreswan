/* test ip addresses, for libreswan
 *
 * Copyright (C) 2018-2019  Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef IPCHECK_H

extern void ip_address_check(void);
extern void ip_endpoint_check(void);
extern void ip_subnet_check(void);

/*
 * See: https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html
 *
 * Unfortunately common compilers don't support __VA_OPT__(,), so
 * forced to use ,##__VA_ARGS__.
 */

extern unsigned fails;

/* t->input */
#define IPRINT(FILE, FMT, ...)						\
	fprintf(FILE, "%s[%zu]: '%s' " FMT "\n",			\
		__func__, ti, t->input ,##__VA_ARGS__);
#define IFAIL(FMT, ...) {						\
		fails++;						\
		IPRINT(stderr, FMT ,##__VA_ARGS__);			\
	}

/* t->start, t->stop */
#define SSPRINT(FILE, FMT, ...) \
	fprintf(FILE, "%s[%zu]: '%s'-'%s' " FMT "\n",			\
		__func__, ti, t->start, t->stop __VA_OPT__(,)		\
		__VA_ARGS__);
#define SSFAIL(FMT, ...) {						\
		fails++;						\
		SSPRINT(stderr, FMT __VA_OPT__(,) __VA_ARGS__);		\
	}

/* t->low, t->high */
#define LHPRINT(FILE, FMT, ...)						\
	fprintf(FILE, "%s[%zu]: '%s'-'%s' " FMT "\n",			\
		__func__, ti, t->low, t->high __VA_OPT__(,)		\
		__VA_ARGS__)
#define LHFAIL(FMT, ...) {						\
		fails++;						\
		LHPRINT(stderr, FMT __VA_OPT__(,) __VA_ARGS__);		\
	}

#endif
