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

#include <stdbool.h>

extern void ip_address_check(void);
extern void ip_endpoint_check(void);
extern void ip_range_check(void);
extern void ip_subnet_check(void);

/*
 * See: https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html
 *
 * Unfortunately common compilers don't support __VA_OPT__(,), so
 * forced to use ,##__VA_ARGS__.
 */

extern unsigned fails;
extern bool use_dns;

#define pri_family(FAMILY) ((FAMILY) == 0 ? "" :	\
			    (FAMILY) == 4 ? " IPv4" :	\
			    (FAMILY) == 6 ? " IPv6" :	\
			    " ???")

#define SA_FAMILY(FAMILY) (FAMILY == 0 ? AF_UNSPEC :	\
			   FAMILY == 4 ? AF_INET :	\
			   FAMILY == 6 ? AF_INET6 :	\
			   -1)

/* t->family, t->in */
#define PRINT_IN(FILE, FMT, ...)					\
	fprintf(FILE, "%s[%zu]:%s '%s'" FMT "\n",			\
		__func__, ti, pri_family(t->family),			\
		t->in ,##__VA_ARGS__);
#define FAIL_IN(FMT, ...)						\
	{								\
		fails++;						\
		PRINT_IN(stderr, ": "FMT ,##__VA_ARGS__);		\
		continue;						\
	}

/* t->family, t->lo, t->hi */
#define PRINT_LO2HI(FILE, FMT, ...)					\
	fprintf(FILE, "%s[%zu]:%s '%s'-'%s'" FMT "\n",			\
		__func__, ti, pri_family(t->family),			\
		t->lo, t->hi,##__VA_ARGS__)
#define FAIL_LO2HI(FMT, ...) {						\
		fails++;						\
		PRINT_LO2HI(stderr, ": "FMT ,##__VA_ARGS__);		\
		continue;						\
	}

#endif
