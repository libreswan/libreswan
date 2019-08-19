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
#include "ip_info.h"

extern void ip_address_check(void);
extern void ip_endpoint_check(void);
extern void ip_range_check(void);
extern void ip_subnet_check(void);
extern void ip_said_check(void);

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

#define SA_FAMILY(FAMILY) ((FAMILY) == 0 ? AF_UNSPEC :	\
			   (FAMILY) == 4 ? AF_INET :	\
			   (FAMILY) == 6 ? AF_INET6 :	\
			   -1)

#define IP_TYPE(FAMILY) ((FAMILY) == 4 ? &ipv4_info :	\
			 (FAMILY) == 6 ? &ipv6_info :	\
			 NULL)

#define PRINT(FILE, FMT, ...)						\
	fprintf(FILE, "%s[%zu]:"FMT"\n", __func__, ti,##__VA_ARGS__)

/* t->family, t->in */
#define PRINT_IN(FILE, FMT, ...)					\
	PRINT(FILE, "%s '%s'"FMT,					\
	      pri_family(t->family), t->in ,##__VA_ARGS__);

#define FAIL_IN(FMT, ...)						\
	{								\
		fails++;						\
		PRINT_IN(stderr, " "FMT" (%s() %s:%d)",##__VA_ARGS__,	\
			 __func__, __FILE__, __LINE__);			\
		continue;						\
	}

/* t->family, t->lo, t->hi */
#define PRINT_LO2HI(FILE, FMT, ...)					\
	PRINT(FILE, "%s '%s'-'%s'"FMT,					\
	      pri_family(t->family), t->lo, t->hi,##__VA_ARGS__)

#define FAIL_LO2HI(FMT, ...) {						\
		fails++;						\
		PRINT_LO2HI(stderr, " "FMT" (%s() %s:%d)",##__VA_ARGS__, \
			    __func__, __FILE__, __LINE__);		\
		continue;						\
	}


#define CHECK_TYPE(FAIL, TYPE, VERSION)					\
	{								\
		const struct ip_info *actual = TYPE;			\
		const char *actual_name =				\
			actual == NULL ? "unspec" : actual->af_name;	\
		const struct ip_info *expected = IP_TYPE(VERSION);	\
		const char *expected_name =				\
			expected == NULL ? "unspec" : expected->af_name; \
		if (actual != expected) {				\
			FAIL(#TYPE" returned %s, expecting %s",		\
			     actual_name, expected_name);		\
		}							\
	}

#endif
