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

#include <stdio.h>
#include <stdbool.h>
#include "ip_info.h"
#include "where.h"

extern void ip_address_check(void);
extern void ip_endpoint_check(void);
extern void ip_range_check(void);
extern void ip_subnet_check(void);
extern void ip_said_check(void);
extern void ip_info_check(void);
extern void ip_protoport_check(void);
extern void ip_selector_check(void);
extern void ip_sockaddr_check(void);
extern void ip_port_check(void);
extern void ip_port_range_check(void);

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

#define FAIL(PRINT, FMT, ...)						\
	{								\
		fails++;						\
		PRINT(stderr, " "FMT" ("PRI_WHERE")",##__VA_ARGS__,	\
		      pri_where(HERE));					\
		continue;						\
	}

/* t->family, t->in */
#define PRINT_IN(FILE, FMT, ...)					\
	PRINT(FILE, "%s '%s'"FMT,					\
	      pri_family(t->family), t->in ,##__VA_ARGS__);

#define FAIL_IN(FMT, ...) FAIL(PRINT_IN, FMT,##__VA_ARGS__)

/* t->family, t->lo, t->hi */
#define PRINT_LO2HI(FILE, FMT, ...)					\
	PRINT(FILE, "%s '%s'-'%s'"FMT,					\
	      pri_family(t->family), t->lo, t->hi,##__VA_ARGS__)

#define FAIL_LO2HI(FMT, ...) FAIL(PRINT_LO2HI, FMT,##__VA_ARGS__)

#define CHECK_FAMILY(PRINT, FAMILY, TYPE)				\
	{								\
		const struct ip_info *actual = TYPE;			\
		const char *actual_name =				\
			actual == NULL ? "unspec" : actual->af_name;	\
		const struct ip_info *expected = IP_TYPE(FAMILY);	\
		const char *expected_name =				\
			expected == NULL ? "unspec" : expected->af_name; \
		if (actual != expected) {				\
			FAIL(PRINT, " "#TYPE" returned %s, expecting %s", \
			     actual_name, expected_name);		\
		}							\
	}

#define CHECK_TYPE(PRINT, TYPE)						\
	CHECK_FAMILY(PRINT, t->family, TYPE)

#define CHECK_ADDRESS(PRINT, ADDRESS)					\
	{								\
		CHECK_TYPE(PRINT, address_type(ADDRESS));		\
		/* aka address_type(ADDRESS) == NULL; */		\
		bool set = address_is_set(ADDRESS);			\
		if (set != t->set) {				\
			FAIL(PRINT, " address_is_set() returned %s; expected %s", \
			     bool_str(set), bool_str(t->set));	\
		}							\
		bool any = address_is_any(ADDRESS);			\
		if (any != t->any) {					\
			FAIL(PRINT, " address_is_any() returned %s; expected %s", \
			     bool_str(any), bool_str(t->any));		\
		}							\
		bool specified = address_is_specified(ADDRESS);		\
		if (specified != t->specified) {			\
			FAIL(PRINT, " address_is_specified() returned %s; expected %s", \
			     bool_str(specified), bool_str(t->specified)); \
		}							\
		bool loopback = address_is_loopback(ADDRESS);		\
		if (loopback != t->loopback) {				\
			FAIL(PRINT, " address_is_loopback() returned %s; expected %s", \
			     bool_str(loopback), bool_str(t->loopback)); \
		}							\
	}

#define CHECK_STR(BUF, OP, EXPECTED, ...)				\
		{							\
			BUF buf;					\
			const char *s = str_##OP(__VA_ARGS__, &buf);	\
			if (s == NULL) {				\
				FAIL_IN("str_"#OP"() unexpectedly returned NULL"); \
			}						\
			printf("expected %s s %s\n", EXPECTED, s);	\
			if (!strcaseeq(EXPECTED, s)) {			\
				FAIL_IN("str_"#OP"() returned '%s', expected '%s'", \
					s, EXPECTED);			\
			}						\
			size_t ssize = strlen(s);			\
			char js[sizeof(buf)];				\
			jambuf_t jbuf = ARRAY_AS_JAMBUF(js);		\
			size_t jsize = jam_##OP(&jbuf, __VA_ARGS__);	\
			if (jsize != ssize) {				\
				FAIL_IN("jam_"#OP"() returned %zu, expecting %zu", \
					jsize, ssize);			\
			}						\
		}

#endif
