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
#include "jambuf.h"

struct logger;

extern void ip_address_check(void);
extern void ip_endpoint_check(void);
extern void ip_range_check(struct logger *logger);
extern void ip_subnet_check(struct logger *logger);
extern void ip_said_check(void);
extern void ip_info_check(void);
extern void ip_protoport_check(void);
extern void ip_selector_check(struct logger *logger);
extern void ip_sockaddr_check(void);
extern void ip_port_check(void);
extern void ip_port_range_check(void);
extern void ip_cidr_check(void);
extern void ip_protocol_check(void);
extern void ip_packet_check(void);

/*
 * See: https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html
 *
 * Unfortunately common compilers don't support __VA_OPT__(,), so
 * forced to use ,##__VA_ARGS__.
 */

extern unsigned fails;
extern enum have_dns { DNS_NO, HAVE_HOSTS_FILE, DNS_YES, } have_dns;

#define pri_family(FAMILY) ((FAMILY) == 0 ? "0" :	\
			    (FAMILY) == 4 ? "IPv4" :	\
			    (FAMILY) == 6 ? "IPv6" :	\
			    " ???")

#define SA_FAMILY(FAMILY) ((FAMILY) == 0 ? AF_UNSPEC :	\
			   (FAMILY) == 4 ? AF_INET :	\
			   (FAMILY) == 6 ? AF_INET6 :	\
			   -1)

#define IP_TYPE(FAMILY) ((FAMILY) == 4 ? &ipv4_info :	\
			 (FAMILY) == 6 ? &ipv6_info :	\
			 NULL)

#define PREFIX(FILE)							\
	{								\
		const char *file = HERE_FILENAME;			\
		fprintf(FILE, "%s:%d", file, t->line);			\
		fprintf(FILE, " ");					\
		fprintf(FILE, "%s():%d[%zu]", __func__, LN, ti);	\
		fprintf(FILE, " ");					\
	}

#define PRINT(...)							\
	{								\
		PREFIX(stdout);						\
		fprintf(stdout, __VA_ARGS__);				\
		fprintf(stdout,	"\n");					\
	}

#define LN __LINE__

#define FAIL_(...)							\
	{								\
		fflush(stdout);	/* keep in sync */			\
		fails++;						\
		PREFIX(stderr);						\
		fprintf(stderr, "FAILED: ");				\
		fprintf(stderr, __VA_ARGS__);				\
	}

#define FAIL(...)				\
	{					\
		FAIL_(__VA_ARGS__);		\
		fprintf(stderr,	"\n");		\
		continue;			\
	}

#define DIAG_FAIL(DIAG, ...)						\
	{								\
		FAIL(__VA_ARGS__);					\
		fprintf(stderr, "%s", str_diag(*(DIAG)));		\
		pfree_diag(DIAG);					\
		fprintf(stderr,	"\n");					\
		continue;						\
	}

#define CHECK_FAMILY(FAMILY, T, V)					\
	{								\
		const struct ip_info *actual = T##_type(V);		\
		const struct ip_info *expected = IP_TYPE(FAMILY);	\
		if (expected != actual) {				\
			T##_buf tb;					\
			const char *en = (actual == NULL ? "unset" :	\
					  actual->af_name);		\
			const char *an = (expected == NULL ? "unset" :	\
					  expected->af_name);		\
			FAIL(#T"_type(%s) returned %s, expecting %s",	\
			     str_##T(V, &tb), an, en);			\
		}							\
	}

#define CHECK_TYPE(T)				\
	CHECK_FAMILY(t->family, T, T)

#define CHECK_STR(BUF, OP, EXPECTED, ...)				\
		{							\
			if (EXPECTED == NULL) {				\
				FAIL(#EXPECTED " is NULL");		\
			}						\
			BUF buf;					\
			const char *s = str_##OP(__VA_ARGS__, &buf);	\
			if (s == NULL) {				\
				FAIL("str_"#OP"() unexpectedly returned NULL"); \
			}						\
			printf("expected %s s %s\n", EXPECTED, s);	\
			if (!strcaseeq(EXPECTED, s)) {			\
				FAIL("str_"#OP"() returned '%s', expected '%s'", \
				     s, EXPECTED);			\
			}						\
			size_t ssize = strlen(s);			\
			char js[sizeof(buf)];				\
			struct jambuf jbuf = ARRAY_AS_JAMBUF(js);		\
			size_t jsize = jam_##OP(&jbuf, __VA_ARGS__);	\
			if (jsize != ssize) {				\
				FAIL("jam_"#OP"() returned %zu, expecting %zu", \
				     jsize, ssize);			\
			}						\
		}

#define CHECK_STR2(T)                                                   \
                {                                                       \
			if (t->str == NULL) {				\
				FAIL("t->str is NULL");			\
			}						\
                        T##_buf buf;                                    \
                        const char *str = str_##T(T, &buf);             \
                        if (str == NULL) {                              \
                                FAIL("str_"#T"(%s) unexpectedly returned NULL",\
                                     t->str);                           \
                        }                                               \
                        if (!strcaseeq(t->str, str)) {                  \
                                FAIL("str_"#T"(%s) returned '%s', expecting '%s'", \
                                     t->str, str, t->str);		\
                        }                                               \
                        size_t str_size = strlen(str);                  \
                        char jam_str[sizeof(buf)];                      \
                        struct jambuf jambuf = ARRAY_AS_JAMBUF(jam_str); \
                        size_t jam_size = jam_##T(&jambuf, T);          \
                        if (jam_size != str_size) {                     \
                                FAIL("jam_"#T"() returned %zu, expecting %zu", \
                                     jam_size, str_size);               \
                        }                                               \
                        if (!strcaseeq(t->str, jam_str)) {              \
                                FAIL("jam_"#T"(%s) emitted '%s', expecting '%s'", \
                                     t->str, jam_str, t->str);		\
                        }                                               \
                }

/*
 * Call a predicate.  First form assumes NULL allowed, second does
 * not.
 */

#define CHECK_COND(T,COND)						\
		{							\
			bool cond = T##_##COND(T);			\
			if (cond != t->COND) {				\
				T##_buf b;				\
				FAIL(#T"_"#COND"(%s) returned %s, expecting %s", \
				     str_##T(T, &b),			\
				     bool_str(cond),			\
				     bool_str(t->COND));		\
			}						\
		}

#define CHECK_COND2(T,COND)						\
		if (T != NULL) {					\
			bool cond = T##_##COND(*T);			\
			if (cond != t->COND) {				\
				T##_buf b;				\
				FAIL(#T"_"#COND"(%s) returned %s, expecting %s", \
				     str_##T(T, &b),			\
				     bool_str(cond),			\
				     bool_str(t->COND));		\
			}						\
		}

#define CHECK_UNOP(T, OP, PRI, STR)					\
		if (T != NULL) {					\
			typeof(t->OP) op = T##_##OP(*T);		\
			if (op != t->OP) {				\
				T##_buf b;				\
				FAIL(#T "_" #OP "(%s) returned "PRI", expecting "PRI, \
				     str_##T(T, &b),			\
				     STR(op),				\
				     STR(t->OP));			\
			}						\
		}

#define IPv4_MAX "255.255.255.255"
#define IPv6_MAX "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

#endif
