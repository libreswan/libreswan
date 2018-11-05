/*
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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

#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H

#include "chunk.h"
#include "err.h"

/*
 * Hack around this file being sucked into linux kernel module builds.
 */
#include <netinet/in.h>		/* for struct sockaddr_in */
#ifdef HAVE_INET6_IN6_H
#include <netinet6/in6.h>	/* for struct sockaddr_in6 */
#endif

#ifdef NEED_SIN_LEN
#define SET_V4(a)	{ (a).u.v4.sin_family = AF_INET; (a).u.v4.sin_len = sizeof(struct sockaddr_in); }
#define SET_V6(a)	{ (a).u.v6.sin6_family = AF_INET6; (a).u.v6.sin6_len = sizeof(struct sockaddr_in6); }
#else
#define SET_V4(a)	{ (a).u.v4.sin_family = AF_INET; }
#define SET_V6(a)	{ (a).u.v6.sin6_family = AF_INET6; }
#endif

struct lswlog;

/*
 * The type IP_ADDRESS is shared between KLIPS (kernel module) and
 * PLUTO.  Its definition is buried in the common include file
 * "libreswan.h".
 *
 * This header contains declarations for userland specific extensions.
 * Their implementation is found in libswan.a.
 *
 * When KLIPS goes away, the definition of IP_ADDRESS et.al., can be
 * moved here.
 */

/*
 * Basic data types for the address-handling functions.
 * ip_address and ip_subnet are supposed to be opaque types; do not
 * use their definitions directly, they are subject to change!
 */

typedef struct {
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} u;
} ip_address;

/* network byte ordered */
int nportof(const ip_address *src);
ip_address nsetportof(int port, ip_address dst);

/* host byte ordered */
int hportof(const ip_address *src);
ip_address hsetportof(int port, const ip_address dst);

/* XXX: compatibility */
#define portof(SRC) nportof((SRC))
#define setportof(PORT, DST) { *(DST) = nsetportof(PORT, *(DST)); }

struct sockaddr *sockaddrof(const ip_address *src);
size_t sockaddrlenof(const ip_address *src);

/* RFC 1886 old IPv6 reverse-lookup format is the bulkiest */

#define ADDRTOT_BUF     (32 * 2 + 3 + 1 + 3 + 1 + 1)
typedef struct {
	char private_buf[ADDRTOT_BUF]; /* defined in libreswan.h */
} ipstr_buf;

const char *ipstr(const ip_address *src, ipstr_buf *b);
const char *sensitive_ipstr(const ip_address *src, ipstr_buf *b);

/* See: ipstr() / sensitive_ipstr() */
size_t lswlog_ip(struct lswlog *buf, const ip_address *ip);
size_t lswlog_sensitive_ip(struct lswlog *buf, const ip_address *ip);

/*
 * isvalidaddr(): true when ADDR contains some sort of IPv4 or IPv6
 * address.
 *
 * The relationship !isvalidaddr() IFF ipstr()=="<invalid>" is ment to
 * hold.  Both the *addrtot() (used by ipstr()) and *portof() seem to
 * use the same check.  hportof() just happens to be an easy way to
 * access it.
 *
 * The routine isanyaddr() isn't used as, in addition to "<invalid>"
 * it includes magic "any" IPv4 and IPv6 addresses.
 */

#define isvalidaddr(ADDR) (hportof(ADDR) >= 0)

/*
 * address as a chunk
 *
 * XXX: chunk_t doesn't do const so this strips off the constiness of
 * address :-(
 */
chunk_t same_ip_address_as_chunk(const ip_address *address);

/*
 * Old style.
 */

/* looks up names in DNS */
extern err_t ttoaddr(const char *src, size_t srclen, int af, ip_address *dst);

/* does not look up names in DNS */
extern err_t ttoaddr_num(const char *src, size_t srclen, int af, ip_address *dst);

extern err_t tnatoaddr(const char *src, size_t srclen, int af, ip_address *dst);
extern size_t addrtot(const ip_address *src, int format, char *buf, size_t buflen);

/* initializations */
extern err_t loopbackaddr(int af, ip_address *dst);
extern err_t unspecaddr(int af, ip_address *dst);
extern err_t anyaddr(int af, ip_address *dst);
extern err_t initaddr(const unsigned char *src, size_t srclen, int af,
	       ip_address *dst);
extern err_t add_port(int af, ip_address *addr, unsigned short port);

/* misc. conversions and related */
extern int addrtypeof(const ip_address *src);
extern size_t addrlenof(const ip_address *src);
extern size_t addrbytesptr_read(const ip_address *src, const unsigned char **dst);
extern size_t addrbytesptr_write(ip_address *src, unsigned char **dst);
extern size_t addrbytesof(const ip_address *src, unsigned char *dst, size_t dstlen);
extern int masktocount(const ip_address *src);

/* tests */
extern bool sameaddr(const ip_address *a, const ip_address *b);
extern int addrcmp(const ip_address *a, const ip_address *b);
extern bool sameaddrtype(const ip_address *a, const ip_address *b);
extern int isanyaddr(const ip_address *src);
extern int isunspecaddr(const ip_address *src);
extern int isloopbackaddr(const ip_address *src);

#endif
