/* ip address type, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "lswcdefs.h"		/* for MUST_USE_RESULT */
#include "shunk.h"
#include "chunk.h"
#include "err.h"
#include "diag.h"
#include "where.h"
#include "ip_bytes.h"
#include "ip_version.h"
#include "ip_index.h"

struct in_addr;
struct in6_addr;

struct jambuf;
struct ip_info;

extern bool log_ip; /* false -> redact (aka sanitize) ip addresses */

/*
 * Basic data types for the address-handling functions.
 *
 * ip_address et.al. are supposed to be opaque types; do not use their
 * definitions directly, they are subject to change!
 *
 * Because whack sends raw ip_addresses to pluto using a byte
 * stream, this structure needs to be stream friendly - it
 * must not contain pointers (such as a pointer to struct
 * ip_info). so instead it contains an index.
 */

typedef struct {
	bool is_set;
	/*
	 * Index into the struct ip_info array; must be stream
	 * friendly.
	 */
	enum ip_version ip_version; /* 0, IPv4(4), IPv6(6) */

	/*
	 * We need something that makes static IPv4 initializers possible
	 * (struct in_addr requires htonl() which is run-time only).
	 */
	struct ip_bytes bytes;
} ip_address;

#define PRI_ADDRESS "<address-%s:IPv%d["PRI_IP_BYTES"]>"
#define pri_address(A)					\
		((A)->is_set ? "set" : "unset"),	\
			(A)->ip_version,		\
		pri_ip_bytes((A)->bytes)

void pexpect_address(const ip_address *a, where_t where);
#define paddress(A) pexpect_address(A, HERE)

/*
 * Constructors.
 */

ip_address address_from_raw(where_t where, const struct ip_info *afi,
			    const struct ip_bytes bytes);

ip_address address_from_in_addr(const struct in_addr *in);
ip_address address_from_in6_addr(const struct in6_addr *sin6);

diag_t data_to_address(const void *data, size_t sizeof_data,
		      const struct ip_info *af, ip_address *dst) MUST_USE_RESULT;

/* either SHUNK or CHUNK */
#define hunk_to_address(HUNK, AF, DST) data_to_address(HUNK.ptr, HUNK.len, AF, DST)

/* assumes dotted / colon notation */
err_t ttoaddress_num(shunk_t src, const struct ip_info *type, ip_address *dst);
/* if numeric lookup fails, try a DNS lookup */
err_t ttoaddress_dns(shunk_t src, const struct ip_info *type, ip_address *dst);

/* comma/space separated list */

typedef struct {
	unsigned len;
	ip_address *list;
} ip_addresses;

extern const ip_addresses empty_ip_addresses;

diag_t ttoaddresses_num(shunk_t input, const char *delims,
			const struct ip_info *afi,
			ip_addresses *output);

size_t jam_addresses(struct jambuf *buf, ip_addresses addresses);

/*
 * Convert an address to a string:
 *
 * This implements https://tools.ietf.org/html/rfc5952 where zeros in
 * the middle of an IPv6 address are suppressed.  If the IP address is
 * "sensitive" use *_address_sensitive().
 */

typedef struct {
	/* sizeof(string) includes NUL, add 1 for canary */
	char buf[sizeof("[1111:2222:3333:4444:5555:6666:7777:8888]") + 1/*CANARY*/];
} address_buf;

size_t jam_address(struct jambuf *buf, const ip_address *src);
const char *str_address(const ip_address *src, address_buf *dst);

/* either N.N.N.N or [::] */
size_t jam_address_wrapped(struct jambuf *buf, const ip_address *src);
const char *str_address_wrapped(const ip_address *src, address_buf *dst);

/*
 * sensitive: don't print address when !log_ip
 *
 * reversed: in-addr format.
 *
 * raw: This is not the format function you are looking for. For IPv6
 * include all zeros, vis :0:..:0:; when SEPC != '\0' use it as the
 * separator instead of '.' (IPv4) or ':' (IPv6).
 */

typedef struct {
	/* sizeof(string) includes NUL, add 1 for canary */
	char buf[sizeof("4.0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.0.IP6.ARPA.") + 1/*CANARY*/];
}  address_reversed_buf;

size_t jam_address_sensitive(struct jambuf *buf, const ip_address *src);
size_t jam_address_reversed(struct jambuf *buf, const ip_address *src);

const char *str_address_sensitive(const ip_address *src, address_buf *dst);
const char *str_address_reversed(const ip_address *src, address_reversed_buf *buf);

/*
 * Magic values.
 *
 * XXX: While the headers call the all-zero address "ANY" (INADDR_ANY,
 * IN6ADDR_ANY_INIT), the headers also refer to the IPv6 value as
 * unspecified (for instance IN6_IS_ADDR_UNSPECIFIED()) leaving the
 * term "unspecified" underspecified.
 *
 * Consequently an AF_UNSPEC address (i.e., uninitialized or unset),
 * is identified by *_unset().
 */

extern const ip_address unset_address;

bool address_is_unset(const ip_address *address);		/* handles NULL */
const struct ip_info *address_type(const ip_address *address);	/* handles NULL */

const struct ip_info *address_info(const ip_address address);

bool address_is_specified(const ip_address address);

bool address_is_loopback(const ip_address address);

/* are two is_set() addresses identical? */
bool address_eq_address(const ip_address address, const ip_address another);

/*
 * Raw address bytes, both read-only and read-write.
 */
shunk_t address_as_shunk(const ip_address *address);
chunk_t address_as_chunk(ip_address *address);

/*
 * Old style.
 */

/* tests */
extern bool sameaddr(const ip_address *a, const ip_address *b);
extern int addrcmp(const ip_address *a, const ip_address *b);

#endif
