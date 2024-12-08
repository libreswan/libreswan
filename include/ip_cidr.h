/* ip cidr (prefix/host-id), for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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

#ifndef IP_CIDR_H
#define IP_CIDR_H

/*
 * NETWORK_PREFIX/HOST_IDENTIFIER
 *
 * Unlike ip_subnet, this allows a non-zero host_identifier.
 */

#include "ip_bytes.h"
#include "ip_version.h"
#include "ip_address.h"

struct jambuf;

typedef struct {
	bool is_set;
	enum ip_version version;
	struct ip_bytes bytes;
	unsigned prefix_len;
} ip_cidr;

#define PRI_CIDR "<cidr-%s:IPv%d["PRI_IP_BYTES"]/%u>"
#define pri_cidr(A)							\
		((A).is_set ? "set" : "unset"),				\
		(A).version,						\
		pri_ip_bytes((A).bytes),					\
		(A).prefix_len

void pexpect_cidr(const ip_cidr a, where_t where);
#define pcidr(A) pexpect_cidr(A, HERE)

extern const ip_cidr unset_cidr;

/* convert CIDR address/mask; does not judge the result */
ip_cidr cidr_from_raw(where_t where, const struct ip_info *afi,
		      const struct ip_bytes bytes,
		      unsigned prefix_bits);

diag_t data_to_cidr(const void *data, size_t data_size, unsigned prefix_len,
		    const struct ip_info *afi, ip_cidr *cidr) MUST_USE_RESULT;
#define hunk_to_cidr(HUNK, PREFIX_LEN, AFI, CIDR) \
	data_to_cidr((HUNK).ptr, (HUNK).len, PREFIX_LEN, AFI, CIDR)

ip_cidr cidr_from_address(ip_address address);

/*
 * return why, if CDIR isn't useful.
 *
 * "specified"? wikipedia refers to ::/0 as "Default route (no
 * specific route)" and ::/128 as "Unspecified address". While these
 * addresses are valid, they don't specifically specify anything...
 */

err_t cidr_check(const ip_cidr cidr);
bool cidr_is_specified(const ip_cidr cidr);

const struct ip_info *cidr_type(const ip_cidr *cidr);	/* handles NULL */
const struct ip_info *cidr_info(const ip_cidr cidr);

ip_address cidr_address(const ip_cidr cidr);
ip_address cidr_prefix(const ip_cidr cidr);
ip_address cidr_host(const ip_cidr cidr);
unsigned cidr_prefix_len(const ip_cidr cidr);

/* are two is_set() cidrs identical? */
bool cidr_eq_cidr(const ip_cidr address, const ip_cidr another);

/*
 * Raw address bytes, both read-only and read-write.
 */
shunk_t cidr_as_shunk(const ip_cidr *cidr);
chunk_t cidr_as_chunk(ip_cidr *cidr);

err_t ttocidr_num(shunk_t src, const struct ip_info *afi, ip_cidr *cidr);

typedef struct {
	char buf[sizeof(address_buf) + 4/*/128*/];
} cidr_buf;

size_t jam_cidr(struct jambuf *buf, const ip_cidr *cidr);
const char *str_cidr(const ip_cidr *cidr, cidr_buf*buf);

#endif
