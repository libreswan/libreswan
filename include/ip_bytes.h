/* ip address type, for libreswan
 *
 * Copyright (C) 2021 Andrew Cagney
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

#ifndef IP_BYTES_H
#define IP_BYTES_H

#include <stdint.h>		/* for uint8_t */

struct ip_info;
enum ip_version;

/*
 * We need something that makes static IPv4 initializers possible
 * (struct in_addr requires htonl() which is run-time only).
 */

struct ip_bytes {
	uint8_t byte[16];
};

extern const struct ip_bytes unset_ip_bytes;

#define PRI_IP_BYTES "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
#define pri_ip_bytes(B)							\
	(B).byte[0],							\
		(B).byte[1],						\
		(B).byte[2],						\
		(B).byte[3],						\
		(B).byte[4],						\
		(B).byte[5],						\
		(B).byte[6],						\
		(B).byte[7],						\
		(B).byte[8],						\
		(B).byte[9],						\
		(B).byte[10],						\
		(B).byte[11],						\
		(B).byte[12],						\
		(B).byte[13],						\
		(B).byte[14],						\
		(B).byte[15]

/*
 * Modify address bytes broken down according to AFI as
 * ROUTING-PREFIX:HOST-ID.
 */

extern const struct ip_routing_prefix_blit keep_routing_prefix;
extern const struct ip_routing_prefix_blit clear_routing_prefix;
extern const struct ip_routing_prefix_blit set_routing_prefix;
extern const struct ip_host_identifier_blit clear_host_identifier;
extern const struct ip_host_identifier_blit set_host_identifier;

struct ip_bytes ip_bytes_blit(const struct ip_info *afi,
			      const struct ip_bytes bytes,
			      const struct ip_routing_prefix_blit *routing_prefix,
			      const struct ip_host_identifier_blit *host_identifier,
			      int prefix_len);

/* Calculate l-r using unsigned arithmetic */
struct ip_bytes ip_bytes_sub(const struct ip_info *afi,
			     const struct ip_bytes l,
			     const struct ip_bytes r);

/* find first non-zero bit from left */
int ip_bytes_first_set_bit(const struct ip_info *afi,
			   const struct ip_bytes bytes);

/* match prefixes, or -1 */

int ip_bytes_prefix_len(const struct ip_info *afi,
			const struct ip_bytes lo,
			const struct ip_bytes hi);
int ip_bytes_host_len(const struct ip_info *afi,
		      const struct ip_bytes lo,
		      const struct ip_bytes hi);
int ip_bytes_mask_len(const struct ip_info *afi,
		      const struct ip_bytes bytes);

int ip_bytes_cmp(enum ip_version l_version, const struct ip_bytes l_bytes,
		 enum ip_version r_version, const struct ip_bytes r_bytes);

bool ip_bytes_is_zero(const struct ip_bytes *bytes);

size_t jam_ip_bytes_range(struct jambuf *buf,
			  const struct ip_info *afi,
			  const struct ip_bytes lo,
			  const struct ip_bytes hi);

#endif
