/* ip address type, for libreswan
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

#ifndef IP_BYTES_H
#define IP_BYTES_H

#include <stdint.h>

/*
 * We need something that makes static IPv4 initializers possible
 * (struct in_addr requires htonl() which is run-time only).
 */

typedef struct {
	uint8_t byte[16];
} ip_bytes;

extern const ip_bytes unset_bytes;

/*
 * Modify bytes.
 */

extern const struct ip_blit set_bits;
extern const struct ip_blit clear_bits;
extern const struct ip_blit keep_bits;

ip_bytes bytes_blit(const ip_bytes in, size_t len,
		    const struct ip_blit *routing_prefix,
		    const struct ip_blit *host_id,
		    unsigned nr_mask_bits);

#endif
