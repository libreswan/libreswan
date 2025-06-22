/* ip port range, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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
 */

#ifndef IP_PORT_RANGE_H
#define IP_PORT_RANGE_H

#include <stdint.h>
#include <stdbool.h>

#include "ip_port.h"

/*
 * XXX: open question: all ports should be represented as 0..65535,
 * but how to represent no ports (magic 0 0?).
 *
 * This feeds into the selector code.
 */

typedef struct {
	/* be consistent with ip_base */
	struct {
		bool is_set;
	} ip;

	unsigned lo;
	unsigned hi;
} ip_port_range;

ip_port_range port_range_from_ports(ip_port lo, ip_port hi);

extern const ip_port_range unset_port_range;

typedef struct {
	char buf[sizeof("65535-65535") + 1/*canary*/];
} port_range_buf;

size_t jam_port_range(struct jambuf *buf, ip_port_range port_range);
const char *str_port_range(ip_port_range port_range, port_range_buf *buf);

#endif
