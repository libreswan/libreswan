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

/*
 * XXX: Something to force the order of the port.
 *
 * Probably overkill, but then port byte order and parameters keep
 * being messed up.
 */

#include <stdint.h>
#include <stdbool.h>

#include "ip_port.h"

typedef struct {
	/* XXX: 0 is 0 (is this a good idea?); network ordered */
	ip_port lo;
	ip_port hi;
} ip_port_range;

extern ip_port unset_port_range; /* aka all ports? */

ip_port_range ip_port_range_from_ports(ip_port lo, ip_port hi);

bool port_range_is_unset(ip_port_range port_range);
#define port_range_is_set !port_range_is_unset

typedef struct {
	char buf[sizeof("65535-65535") + 1/*canary*/];
} port_range_buf;

size_t jam_port_range(jambuf_t *buf, ip_port_range port_range);
const char *str_port_range(ip_port_range port_range, port_range_buf *buf);

#endif
