/* ip port (port), for libreswan
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

#ifndef IP_PORT_H
#define IP_PORT_H

/*
 * XXX: Something to force the order of the port.
 *
 * Probably overkill, but then port byte order and parameters keep
 * being messed up.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "err.h"

struct jambuf;

typedef struct {
	bool is_set;
	/*
	 * XXX: 0 is interpreted as either 0, or any-port (is this a
	 * good idea?); host-byte ordered.
	 */
	unsigned hport;
} ip_port;

extern const ip_port unset_port; /* aka all ports? */

ip_port ip_hport(unsigned hport);
ip_port ip_nport(unsigned nport);

unsigned hport(ip_port port);
unsigned nport(ip_port port);

bool port_is_specified(ip_port p);
#define port_eq(L,R) ((L).hport == (R).hport)

err_t ttoport(shunk_t text, ip_port *port);

/*
 * XXX: to choices, which is better?
 *
 * str/jam can potentially deal with NULL and <unset> but should they?
 */

#define PRI_HPORT "%u"
#define pri_hport(PORT) hport(PORT)

#define PRI_NPORT "%04x"
#define pri_nport(PORT) hport(PORT) /* yes, hport() */

typedef struct {
	char buf[sizeof("65535")+1/*canary*/];
} port_buf;

size_t jam_hport(struct jambuf *buf, ip_port port);
size_t jam_nport(struct jambuf *buf, ip_port port);

const char *str_hport(ip_port port, port_buf *buf);
const char *str_nport(ip_port port, port_buf *buf);

#endif
