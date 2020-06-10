/* header file for protoport,
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
 *
 */

#ifndef IP_PROTOPORT_H
#define IP_PROTOPORT_H    /* seen it, no need to see it again */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "err.h"
#include "jambuf.h"
#include "ip_port.h"

typedef struct {
	bool any_port;
	unsigned port;		/* 1..65535; 0->0-65535 */
	unsigned protocol;	/* 1..255; 0->unset */
} ip_protoport;

extern const ip_protoport unset_protoport;

ip_protoport protoport2(unsigned ipproto, ip_port port);

err_t ttoprotoport(const char *src, ip_protoport *protoport);
err_t ttoipproto(const char *text, unsigned *ipproto);
err_t ttoport(const char *text, unsigned *port);

bool protoport_is_set(const ip_protoport *protoport);
bool protoport_has_any_port(const ip_protoport *protoport);

typedef struct {
	char buf[32+1+32+1+1];
} protoport_buf;

size_t jam_protoport(jambuf_t *buf, const ip_protoport *protoport);
const char *str_protoport(const ip_protoport *protoport, protoport_buf *buf);

#endif
