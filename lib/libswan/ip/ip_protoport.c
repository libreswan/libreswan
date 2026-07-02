/*
 * conversion from protocol/port string to protocol and port
 *
 * Copyright (C) 2002 Mario Strasser <mast@gmx.net>,
 *                    Zuercher Hochschule Winterthur,
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

#include "jambuf.h"

#include "ip_protoport.h"

#include "constants.h"		/* for zero() */
#include "chunk.h"		/* for clone_bytes_as_string() */
#include "lswlog.h"		/* for pexpect() */

const ip_protoport unset_protoport;

size_t jam_protoport(struct jambuf *buf, const ip_protoport *protoport)
{
	if (protoport == NULL) {
		return jam(buf, "<null-protoport>");
	}

	if (!protoport->ip.is_set) {
		return jam(buf, "<unset-protoport>");
	}

	if (protoport->ipproto == 0) {
		pexpect(protoport->has_port_wildcard == false);
		pexpect(protoport->hport == 0);
		return jam_string(buf, "%any");
	}

	size_t s = 0;
	s += jam(buf, "%s/", protocol_from_ipproto(protoport->ipproto)->name);
	if (protoport->has_port_wildcard) {
		pexpect(protoport->hport == 0);
		s += jam_string(buf, "%any");
	} else {
		/* 0 implies 0-65535 */
		s += jam(buf, "%u", protoport->hport);
	}
	return s;
}

const char *str_protoport(const ip_protoport *protoport, protoport_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_protoport(&jambuf, protoport);
	return buf->buf;
}
