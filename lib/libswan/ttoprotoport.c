/* conversion from protocol/port string to protocol and port
 *
 * Copyright (C) 2002 Mario Strasser <mast@gmx.net>
 * Copyright (C) 2002 Zuercher Hochschule Winterthur
 * Copyright (C) 2025 Andrew Cagney
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

/*
 * ttoprotoport() - converts from protocol/port string to protocol and
 * port
 */

err_t ttoprotoport(shunk_t src, ip_protoport *protoport)
{
	err_t err;
	zero(protoport);

	shunk_t cursor = src;

	/* Split PROTOCOL / PORT */

	char slash = '\0';
	shunk_t protocol_name = shunk_token(&cursor, &slash, "/");
	shunk_t port_name = cursor;

	if (protocol_name.len == 0) {
		return "missing protocol";
	}

	/* extract protocol by trying to resolve it by name */

	const struct ip_protocol *protocol;
	if (hunk_strcaseeq(protocol_name, "%any")) {
		protocol = &ip_protocol_all;
	} else {
		err = ttoprotocol(protocol_name, &protocol);
		if (err != NULL) {
			return err;
		}
	}

	/* is there a port wildcard? */

	ip_port port;
	bool port_wildcard;

	if (port_name.len == 0) {
		/*
		 * Either PROTOCOL or PROTOCOL /
		 *
		 * Different to wildcard PROTOCOL / %any.
		 */
		port = unset_port;
		port_wildcard = false;
	} else if (hunk_strcaseeq(port_name, "%any")) {
		/* PROTOCOL / %any -- port wildcard */
		if (protocol == &ip_protocol_all) {
			return "port wildcard (%any) requires a valid protocol";
		}
		port = unset_port;
		port_wildcard = true;
	} else {
		/* Port 0-65535 is different to %any */
		err = ttoport(port_name, &port);
		if (err != NULL) {
			return err;
		}
		if (protocol->ipproto == 0 && port.hport != 0) {
			return "protocol 0 must have 0 port";
		}
		port_wildcard = false;
	}

	protoport->is_set = true;
	protoport->ipproto = protocol->ipproto;
	protoport->has_port_wildcard = port_wildcard;
	protoport->hport = port.hport;
	return NULL;
}
