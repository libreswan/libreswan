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

/*
 * ttoprotoport - converts from protocol/port string to protocol and
 * port
 */
err_t ttoprotoport(const char *src, ip_protoport *protoport)
{
	err_t err;
	zero(protoport);

	/* get the length of the string */
	size_t src_len = strlen(src);

	/* locate delimiter '/' between protocol and port */
	char *end = strchr(src, '/');
	const char *service_name;
	shunk_t proto_name;
	if (end != NULL) {
		/* PROT/PORT */
		proto_name = shunk2(src, end - src);
		service_name = end + 1;
	} else if (streq(src, "%any")) {
		/* %any */
		proto_name = shunk1("unknown");
		service_name = src + src_len; /*NUL*/
	} else {
		/* PROTO */
		proto_name = shunk2(src, src_len);
		service_name = src + src_len; /*NUL*/
	}

	/* extract protocol by trying to resolve it by name */
	const struct ip_protocol *protocol;
	err = ttoprotocol(proto_name, &protocol);
	if (err != NULL) {
		return err;
	}

	/* is there a port wildcard? */
	ip_port port;
	bool port_wildcard;
	if (service_name[0] == '\0') {
		/* allow N/ and N; different to N/%any */
		port = unset_port;
		port_wildcard = false;
	} else if (streq(service_name, "%any")) {
		if (protocol->ipproto == 0) {
			return "port wildcard (%any) requires a valid protocol";
		}
		port = unset_port;
		port_wildcard = true;
	} else {
		/* Port 0-65535 is different to %any */
		err = ttoport(shunk1(service_name), &port);
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

size_t jam_protoport(struct jambuf *buf, const ip_protoport *protoport)
{
	if (protoport == NULL) {
		return jam(buf, "<null-protoport>");
	}

	if (!protoport->is_set) {
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
