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

#include <netdb.h>

#include "ip_protoport.h"

#include "constants.h"		/* for zero() */

/*
 * ttoprotoport - converts from protocol/port string to protocol and
 * port
 */
err_t ttoprotoport(const char *src, ip_protoport *protoport)
{
	zero(protoport);
	char proto_name[16];

	/* get the length of the string */
	size_t src_len = strlen(src);

	/* locate delimiter '/' between protocol and port */
	char *end = strchr(src, '/');
	const char*service_name;
	int proto_len;
	if (end != NULL) {
		proto_len = end - src;
		service_name = end + 1;
	} else {
		proto_len = src_len;
		service_name = src + src_len;
	}

	/* copy protocol name */
	memset(proto_name, '\0', sizeof(proto_name));
	memcpy(proto_name, src, proto_len);

	/* extract protocol by trying to resolve it by name */
	unsigned protocol;
	const struct protoent *protoent = getprotobyname(proto_name);
	if (protoent != NULL) {
		protocol = protoent->p_proto;
	} else {	/* failed, now try it by number */
		long l = strtol(proto_name, &end, 0);
		if (*proto_name && *end)
			return "<protocol> is neither a number nor a valid name";
		if (l < 0 || l > 0xff)
			return "<protocol> must be between 0 and 255";
		protocol = l;
	}

	/* is there a port wildcard? */
	unsigned port;
	if (streq(service_name, "%any")) {
		port = 0;
	} else {
		/* extract port by trying to resolve it by name */
		const struct servent *service = getservbyname(service_name, NULL);
		if (service != NULL) {
			port = ntohs(service->s_port);
		} else {	/* failed, now try it by number */
			long l = strtol(service_name, &end, 0);
			if (*service_name && *end) {
				/*
				 * set port to 0, this is needed for
				 * protocols without port in the
				 * proposal, such as with GRE
				 * (protoport=47)
				 */
				l = 0;
			} else if (l < 0 || l > 0xffff) {
				return "<port> must be between 0 and 65535";
			}
			port = (uint16_t)l;
		}
	}

	if (protocol == 0 && port != 0) {
		return "protocol 0 must have 0 port";
	}

	protoport->protocol = protocol;
	protoport->port = port;
	return NULL;
}

size_t jam_protoport(jambuf_t *buf, const ip_protoport *protoport)
{
	size_t s = 0;
	if (protoport->protocol == 0) {
		s += jam_string(buf, "%any");
	} else {
		s += jam(buf, "%u", protoport->protocol);
	}
	jam(buf, "/");
	if (protoport->port == 0) { /* XXX:->any_port?*/
		s += jam_string(buf, "%any");
	} else {
		s += jam(buf, "%u", protoport->port);
	}
	return s;
}

const char *str_protoport(const ip_protoport *protoport, protoport_buf *buf)
{
	jambuf_t jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_protoport(&jambuf, protoport);
	return buf->buf;
}

bool protoport_is_set(const ip_protoport *protoport)
{
	return protoport->protocol != 0;
}

bool protoport_has_any_port(const ip_protoport *protoport)
{
	return protoport->protocol != 0 && protoport->port == 0;
}
