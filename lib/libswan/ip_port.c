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


#include <netdb.h>		/* for getservbyname() */
#include <arpa/inet.h>		/* for ntohs() */
#include <stdlib.h>		/* for strtol() */

#include "jambuf.h"
#include "constants.h"		/* for thingeq() */
#include "ip_port.h"

const ip_port unset_port; /* aka all ports? */

ip_port ip_hport(unsigned hport)
{
	ip_port port = {
		.ip.is_set = true,
		.hport = hport,
	};
	return port;
}

ip_port ip_nport(unsigned nport)
{
	return ip_hport(ntohs(nport));
}

unsigned hport(const ip_port port)
{
	return port.hport;
}

unsigned nport(const ip_port port)
{
	return htons(port.hport);
}

bool port_is_specified(ip_port port)
{
	return (port.ip.is_set && port.hport != 0); /* assumes udp/tcp */
}

size_t jam_hport(struct jambuf *buf, ip_port port)
{
	return jam(buf, PRI_HPORT, hport(port));

}

size_t jam_nport(struct jambuf *buf, ip_port port)
{
	return jam(buf, PRI_NPORT, pri_nport(port));
}

const char *str_hport(ip_port port, port_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_hport(&jambuf, port);
	return buf->buf;
}

const char *str_nport(ip_port port, port_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_nport(&jambuf, port);
	return buf->buf;
}
