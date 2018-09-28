/* Output an IP address, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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
 *
 */

#include <stdio.h>
#include <stdarg.h>

#include "lswlog.h"
#include "ip_address.h"

size_t lswlog_ip(struct lswlog *buf, const ip_address *ip)
{
	ipstr_buf b;
	size_t size = 0;
	size += lswlogs(buf, ipstr(ip, &b));
	/*
	 * From wikipedia: For TCP, port number 0 is reserved and
	 * cannot be used, while for UDP, the source port is optional
	 * and a value of zero means no port.
	 *
	 * Omit the port number when hportof() returns either -1
	 * (address is invalid) or 0 (the port is either unset or
	 * there is no port).
	 */
	int port = hportof(ip);
	if (port > 0) {
		size += lswlogf(buf, ":%d", port);
	}
	return size;
}
