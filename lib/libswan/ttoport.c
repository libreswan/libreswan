/* ttoport, for libreswan
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

err_t ttoport(const char *service_name, ip_port *port)
{
	/*
	 * Extract port by trying to resolve it by name.
	 *
	 * XXX: the getservbyname() call requires a NUL terminated
	 * SERVICE_NAME; hence this is not a shunk_t.
	 */
	const struct servent *service = getservbyname(service_name, NULL);
	if (service != NULL) {
		/* success */
		*port = ip_nport(service->s_port/*network-order*/);
		return NULL;
	}

	/*
	 * Now try converting it to a number; use SHUNK variant as it
	 * is more strict.
	 */
	uintmax_t l;
	err_t e = shunk_to_uintmax(shunk1(service_name), NULL/*trailing-chars-not-allowed*/,
				   0/*any-base*/, &l);
	if (e != NULL) {
		*port = unset_port;
		return e;
	}

	if (l > 0xffff) {
		*port = unset_port;
		return "must be between 0 and 65535";
	}

	*port = ip_hport(l);
	return NULL;
}
