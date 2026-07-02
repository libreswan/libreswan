/* ttoprotocol(), for libreswan
 *
 * Copyright (C) 2021 Andrew Cagney <cagney@gnu.org>
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

#include <netdb.h>		/* for getprotobyname() */
#include <netinet/in.h>		/* for IPPROTO_* */

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for strncaseeq() */
#include "enum_names.h"

#include "passert.h"
#include "lswalloc.h"
#include "ip_protocol.h"
#include "ip_encap.h"
#include "jambuf.h"

err_t ttoprotocol(shunk_t text, const struct ip_protocol **proto)
{
	/* look it up */
	*proto = protocol_from_caseeat_prefix(&text);
	if (*proto != NULL) {
		return NULL;
	}

	/* failed, now try it by number in [0,255]*/
	uintmax_t p;
	err_t err = shunk_to_uintmax(text, NULL, 0, &p);
	if (err == NULL) {
		/* possible success */
		if (p > 255) {
			return "numeric protocol must be <= 255";
		}
		*proto = protocol_from_ipproto(p);
		passert(*proto != NULL);
		return NULL;
	}

	/* act of desperation */
	char *n = clone_hunk_as_string(&text, "proto name");
	const struct protoent *protocol = getprotobyname(n);
	pfree(n);
	if (protocol != NULL) {
		*proto = protocol_from_ipproto(protocol->p_proto);
		return NULL;
	}

	/* make something up */
	return err;
}
