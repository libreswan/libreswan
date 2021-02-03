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

#include "ipcheck.h"
#include "ip_protoport.h"

void ip_protoport_check(void)
{
	static const struct test {
		char *in;
		unsigned proto, port;
		bool ok;
	} tests[] = {
		/* { "", 0, 0, false, }, */
		{ "tcp/%any", 6, 0, true,  },
		{ "udp/255", 17, 255, true,  },
		{ "0/1", 0, 0, false,  },
		{ "0/0", 0, 0, true,  },
		{ "47", 47, 0, true, },
		{ "47/", 47, 0, true, },
		{ "something-longer-than-16-bytes/0", 0, 0, false, }
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT(stdout, "in=%s proto=%d port=%d ok=%s",
		      t->in, t->proto, t->port, bool_str(t->ok));

		ip_protoport out;
		err_t err = ttoprotoport(t->in, &out);

		if (!t->ok && err == NULL) {
			FAIL(PRINT, "%s expected error, got none", t->in);
		}

		if (t->ok && err != NULL) {
			FAIL(PRINT, "%s got error: %s\n", t->in, err);
		}

		if (out.protocol != t->proto) {
			FAIL(PRINT, "%s expected proto %u, got %u", t->in,
			     t->proto, out.protocol);
		}

		if (out.port != t->port) {
			FAIL(PRINT, "%s expected port %u, got %u",
			     t->in, t->port, out.port);
		}
	}
}
