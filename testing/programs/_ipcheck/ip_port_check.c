/* ip_address tests, for libreswan
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

#include <stdio.h>
#include <string.h>

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for streq() */
#include "ip_port.h"

#include "ipcheck.h"

void ip_port_check(void)
{
	static const struct test {
		int line;
		unsigned hport;
		const char *hstr;
		uint8_t nport[2];
		const char *nstr;
	} tests[] = {
		{ LN, 0, "0", { 0, 0, }, "0000", },
		{ LN, 0x1234, "4660", { 0x12, 0x34, }, "1234", },
		{ LN, 65535, "65535", { 0xff, 0xff, }, "ffff", },
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("hport=%u hstr=%s nport=%02x%02x nstr=%s",
		      t->hport, t->hstr,
		      t->nport[0], t->nport[1], t->nstr);

		ip_port port = ip_hport(t->hport);

		uint16_t hp = hport(port);
		if (hp != t->hport) {
			FAIL("hport() returned %u, expecting %u",
			     hp, t->hport);
		}

		port_buf hstr;
		if (!streq(t->hstr, str_hport(port, &hstr))) {
			FAIL("str_hport() returned %s, expecting %s",
			     hstr.buf, t->hstr);
		}

		uint16_t np = nport(port);
		if (!memeq(&np, t->nport, sizeof(np))) {
			FAIL("nport() returned %u, expecting %02x%02x",
			     np, (unsigned)t->nport[0], (unsigned)t->nport[1]);
		}

		port_buf nstr;
		if (!streq(t->nstr, str_nport(port, &nstr))) {
			FAIL("str_nport() returned %s, expecting %s",
			     nstr.buf, t->nstr);
		}
	}
}
