/* ip_address tests, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2018 Andrew Cagney
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
#include "ip_packet.h"
#include "ipcheck.h"

void ip_packet_check(void)
{
	static const struct test {
		int line;
		int family;
		const struct ip_protocol *proto;
		const char *sa;
		int sp;
		const char *da;
		int dp;
		const char *str;
	} tests[] = {
		/* anything else? */
		{ LN, 4, &ip_protocol_tcp, "1.2.3.4", 1, "1.2.3.4", 65535, "1.2.3.4:1-TCP->1.2.3.4:65535", },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("[%s]:%d %s [%s]:%d => %s",
		      t->sa, t->sp, t->proto->name, t->da, t->dp, t->str);

		const struct ip_info *afi = IP_TYPE(t->family);

		ip_address sa;
		oops = ttoaddress_num(shunk1(t->sa), afi, &sa);
		if (oops != NULL) {
			/* Error occurred, but we didn't expect one */
			FAIL("ttoendpoint failed: %s", oops);
		}

		ip_address da;
		oops = ttoaddress_num(shunk1(t->da), afi, &da);
		if (oops != NULL) {
			/* Error occurred, but we didn't expect one */
			FAIL("ttoendpoint failed: %s", oops);
		}

		ip_packet packet = packet_from_raw(HERE, afi, t->proto,
						   &sa.bytes, ip_hport(t->sp),
						   &da.bytes, ip_hport(t->dp));

		packet_buf tb;
		const char *str = str_packet(&packet, &tb);
		if (!streq(str, t->str)) {
			FAIL("str_packet() returned %s, expecting %s", str, t->str);
		}
	}
}
