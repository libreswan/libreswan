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
		const struct ip_info *afi;
		const struct ip_protocol *protocol;
		const char *sa;
		int sp;
		const char *da;
		int dp;
		const char *str;
	} tests[] = {
		/* normal */
		{ LN, &ipv4_info, &ip_protocol_tcp, "1.2.3.4", 1, "1.2.3.4", 65535, "1.2.3.4:1-TCP->1.2.3.4:65535", },
		{ LN, &ipv6_info, &ip_protocol_tcp, "::1", 1, "::2", 65535, "[::1]:1-TCP->[::2]:65535", },
		/* ephemeral source port */
		{ LN, &ipv4_info, &ip_protocol_tcp, "1.2.3.4", 0, "1.2.3.4", 65535, "1.2.3.4-TCP->1.2.3.4:65535", },
		{ LN, &ipv6_info, &ip_protocol_tcp, "::1", 0, "::2", 65535, "[::1]-TCP->[::2]:65535", },
	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("[%s]:%d %s [%s]:%d => %s",
		      t->sa, t->sp, t->protocol->name, t->da, t->dp, t->str);

		const struct ip_info *afi = t->afi;

		ip_port src_port = ip_hport(t->sp);
		ip_port dst_port = ip_hport(t->dp);

		ip_address src_address;
		oops = ttoaddress_num(shunk1(t->sa), afi, &src_address);
		if (oops != NULL) {
			/* Error occurred, but we didn't expect one */
			FAIL("ttoaddress failed: %s", oops);
		}

		ip_address dst_address;
		oops = ttoaddress_num(shunk1(t->da), afi, &dst_address);
		if (oops != NULL) {
			/* Error occurred, but we didn't expect one */
			FAIL("ttoendpoint failed: %s", oops);
		}

		ip_packet packet = packet_from_raw(HERE,
						   afi, &src_address.bytes, &dst_address.bytes,
						   t->protocol, src_port, dst_port);

		packet_buf tb;
		const char *str = str_packet(&packet, &tb);
		if (!streq(str, t->str)) {
			FAIL("str_packet() returned %s, expecting %s", str, t->str);
		}

		/* src is a selector */
		ip_selector packet_src = packet_src_selector(packet);
		ip_selector src_selector = selector_from_raw(HERE, afi,
							     src_address.bytes,
							     src_address.bytes,
							     t->protocol, src_port);
		if (!selector_eq_selector(packet_src, src_selector)) {
			selector_buf psb, sb;
			FAIL("packet_src_selector failed: returned %s, expecting %s",
			     str_selector(&packet_src, &psb),
			     str_selector(&src_selector, &sb));
		}

		/* dst is an endpoint */
		ip_endpoint packet_dst = packet_dst_endpoint(packet);
		ip_endpoint dst_endpoint = endpoint_from_raw(HERE, afi,
							     dst_address.bytes,
							     t->protocol, dst_port);
		if (!endpoint_eq_endpoint(packet_dst, dst_endpoint)) {
			endpoint_buf pdb, db;
			FAIL("packet_dst_endpoint failed: returned %s, expecting %s",
			     str_endpoint(&packet_dst, &pdb),
			     str_endpoint(&dst_endpoint, &db));
		}
	}
}
