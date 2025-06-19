/* ip_endpoint tests, for libreswan
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
 */

#include <stdio.h>
#include <string.h>

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for streq() */
#include "ip_endpoint.h"
#include "ip_protocol.h"
#include "ipcheck.h"

void ip_endpoint_check(void)
{
	/*
	 * XXX: can't yet do invalid ports.
	 */
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		uint16_t hport;
		const char *str;
		uint8_t nport[2];
		bool is_unset;
		bool is_specified;
		bool is_any;
	} tests[] = {
		/* anything else? */
		{ LN, &ipv4_info, "1.2.3.4",	65535, "1.2.3.4:65535", { 255, 255, }, .is_specified = true, },
		{ LN, &ipv4_info, "255.255.255.255",	65535, "255.255.255.255:65535", { 255, 255, }, .is_specified = true, },
		{ LN, &ipv6_info, "1:12:3:14:5:16:7:18", 65535, "[1:12:3:14:5:16:7:18]:65535", { 255, 255, }, .is_specified = true, },
		{ LN, &ipv6_info, "11:22:33:44:55:66:77:88",	65535, "[11:22:33:44:55:66:77:88]:65535", { 255, 255, }, .is_specified = true, },

		/* treat special different ? */
		{ LN, &ipv4_info, "0.0.0.1", 65535, "0.0.0.1:65535", { 255, 255, }, .is_specified = true, },
		{ LN, &ipv6_info, "::1", 65535, "[::1]:65535", { 255, 255, }, .is_specified = true, },

		/* never suppress the port */
		{ LN, &ipv4_info, "0.0.0.0", 0, "0.0.0.0:0", { 0, 0, }, .is_any = true, },
		{ LN, &ipv6_info, "::", 0, "[::]:0", { 0, 0, }, .is_any = true, },
		/* not valid, hence not specified */
		{ LN, &ipv4_info, "0.0.0.0", 1, "0.0.0.0:1", { 0, 1, }, .is_specified = false, },
		{ LN, &ipv6_info, "::", 1, "[::]:1", { 0, 1, }, .is_specified = false, },

		/* longest */
		{ LN, &ipv4_info, "101.102.103.104", 65534, "101.102.103.104:65534", { 255, 254, }, .is_specified = true, },
		{ LN, &ipv6_info, "1001:1002:1003:1004:1005:1006:1007:1008", 65534, "[1001:1002:1003:1004:1005:1006:1007:1008]:65534", { 255, 254, }, .is_specified = true, },

	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT("%s '%s'%d->%s", pri_afi(t->afi), t->in, t->hport, t->str);

		const struct ip_info *type = t->afi;

		ip_address a;
		oops = ttoaddress_num(shunk1(t->in), type, &a);
		if (oops != NULL) {
			/* Error occurred, but we didn't expect one */
			FAIL("ttosubnet failed: %s", oops);
		}

		ip_endpoint e, *endpoint = &e;
		const struct ip_protocol *protocol = t->hport == 0 ? &ip_protocol_icmp : &ip_protocol_udp;
		if (t->is_specified) {
			e = endpoint_from_address_protocol_port(a, protocol,
								ip_hport(t->hport));
		} else {
			/*
			 * Construct the bogus endpoint by hand - the
			 * endpoint_from_*() code would pexpect().
			 */
			e = (ip_endpoint) {
				.is_set = true,
				.ip.version = a.ip.version,
				.bytes = a.bytes,
				.hport = t->hport,
				.ipproto = protocol->ipproto,
			};
		}

		CHECK_INFO(endpoint);

		/*
		 * str_endpoint() / jam_endpoint()
		 */
		CHECK_STR2(endpoint);

		CHECK_COND(endpoint, is_unset);
		CHECK_COND2(endpoint, is_specified);

		/*
		 * endpoint_*address()
		 */
		ip_address aout = endpoint_address(e);
		address_buf astr;
		if (!streq(str_address(&aout, &astr), t->in)) {
			FAIL("endpoint_address() returned %s, expecting %s",
				astr.buf, t->in);
		}

		/*
		 * endpoint_*port()
		 */

		/* host port */
		uint16_t heport = endpoint_hport(e);
		if (!memeq(&heport, &t->hport, sizeof(heport))) {
			FAIL("endpoint_hport() returned '%d', expected '%d'",
				heport, t->hport);
		}

		/* network port */
		uint16_t neport = nport(endpoint_port(e));
		if (!memeq(&neport, &t->nport, sizeof(neport))) {
			FAIL("endpoint_nport() returned '%04x', expected '%02x%02x'",
				neport, t->nport[0], t->nport[1]);
		}

		/* tweak the port numbers */
		uint16_t hport_plus_one = t->hport+1;
		uint16_t nport_plus_one = ntohs(t->hport+1);
		/* check math? handle carry; */
		uint8_t nport_plus_plus[2];
		memcpy(nport_plus_plus, t->nport, sizeof(nport_plus_plus));
		nport_plus_plus[1]++;
		if (nport_plus_plus[1] < t->nport[1])
			nport_plus_plus[0]++;
		if (!memeq(&nport_plus_one, nport_plus_plus, sizeof(nport_plus_one))) {
			FAIL("can't do basic math");
		}

		/* hport+1 -> nport+1 */
		ip_endpoint hp = set_endpoint_port(e, ip_hport(hport_plus_one));
		uint16_t nportp = nport(endpoint_port(hp));
		if (!memeq(&nportp, &nport_plus_one, sizeof(nportp))) {
			FAIL("endpoint_nport(set_endpoint_hport(+1)) returned '%04x', expected '%04x'",
				nportp, nport_plus_one);
		}

		/*
		 * endpoint_eq()
		 */
		if (!endpoint_eq_endpoint(e, e)) {
			FAIL("endpoint_eq(e, e) failed");
		}
		if (endpoint_eq_endpoint(e, hp)) {
			FAIL("endpoint_eq(e, e+1) succeeded");
		}

		/*
		 * endpoint_address_eq()
		 */
		if (!endpoint_address_eq_address(e, a)) {
			FAIL("endpoint_address_eq(e, a) failed");
		}

	}
}
