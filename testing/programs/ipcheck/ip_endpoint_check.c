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
#include "jambuf.h"
#include "ipcheck.h"

void ip_endpoint_check()
{
	/*
	 * XXX: can't yet do invalid ports.
	 */
	static const struct test {
		int family;
		const char *in;
		uint16_t hport;
		const char *out;
		uint8_t nport[2];
	} tests[] = {
		/* anything else? */
		{ 4, "1.2.3.4",	65535, "1.2.3.4:65535", { 255, 255, }, },
		{ 4, "255.255.255.255",	65535, "255.255.255.255:65535", { 255, 255, } },
		{ 6, "1:12:3:14:5:16:7:18", 65535, "[1:12:3:14:5:16:7:18]:65535", { 255, 255, }, },
		{ 6, "11:22:33:44:55:66:77:88",	65535, "[11:22:33:44:55:66:77:88]:65535", { 255, 255, }, },

		/* treat special different ? */
		{ 4, "0.0.0.1", 65535, "0.0.0.1:65535", { 255, 255, }, },
		{ 6, "::1", 65535, "[::1]:65535", { 255, 255, }, },

		/* never suppress the port */
		{ 4, "0.0.0.0", 0, "0.0.0.0:0", { 0, 0, }, },
		{ 6, "::", 0, "[::]:0", { 0, 0, }, },
		{ 4, "0.0.0.0", 1, "0.0.0.0:1", { 0, 1, }, },
		{ 6, "::", 1, "[::]:1", { 0, 1, }, },

		/* longest */
		{ 4, "101.102.103.104", 65534, "101.102.103.104:65534", { 255, 254, }, },
		{ 6, "1001:1002:1003:1004:1005:1006:1007:1008", 65534, "[1001:1002:1003:1004:1005:1006:1007:1008]:65534", { 255, 254, }, },

	};

	const char *oops;

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		PRINT_IN(stdout, "%d->%s", t->hport, t->out);

		const struct ip_info *type = IP_TYPE(t->family);

		ip_address a;
		oops = numeric_to_address(shunk1(t->in), type, &a);
		if (oops != NULL) {
			/* Error occurred, but we didn't expect one  */
			FAIL_IN("ttosubnet failed: %s", oops);
		}

		ip_endpoint e = endpoint_from_address_protocol_port(&a, &ip_protocol_udp,
								    ip_hport(t->hport));

		CHECK_TYPE(PRINT_IN, endpoint_type(&e));

		/*
		 * str_endpoint() / jam_endpoint()
		 */
		CHECK_STR(endpoint_buf, endpoint, t->out, &e);

		/*
		 * endpoint_*address()
		 */
		ip_address aout = endpoint_address(&e);
		address_buf astr;
		if (!streq(str_address(&aout, &astr), t->in)) {
			FAIL_IN("endpoint_address() returned %s, expecting %s",
				astr.buf, t->in);
		}

		/*
		 * endpoint_*port()
		 */

		/* host port */
		uint16_t heport = endpoint_hport(&e);
		if (!memeq(&heport, &t->hport, sizeof(heport))) {
			FAIL_IN("endpoint_hport() returned '%d', expected '%d'",
				heport, t->hport);
		}

		/* network port */
		uint16_t neport = nport(endpoint_port(&e));
		if (!memeq(&neport, &t->nport, sizeof(neport))) {
			FAIL_IN("endpoint_nport() returned '%04x', expected '%02x%02x'",
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
			FAIL_IN("can't do basic math");
		}

		/* hport+1 -> nport+1 */
		ip_endpoint hp = set_endpoint_port(&e, ip_hport(hport_plus_one));
		uint16_t nportp = nport(endpoint_port(&hp));
		if (!memeq(&nportp, &nport_plus_one, sizeof(nportp))) {
			FAIL_IN("endpoint_nport(set_endpoint_hport(+1)) returned '%04x', expected '%04x'",
				nportp, nport_plus_one);
		}

		/*
		 * endpoint_eq()
		 */
		if (!endpoint_eq(&e, &e)) {
			FAIL_IN("endpoint_eq(e, e) failed");
		}
		if (endpoint_eq(&e, &hp)) {
			FAIL_IN("endpoint_eq(e, e+1) succeeded");
		}

		/*
		 * endpoint_address_eq()
		 */
		if (!endpoint_address_eq(&e, &a)) {
			FAIL_IN("endpoint_address_eq(e, a) failed");
		}

	}
}
