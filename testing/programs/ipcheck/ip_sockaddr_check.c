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
 *
 */

#include "ip_sockaddr.h"
#include "ip_info.h"
#include "ip_protocol.h"

#include "lswlog.h"		/* for DBG_dump_thing() */

#include "ipcheck.h"

static void check_sockaddr_as_endpoint(void)
{
	static const struct test {
		int line;
		const struct ip_info *afi;
		const char *in;
		uint8_t addr[16];
		int port;
		size_t size;
		const char *err;
		const char *out;
	} tests[] = {
		{ LN, &ipv4_info, "1.2.3.4:65535", { 1, 2, 3, 4, }, 65535, sizeof(struct sockaddr_in), NULL, NULL, },
		{ LN, &ipv6_info, "[1::1]:65535", { [1] = 1, [15] = 1, }, 65535, sizeof(struct sockaddr_in6), NULL, NULL, },
		/* far too small */
		{ LN, &ipv4_info, "1.2.3.4:65535", { 1, 2, 3, 4, }, 65535, 0, "too small", "<unset-endpoint>", },
		{ LN, &ipv6_info, "[1::1]:65535", { [1] = 1, [15] = 1, }, 65535, 0, "too small", "<unset-endpoint>", },
		/* somewhat too small */
#define SIZE (offsetof(struct sockaddr, sa_family) + sizeof(sa_family_t))
		{ LN, &ipv4_info, "1.2.3.4:65535", { 1, 2, 3, 4, }, 65535, SIZE, "address truncated", "<unset-endpoint>", },
		{ LN, &ipv6_info, "[1::1]:65535", { [1] = 1, [15] = 1, }, 65535, SIZE, "address truncated", "<unset-endpoint>", },
		/* too big */
		{ LN, &ipv4_info, "1.2.3.4:65535", { 1, 2, 3, 4, }, 65535, sizeof(struct sockaddr_in) + 1, NULL, NULL, },
		{ LN, &ipv6_info, "[1::1]:65535", { [1] = 1, [15] = 1, }, 65535, sizeof(struct sockaddr_in6) + 1, NULL, NULL, },
	};
#undef SIZE

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		const char *expect_out = t->out == NULL ? t->in : t->out;
		PRINT("%s '%s' -> '%s' len=%zd", pri_afi(t->afi), t->in, expect_out, t->size);

		/* construct a raw sockaddr */
		struct {
			ip_sockaddr sa;
			char pad;
		} raw = {
			.sa = {
				.len = t->size,
			}
		};
		switch (t->afi->ip_version) {
		case IPv4:
			memcpy(&raw.sa.sa.sin.sin_addr, t->addr, sizeof(raw.sa.sa.sin.sin_addr));
			raw.sa.sa.sin.sin_family = AF_INET;
			raw.sa.sa.sin.sin_port = htons(t->port);
#ifdef USE_SOCKADDR_LEN
                	raw.sa.sa.sin.sin_len = sizeof(struct sockaddr_in);
#endif
			break;
		case IPv6:
			memcpy(&raw.sa.sa.sin6.sin6_addr, t->addr, sizeof(raw.sa.sa.sin6.sin6_addr));
			raw.sa.sa.sin6.sin6_family = AF_INET6;
			raw.sa.sa.sin6.sin6_port = htons(t->port);
#ifdef USE_SOCKADDR_LEN
                	raw.sa.sa.sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			break;
		}

		/* sockaddr->endpoint */
		ip_address address[1];
		ip_port port;
		ip_endpoint endpoint = unset_endpoint;
		err_t err = sockaddr_to_address_port(&raw.sa.sa.sa, raw.sa.len,
						     address, &port);
		if (err != NULL) {
			if (t->err == NULL) {
				FAIL("sockaddr_to_address_port() unexpectedly failed: %s", err);
			} else if (!streq(err, t->err)) {
				FAIL("sockaddr_to_address_port() returned error '%s', expecting '%s'", err, t->err);
			}
			if (!address_is_unset(address)) {
				FAIL("sockaddr_to_address_port() failed yet address is set");
			}
			if (hport(port) != 0) {
				FAIL("sockaddr_to_address_port() failed yet port is non-zero");
			}
		} else if (t->err != NULL) {
			FAIL("sockaddr_to_address_port() should have failed: %s", t->err);
		} else {
			endpoint = endpoint_from_address_protocol_port(*address, &ip_protocol_udp, port);
			CHECK_INFO(address);
		}

		/* as a string */
		CHECK_STR(endpoint_buf, endpoint, expect_out, &endpoint);

		/* endpoint->sockaddr */
		ip_sockaddr esa = sockaddr_from_endpoint(endpoint);
		if (err == NULL) {
			if (esa.len == 0) {
				FAIL("endpoint_to_sockaddr() returned %d, expecting non-zero",
					esa.len);
			} else if (esa.len > sizeof(esa.sa)) {
				FAIL("endpoint_to_sockaddr() returned %d, expecting %zu or smaller",
					esa.len, sizeof(esa.sa));
			} else if (!memeq(&esa.sa, &raw.sa.sa, sizeof(esa.sa))) {
				/* compare the entire buffer, not just size */
				DBG_dump_thing("esa.sa", esa.sa);
				DBG_dump_thing("sa.sa", raw.sa.sa);
				FAIL("endpoint_to_sockaddr() returned a different value");
			}
		} else {
			if (esa.len != 0) {
				FAIL("endpoint_to_sockaddr() returned %d, expecting non-zero",
					esa.len);
			}
		}
	}
}

void ip_sockaddr_check(void)
{
	check_sockaddr_as_endpoint();
}

