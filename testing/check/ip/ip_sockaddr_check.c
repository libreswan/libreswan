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

#include "jambuf.h"

#include "ip_sockaddr.h"
#include "ip_info.h"
#include "ip_protocol.h"

#include "ipcheck.h"

static void check_sockaddr_as_endpoint(void)
{
	static const struct test {
		const int family;
		const char *in;
		uint8_t addr[16];
		int port;
		size_t size;
		const char *err;
		const char *out;
	} tests[] = {
		{ 4, "1.2.3.4:65535", { 1, 2, 3, 4, }, 65535, sizeof(struct sockaddr_in), NULL, NULL, },
		{ 6, "[1::1]:65535", { [1] = 1, [15] = 1, }, 65535, sizeof(struct sockaddr_in6), NULL, NULL, },
		/* far too small */
		{ 4, "1.2.3.4:65535", { 1, 2, 3, 4, }, 65535, 0, "truncated", "<unspecified:>", },
		{ 6, "[1::1]:65535", { [1] = 1, [15] = 1, }, 65535, 0, "truncated", "<unspecified:>", },
		/* somewhat too small */
#define SIZE (offsetof(struct sockaddr, sa_family) + sizeof(sa_family_t))
		{ 4, "1.2.3.4:65535", { 1, 2, 3, 4, }, 65535, SIZE, "wrong length", "<unspecified:>", },
		{ 6, "[1::1]:65535", { [1] = 1, [15] = 1, }, 65535, SIZE, "wrong length", "<unspecified:>", },
	};
#undef SIZE

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		const struct test *t = &tests[ti];
		const char *expect_out = t->out == NULL ? t->in : t->out;
		PRINT_IN(stdout, " -> '%s' len=%zd", expect_out, t->size);

		/* construct a raw sockaddr */
		ip_sockaddr sa = {
			.sa.sa = {
				.sa_family = SA_FAMILY(t->family),
			},
			.len = t->size,
		};
		switch (t->family) {
		case 4:
			memcpy(&sa.sa.sin.sin_addr, t->addr, sizeof(sa.sa.sin.sin_addr));
			sa.sa.sin.sin_port = htons(t->port);
			break;
		case 6:
			memcpy(&sa.sa.sin6.sin6_addr, t->addr, sizeof(sa.sa.sin6.sin6_addr));
			sa.sa.sin6.sin6_port = htons(t->port);
			break;
		}

		/* sockaddr->endpoint */
		ip_endpoint endpoint;
		err_t err = sockaddr_to_endpoint(&ip_protocol_unset, &sa, &endpoint);
		if (err != NULL) {
			if (t->err == NULL) {
				FAIL_IN("sockaddr_to_endpoint() unexpectedly failed: %s", err);
			} else if (!streq(err, t->err)) {
				FAIL_IN("sockaddr_to_endpoint() returned error '%s', expecting '%s'", err, t->err);
			}
			if (endpoint_type(&endpoint) != NULL) {
				FAIL_IN("sockaddr_to_endpoint() failed yet endpoint has a type");
			}
		} else if (t->err != NULL) {
			FAIL_IN("sockaddr_to_endpoint() should have failed: %s", t->err);
		} else {
			CHECK_TYPE(PRINT_IN, endpoint_type(&endpoint));
		}

		/* endpoint->sockaddr */
		ip_sockaddr esa = sockaddr_from_endpoint(&endpoint);
		if (err == NULL) {
			if (esa.len == 0) {
				FAIL_IN("endpoint_to_sockaddr() returned %d, expecting non-zero",
					esa.len);
			} else if (esa.len > sizeof(esa.sa)) {
				FAIL_IN("endpoint_to_sockaddr() returned %d, expecting %zu or smaller",
					esa.len, sizeof(esa.sa));
			} else if (!memeq(&esa.sa, &sa.sa, sizeof(esa.sa))) {
				/* compare the entire buffer, not just size */
				FAIL_IN("endpoint_to_sockaddr() returned a different value");
			}
		} else {
			if (esa.len != 0) {
				FAIL_IN("endpoint_to_sockaddr() returned %d, expecting non-zero",
					esa.len);
			}
		}

		/* as a string */
		CHECK_STR(endpoint_buf, endpoint, expect_out, &endpoint);
	}
}

void ip_sockaddr_check(void)
{
	check_sockaddr_as_endpoint();
}

