/* ip endpoint (address + port), for libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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
#include "ip_endpoint.h"
#include "constants.h"		/* for memeq() */
#include "ip_info.h"
#include "lswlog.h"		/* for bad_case() */

ip_endpoint endpoint(const ip_address *address, int port)
{
	return set_endpoint_port(address, port);
}

err_t sockaddr_as_endpoint(const struct sockaddr *sa, socklen_t sa_len, ip_endpoint *e)
{
	/* paranoia from demux.c */
	if (sa_len < (socklen_t) (offsetof(struct sockaddr, sa_family) +
				  sizeof(sa->sa_family))) {
		zero(e); /* something better? this is AF_UNSPEC */
		return "truncated";
	}

	/*
	 * The text used in the below errors originated in demux.c.
	 *
	 * XXX: While af_info seems useful, trying to make it work
	 * here resulted in convoluted over-engineering.  Instead
	 * ensure these code paths work using testing.
	 */
	ip_address address;
	int port;
	switch (sa->sa_family) {
	case AF_INET:
	{
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		/* XXX: to strict? */
		if (sa_len != sizeof(*sin)) {
			return "wrong length";
		}
		address = address_from_in_addr(&sin->sin_addr);
		port = ntohs(sin->sin_port);
		break;
	}
	case AF_INET6:
	{
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
		/* XXX: to strict? */
		if (sa_len != sizeof(*sin6)) {
			return "wrong length";
		}
		address = address_from_in6_addr(&sin6->sin6_addr);
		port = ntohs(sin6->sin6_port);
		break;
	}
	case AF_UNSPEC:
		return "unspecified";
	default:
		return "unexpected Address Family";
	}
	*e = endpoint(&address, port);
	return NULL;
}

ip_address endpoint_address(const ip_endpoint *endpoint)
{
#ifdef ENDPOINT_ADDRESS_PORT
	return endpoint->address;
#else
	if (address_type(endpoint) != NULL) {
		return set_endpoint_port(endpoint, 0); /* scrub the port */
	} else {
		return *endpoint; /* empty_address? */
	}
#endif
}

int endpoint_port(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("endpoint has unspecified type");
		return -1;
	}
	switch (afi->af) {
	case AF_INET:
		return ntohs(endpoint->u.v4.sin_port);
	case AF_INET6:
		return ntohs(endpoint->u.v6.sin6_port);
	default:
		bad_case(afi->af);
	}
}

ip_endpoint set_endpoint_port(const ip_endpoint *endpoint, int port)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("endpoint has unspecified type");
		return endpoint_invalid;
	}
	ip_endpoint dst = *endpoint;
	switch (afi->af) {
	case AF_INET:
		dst.u.v4.sin_port = htons(port);
		break;
	case AF_INET6:
		dst.u.v6.sin6_port = htons(port);
		break;
	default:
		bad_case(afi->af);
	}
	return dst;
}

const struct ip_info *endpoint_type(const ip_endpoint *endpoint)
{
	/*
	 * Avoid endpoint*() functions as things quickly get
	 * recursive.
	 */
	return address_type(endpoint);
}

/*
 * Format an endpoint.
 *
 * Either ADDRESS:PORT (IPv4) or [ADDDRESS]:PORT, but when PORT is
 * invalid, just the ADDRESS is formatted.
 *
 * From wikipedia: For TCP, port number 0 is reserved and
 * cannot be used, while for UDP, the source port is optional
 * and a value of zero means no port.
 */
static void format_endpoint(jambuf_t *buf, bool sensitive,
			    const ip_endpoint *endpoint)
{
	/*
	 * A NULL endpoint can't be sensitive so always log it.
	 */
	if (endpoint == NULL) {
		jam(buf, "<none:>");
		return;
	}

	/*
	 * An endpoint with no type (i.e., uninitialized) can't be
	 * sensitive so always log it.
	 */
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		jam(buf, "<unspecified:>");
		return;
	}

	if (sensitive) {
		jam(buf, "<address:>");
		return;
	}
	ip_address address = endpoint_address(endpoint);
	int port = endpoint_port(endpoint);

	switch (afi->af) {
	case AF_INET: /* N.N.N.N[:PORT] */
		jam_address(buf, &address);
		if (port > 0) {
			jam(buf, ":%d", port);
		}
		break;
	case AF_INET6: /* [N:..:N]:PORT or N:..:N */
		if (port > 0) {
			jam(buf, "[");
			jam_address(buf, &address);
			jam(buf, "]");
			jam(buf, ":%d", port);
		} else {
			jam_address(buf, &address);
		}
		break;
	default:
		bad_case(afi->af);
	}
}

void jam_endpoint(jambuf_t *buf, const ip_endpoint *endpoint)
{
	format_endpoint(buf, false, endpoint);
}

const char *str_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_endpoint(&buf, endpoint);
	return dst->buf;
}

void jam_sensitive_endpoint(jambuf_t *buf, const ip_endpoint *endpoint)
{
	format_endpoint(buf, !log_ip, endpoint);
}

const char *str_sensitive_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_sensitive_endpoint(&buf, endpoint);
	return dst->buf;
}

bool endpoint_eq(const ip_endpoint l, ip_endpoint r)
{
	return memeq(&l, &r, sizeof(l));
}

#ifdef ENDPOINT_ADDRESS_PORT
const ip_endpoint endpoint_invalid = {
	.address = {
		.family = AF_UNSPEC,
	},
};
#endif

/*
 * portof - get the port field of an ip_endpoint in network order.
 *
 * Return -1 if ip_endpoint isn't valid.
 */

ip_endpoint nsetportof(int port /* network order */, ip_endpoint endpoint)
{
	return set_endpoint_port(&endpoint, htons(port));
}

ip_endpoint hsetportof(int port /* host order */, ip_endpoint endpoint)
{
	return set_endpoint_port(&endpoint, port);
}
