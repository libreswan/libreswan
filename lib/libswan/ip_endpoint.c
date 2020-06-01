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
#include "ip_protocol.h"
#include "lswlog.h"		/* for bad_case() */

const ip_endpoint unset_endpoint; /* all zeros */

static ip_endpoint raw_endpoint(const struct ip_protocol *protocol,
				const ip_address *address, int hport)
{
#if defined(ENDPOINT_TYPE)
	ip_endpoint endpoint = {
		.address = *address,
		.hport = hport,
		.protocol = protocol->ipproto,
	};
#else
	ip_endpoint endpoint = {
		.hport = hport,
		.version = address->version,
		.ipproto = protocol->ipproto,
		.bytes = address->bytes,
	};
#endif
	return endpoint;
}

ip_endpoint endpoint3(const struct ip_protocol *protocol,
		      const ip_address *address, int hport)
{
#if 0
	padddress(address);
#endif
	return raw_endpoint(protocol, address, hport);
}

ip_endpoint endpoint(const ip_address *address, int hport)
{
	return raw_endpoint(&ip_protocol_unset, address, hport);
}

err_t sockaddr_to_endpoint(const struct ip_protocol *protocol,
			   const ip_sockaddr *sa, socklen_t sa_len,
			   ip_endpoint *e)
{
	/* paranoia from demux.c */
	if (sa_len < (socklen_t) (offsetof(ip_sockaddr, sa.sa_family) +
				  sizeof(sa->sa.sa_family))) {
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
	switch (sa->sa.sa_family) {
	case AF_INET:
	{
		/* XXX: to strict? */
		if (sa_len != sizeof(sa->sin)) {
			return "wrong length";
		}
		address = address_from_in_addr(&sa->sin.sin_addr);
		port = ntohs(sa->sin.sin_port);
		break;
	}
	case AF_INET6:
	{
		/* XXX: to strict? */
		if (sa_len != sizeof(sa->sin6)) {
			return "wrong length";
		}
		address = address_from_in6_addr(&sa->sin6.sin6_addr);
		port = ntohs(sa->sin6.sin6_port);
		break;
	}
	case AF_UNSPEC:
		return "unspecified";
	default:
		return "unexpected Address Family";
	}
	*e = endpoint3(protocol, &address, port);
	return NULL;
}

ip_address endpoint_address(const ip_endpoint *endpoint)
{
#if defined(ENDPOINT_TYPE)
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("endpoint has unspecified type");
		return address_invalid;
	}
	ip_address address = endpoint->address;
#else
	ip_address address = *endpoint;
	/* scrub protocol+port */
	address.hport = 0;
	address.ipproto = 0;
#endif
	return address;
}

int endpoint_hport(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("%s has unspecified type", __func__);
		return -1;
	}
	return endpoint->hport;
}

int endpoint_nport(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("%s has unspecified type", __func__);
		return -1;
	}
	return htons(endpoint->hport);
}

ip_endpoint set_endpoint_hport(const ip_endpoint *endpoint, int hport)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("endpoint has unspecified type");
		return unset_endpoint;
	}
#ifdef ENDPOINT_TYPE
	ip_endpoint dst = {
		.address = endpoint->address,
		.hport = hport,
	};
	return dst;
#else
	ip_endpoint dst = *endpoint;
	dst.hport = hport;
	return dst;
#endif
}

const struct ip_info *endpoint_type(const ip_endpoint *endpoint)
{
	/*
	 * Avoid endpoint*() functions as things quickly get
	 * recursive.
	 */
#if defined(ENDPOINT_TYPE)
	return address_type(&endpoint->address);
#else
	return address_type(endpoint);
#endif
}

const struct ip_protocol *endpoint_protocol(const ip_endpoint *endpoint)
{
	return protocol_by_ipproto(endpoint->ipproto);
}

bool endpoint_is_set(const ip_endpoint *endpoint)
{
	return endpoint_type(endpoint) != NULL;
}

bool endpoint_is_specified(const ip_endpoint *e)
{
#ifdef ENDPOINT_TYPE
	return address_is_specified(&e->address);
#else
	return address_is_specified(e);
#endif
}

/*
 * Format an endpoint.
 *
 * Either ADDRESS:PORT (IPv4) or [ADDRESS]:PORT, but when PORT is
 * invalid, just the ADDRESS is formatted.
 *
 * From wikipedia: For TCP, port number 0 is reserved and
 * cannot be used, while for UDP, the source port is optional
 * and a value of zero means no port.
 */
static size_t format_endpoint(jambuf_t *buf, bool sensitive,
			    const ip_endpoint *endpoint)
{
	/*
	 * A NULL endpoint can't be sensitive so always log it.
	 */
	if (endpoint == NULL) {
		return jam(buf, "<none:>");
	}

	/*
	 * An endpoint with no type (i.e., uninitialized) can't be
	 * sensitive so always log it.
	 */
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		return jam(buf, "<unspecified:>");
	}

	if (sensitive) {
		return jam(buf, "<address:>");
	}

	ip_address address = endpoint_address(endpoint);
	int hport = endpoint_hport(endpoint);
	size_t s = 0;

	switch (afi->af) {
	case AF_INET: /* N.N.N.N[:PORT] */
		s += jam_address(buf, &address);
		if (hport > 0) {
			s += jam(buf, ":%d", hport);
		}
		break;
	case AF_INET6: /* [N:..:N]:PORT or N:..:N */
		if (hport > 0) {
			s += jam(buf, "[");
			s += jam_address(buf, &address);
			s += jam(buf, "]");
			s += jam(buf, ":%d", hport);
		} else {
			s += jam_address(buf, &address);
		}
		break;
	default:
		bad_case(afi->af);
	}
	return s;
}

size_t jam_endpoint(jambuf_t *buf, const ip_endpoint *endpoint)
{
	return format_endpoint(buf, false, endpoint);
}

const char *str_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_endpoint(&buf, endpoint);
	return dst->buf;
}

size_t jam_sensitive_endpoint(jambuf_t *buf, const ip_endpoint *endpoint)
{
	return format_endpoint(buf, !log_ip, endpoint);
}

const char *str_sensitive_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_sensitive_endpoint(&buf, endpoint);
	return dst->buf;
}

bool endpoint_eq(const ip_endpoint l, ip_endpoint r)
{
	if (l.version == r.version &&
	    l.hport == r.hport &&
	    memeq(&l.bytes, &r.bytes, sizeof(l.bytes))) {
		if (l.ipproto == r.ipproto) {
			/* both 0; or both valid */
			return true;
		}
		if (l.ipproto == 0 || r.ipproto == 0) {
			dbg("endpoint fuzzy ipproto match");
			return true;
		}
	}
	return false;
}

/*
 * Construct and return a sockaddr structure.
 */

size_t endpoint_to_sockaddr(const ip_endpoint *endpoint, ip_sockaddr *sa)
{
	zero(sa);
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		return 0;
	}
	ip_address address = endpoint_address(endpoint);
	int hport = endpoint_hport(endpoint);

	shunk_t src_addr = address_as_shunk(&address);
	chunk_t dst_addr;

	switch (afi->af) {
	case AF_INET:
		sa->sin.sin_family = afi->af;
		sa->sin.sin_port = htons(hport);
		dst_addr = THING_AS_CHUNK(sa->sin.sin_addr);
#ifdef NEED_SIN_LEN
		sa->sin.sin_len = sizeof(struct sockaddr_in);
#endif
		break;
	case AF_INET6:
		sa->sin6.sin6_family = afi->af;
		sa->sin6.sin6_port = htons(hport);
		dst_addr = THING_AS_CHUNK(sa->sin6.sin6_addr);
#ifdef NEED_SIN_LEN
		sa->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		break;
	default:
		bad_case(afi->af);
	}
	passert(src_addr.len == afi->ip_size);
	passert(dst_addr.len == afi->ip_size);
	memcpy(dst_addr.ptr, src_addr.ptr, src_addr.len);
	return afi->sockaddr_size;
}
