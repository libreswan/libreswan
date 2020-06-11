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
	ip_endpoint endpoint = {
		.version = address->version,
		.bytes = address->bytes,
		.hport = hport,
		.ipproto = protocol->ipproto,
		.is_endpoint = true,
	};
#if 0
	pendpoint(&endpoint);
#endif
	return endpoint;
}

ip_endpoint endpoint3(const struct ip_protocol *protocol,
		      const ip_address *address, ip_port port)
{
#if 0
	padddress(address);
#endif
	return raw_endpoint(protocol, address, hport(port));
}

ip_endpoint endpoint(const ip_address *address, int hport)
{
	return raw_endpoint(&ip_protocol_unset, address, hport);
}

ip_address endpoint_address(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		return unset_address; /* empty_address? */
	}
	shunk_t bytes = {
		.ptr = &endpoint->bytes,
		.len = afi->ip_size,
	};
	ip_address address = address_from_shunk(afi, bytes);
	paddress(&address);
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

ip_port endpoint_port(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("%s has unspecified type", __func__);
		return unset_port;
	}
	return ip_hport(endpoint->hport);
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
