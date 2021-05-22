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

#include <sys/socket.h>		/* for AF_INET/AF_INET6 */

#include "jambuf.h"
#include "ip_endpoint.h"
#include "constants.h"		/* for memeq() */
#include "ip_info.h"
#include "ip_protocol.h"
#include "lswlog.h"		/* for bad_case() */

const ip_endpoint unset_endpoint; /* all zeros */

ip_endpoint endpoint_from_raw(where_t where, enum ip_version version,
			      const struct ip_bytes bytes,
			      const struct ip_protocol *protocol,
			      ip_port port)
{
	ip_endpoint endpoint = {
		.is_set = true,
		.version = version,
		.bytes = bytes,
		.hport = port.hport,
		.ipproto = protocol->ipproto,
	};
	pexpect_endpoint(&endpoint, where);
	return endpoint;
}

ip_endpoint endpoint_from_address_protocol_port(const ip_address address,
						const struct ip_protocol *protocol,
						ip_port port)
{
	return endpoint_from_raw(HERE, address.version, address.bytes,
				 protocol, port);
}

ip_address endpoint_address(const ip_endpoint endpoint)
{
	const struct ip_info *afi = endpoint_type(&endpoint);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address; /* empty_address? */
	}

	return address_from_raw(HERE, endpoint.version, endpoint.bytes);
}

int endpoint_hport(const ip_endpoint endpoint)
{
	const struct ip_info *afi = endpoint_type(&endpoint);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		/* not asserting, who knows what nonsense a user can generate */
		dbg("%s has unspecified type", __func__);
		return -1;
	}

	return endpoint.hport;
}

ip_port endpoint_port(const ip_endpoint endpoint)
{
	const struct ip_info *afi = endpoint_type(&endpoint);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		/* not asserting, who knows what nonsense a user can generate */
		dbg("%s has unspecified type", __func__);
		return unset_port;
	}

	return ip_hport(endpoint.hport);
}

void update_endpoint_port(ip_endpoint *endpoint, ip_port port)
{
	*endpoint = set_endpoint_port(*endpoint, port);
}

ip_endpoint set_endpoint_port(const ip_endpoint endpoint, ip_port port)
{
	const struct ip_info *afi = endpoint_type(&endpoint);
	if (afi == NULL) {
		/* includes NULL+unset+unknown */
		/* not asserting, who knows what nonsense a user can generate */
		dbg("endpoint has unspecified type");
		return unset_endpoint;
	}

	ip_endpoint dst = endpoint;
	dst.hport = hport(port);
	pendpoint(&dst);
	return dst;
}

const struct ip_info *endpoint_type(const ip_endpoint *endpoint)
{
	if (endpoint_is_unset(endpoint)) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(endpoint->version);
}

bool endpoint_is_unset(const ip_endpoint *endpoint)
{
	if (endpoint == NULL) {
		return true;
	}
	return !endpoint->is_set;
}

const struct ip_protocol *endpoint_protocol(const ip_endpoint endpoint)
{
	if (endpoint_is_unset(&endpoint)) {
		return NULL;
	}
	return protocol_by_ipproto(endpoint.ipproto);
}

bool endpoint_is_specified(const ip_endpoint endpoint)
{
	const struct ip_info *afi = endpoint_type(&endpoint);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	/* treat any 0 address as suspect */
	if (thingeq(endpoint.bytes, unset_bytes)) {
		/* any address (but we know it is zero) */
		return false;
	}

	return true;
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

size_t jam_endpoint(struct jambuf *buf, const ip_endpoint *endpoint)
{
	if (endpoint_is_unset(endpoint)) {
		return jam_string(buf, "<unset-endpoint>");
	}

	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		return jam_string(buf, "<unknown-endpoint>");
	}

	size_t s = 0;
	switch (afi->af) {
	case AF_INET: /* N.N.N.N[:PORT] */
		s += afi->jam_address(buf, afi, &endpoint->bytes);
		break;
	case AF_INET6: /* [N:..:N]:PORT */
		s += jam(buf, "[");
		s += afi->jam_address(buf, afi, &endpoint->bytes);
		s += jam(buf, "]");
		break;
	default:
		bad_case(afi->af);
	}
	s += jam(buf, ":%d", endpoint->hport);
	return s;
}

const char *str_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_endpoint(&buf, endpoint);
	return dst->buf;
}

size_t jam_endpoint_sensitive(struct jambuf *buf, const ip_endpoint *endpoint)
{
	if (!log_ip) {
		return jam_string(buf, "<endpoint>");
	}

	return jam_endpoint(buf, endpoint);
}

const char *str_endpoint_sensitive(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_endpoint_sensitive(&buf, endpoint);
	return dst->buf;
}

size_t jam_endpoints(struct jambuf *buf, const ip_endpoint *src, const ip_endpoint *dst)
{
	size_t s = 0;
	s += jam_endpoint(buf, src);
	s += jam_char(buf, ' ');


	const ip_protocol *srcp = src != NULL ? endpoint_protocol(*src) : &ip_protocol_unset;
	const ip_protocol *dstp = src != NULL ? endpoint_protocol(*dst) : &ip_protocol_unset;
	s += jam_protocols(buf, srcp, '-', dstp);

	s += jam_char(buf, ' ');
	s += jam_endpoint(buf, dst);
	return s;
}

const char *str_endpoints(const ip_endpoint *src, const ip_endpoint *dst, endpoints_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_endpoints(&buf, src, dst);
	return out->buf;
}

bool endpoint_eq_endpoint(const ip_endpoint l, const ip_endpoint r)
{
	if (endpoint_is_unset(&l) && endpoint_is_unset(&r)) {
		/* unset/NULL endpoints are equal */
		return true;
	}

	if (endpoint_is_unset(&l) || endpoint_is_unset(&r)) {
		return false;
	}

	/* must compare individual fields */
	return (l.version == r.version &&
		thingeq(l.bytes, r.bytes) &&
		l.ipproto == r.ipproto &&
		l.hport == r.hport);
}

bool endpoint_address_eq_address(const ip_endpoint endpoint, const ip_address address)
{
	ip_address ea = endpoint_address(endpoint);
	return address_eq_address(ea, address);
}

void pexpect_endpoint(const ip_endpoint *e, where_t where)
{
	if (e == NULL) {
		return;
	}

	/* more strict than is_unset() */
	if (endpoint_eq_endpoint(*e, unset_endpoint)) {
		return;
	}

	/*
	 * XXX: xfrm generates tcp acquires of the form:
	 *
	 *   192.1.2.45:TCP/0 -> 192.1.2.23:TCP/80 (0x5000)
	 *
	 * Presumably source port 0 is because the connect(?) call
	 * specified no source port.
	 *
	 * Until there's an ip_traffic object to wrap this up, this
	 * passert can't require a port.
	 *
	 * XXX: is [::]:TCP/10 valid?
	 */

	const ip_protocol *protocol = endpoint_protocol(*e);
	if (e->is_set == false ||
	    e->version == 0 ||
	    e->ipproto == 0 ||
	    protocol == NULL /* ||
	    (protocol->endpoint_requires_non_zero_port && e->hport == 0) */) {
		endpoint_buf b;
		log_pexpect(where, "invalid endpoint: "PRI_ENDPOINT,
			    pri_endpoint(e, &b));
	}
}
