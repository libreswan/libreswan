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
	return address_from_raw(endpoint->version, &endpoint->bytes);
}

int endpoint_hport(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		dbg("%s has unspecified type", __func__);
		return -1;
	}
	return endpoint->hport;
}

ip_port endpoint_port(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		dbg("%s has unspecified type", __func__);
		return unset_port;
	}
	return ip_hport(endpoint->hport);
}

void update_endpoint_port(ip_endpoint *endpoint, ip_port port)
{
	*endpoint = set_endpoint_port(endpoint, port);
}

ip_endpoint set_endpoint_port(const ip_endpoint *endpoint, ip_port port)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		dbg("endpoint has unspecified type");
		return unset_endpoint;
	}

	ip_endpoint dst = *endpoint;
	dst.hport = hport(port);
#if 0
	pendpoint(&dst);
#endif
	return dst;
}

const struct ip_info *endpoint_type(const ip_endpoint *endpoint)
{
	return (endpoint == NULL ? NULL : ip_version_info(endpoint->version));
}

bool endpoint_is_unset(const ip_endpoint *endpoint)
{
	return thingeq(*endpoint, unset_endpoint);
}

const struct ip_protocol *endpoint_protocol(const ip_endpoint *endpoint)
{
	return protocol_by_ipproto(endpoint->ipproto);
}

bool endpoint_is_specified(const ip_endpoint *endpoint)
{
	if (endpoint_is_unset(endpoint)) {
		return false;
	}
	const struct ip_info *afi = endpoint_type(endpoint);
	if (afi == NULL) {
		return false;
	}
	if (memeq(&endpoint->bytes, &afi->any_address.bytes, afi->ip_size)) {
		/* any address (but we know it is zero) */
		return false;
	}
	if (endpoint->hport == 0) {
		dbg("treating endpoint with unset port as specified");
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
static size_t format_endpoint(struct jambuf *buf, bool sensitive,
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

size_t jam_endpoint(struct jambuf *buf, const ip_endpoint *endpoint)
{
	return format_endpoint(buf, false, endpoint);
}

const char *str_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_endpoint(&buf, endpoint);
	return dst->buf;
}

size_t jam_sensitive_endpoint(struct jambuf *buf, const ip_endpoint *endpoint)
{
	return format_endpoint(buf, !log_ip, endpoint);
}

const char *str_sensitive_endpoint(const ip_endpoint *endpoint, endpoint_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_sensitive_endpoint(&buf, endpoint);
	return dst->buf;
}

bool endpoint_eq(const ip_endpoint *l, const ip_endpoint *r)
{
	const struct ip_info *lt = address_type(l);
	const struct ip_info *rt = address_type(r);
	if (lt == NULL || rt == NULL) {
		/* AF_UNSPEC/NULL are never equal; think NaN */
		return false;
	}
	if (lt != rt) {
		return false;
	}
	if (l->hport != r->hport) {
		return false;
	}
	if (!memeq(&l->bytes, &r->bytes, sizeof(l->bytes))) {
		return false;
	}
	if (l->ipproto != 0 && r->ipproto != 0 &&
	    l->ipproto != r->ipproto) {
		return false;
	}
	if (l->ipproto == 0 || r->ipproto == 0) {
		/*
		 * XXX: note the <<#if 0 pendpoint()>> sprinkled all
		 * over this file.
		 *
		 * There is (was?) code lurking in pluto that does not
		 * initialize the ip_endpoint's .iproto field.  For
		 * instance by assigning an ip_address to an
		 * ip_endpoint (the two are still compatible).
		 *
		 * This dbg() line is one step towards tracking these
		 * cases down.
		 *
		 * (If the intent is for some sort of wildcard match
		 * then either ip_selector or ip_subnet can be used.)
		 */
		dbg("endpoint fuzzy ipproto match");
	}
	return true;
}

void pexpect_endpoint(const ip_endpoint *e, const char *s, where_t where)
{
	if (e != NULL && e->version != 0) {
		/* i.e., is set */
		if (e->is_endpoint == false ||
		    e->is_address == true ||
		    e->hport == 0 ||
		    e->ipproto == 0) {
			address_buf b;
			dbg("EXPECTATION FAILED: %s is not an endpoint; "PRI_ADDRESS" "PRI_WHERE,
			    s, pri_address(e, &b),
			    pri_where(where));
		}
	}
}
