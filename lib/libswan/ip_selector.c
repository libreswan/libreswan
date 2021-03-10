/* ip selector, for libreswan
 *
 * Copyright (C) 2020  Andrew Cagney
 * Copyright (C) 2000  Henry Spencer.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "lswlog.h"

#include "ip_selector.h"
#include "ip_info.h"

const ip_selector unset_selector;

bool selector_is_unset(const ip_selector *selector)
{
	if (selector == NULL) {
		return true;
	}
	return !selector->is_set;
}

size_t jam_selector(struct jambuf *buf, const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return jam_string(buf, "<unset-selector>");
	}

	const struct ip_info *afi = selector_type(selector);
	if (afi == NULL) {
		return jam_string(buf, "<unknown-selector>");
	}

	size_t s = 0;
	ip_address sa = selector_prefix(selector);
	s += jam_address(buf, &sa); /* sensitive? */
	s += jam(buf, "/%u", selector->maskbits);
	int port = selector_hport(selector);
	if (port >= 0) {
		s += jam(buf, ":%d", port);
	}
	return s;
}

const char *str_selector(const ip_selector *selector, selector_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector(&buf, selector);
	return out->buf;
}

size_t jam_selector_sensitive(struct jambuf *buf, const ip_selector *selector)
{
	if (!log_ip) {
		return jam_string(buf, "<selector>");
	}
	return jam_selector(buf, selector);
}

const char *str_selector_sensitive(const ip_selector *selector, selector_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector_sensitive(&buf, selector);
	return out->buf;
}

size_t jam_selector_subnet(struct jambuf *buf, const ip_selector *selector)
{
	ip_address address = selector_prefix(selector);
	int prefix_bits = selector_prefix_bits(selector);
	ip_subnet subnet = subnet_from_address_prefix_bits(&address, prefix_bits);
	return jam_subnet(buf, &subnet);
}

const char *str_selector_subnet(const ip_selector *selector, subnet_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector_subnet(&buf, selector);
	return out->buf;
}

size_t jam_selectors(struct jambuf *buf, const ip_selector *src, const ip_selector *dst)
{
	const ip_protocol *srcp = selector_protocol(src);
	const ip_protocol *dstp = selector_protocol(dst);
	size_t s = 0;
	s += jam_selector(buf, src);
	s += jam_char(buf, ' ');
	s += jam_protocols(buf, srcp, '-', dstp);
	s += jam_char(buf, ' ');
	s += jam_selector(buf, dst);
	return s;
}

const char *str_selectors(const ip_selector *src, const ip_selector *dst, selectors_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selectors(&buf, src, dst);
	return out->buf;
}

size_t jam_selectors_sensitive(struct jambuf *buf, const ip_selector *src, const ip_selector *dst)
{
	if(!log_ip) {
		return jam_string(buf, "<selector> -> <selector>");
	}
	return jam_selectors(buf, src, dst);
}

const char *str_selectors_sensitive(const ip_selector *src, const ip_selector *dst, selectors_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selectors_sensitive(&buf, src, dst);
	return out->buf;
}

ip_selector selector_from_address(const ip_address *address)
{
	return selector_from_address_protocol_port(address, &ip_protocol_unset, unset_port);
}

ip_selector selector_from_address_protocol(const ip_address *address,
					   const ip_protocol *protocol)
{
	return selector_from_address_protocol_port(address, protocol, unset_port);
}

ip_selector selector_from_address_protocol_port(const ip_address *address,
						const ip_protocol *protocol,
						ip_port port)
{
	if (address_is_unset(address)) {
		return unset_selector;
	}
	ip_subnet subnet = subnet_from_address(address);
	return selector_from_subnet_protocol_port(&subnet, protocol, port);
}

ip_selector selector_from_endpoint(const ip_endpoint *endpoint)
{
	if (endpoint_is_unset(endpoint)) {
		return unset_selector;
	}
	ip_address address = endpoint_address(endpoint);
	ip_subnet subnet = subnet_from_address(&address);
	const ip_protocol *protocol = endpoint_protocol(endpoint);
	ip_port port = endpoint_port(endpoint);
	return selector_from_subnet_protocol_port(&subnet, protocol, port);
}

ip_selector selector_from_subnet(const ip_subnet *subnet)
{
	return selector_from_subnet_protocol_port(subnet, &ip_protocol_unset, unset_port);
}

ip_selector selector_from_subnet_protocol_port(const ip_subnet *subnet,
					       const ip_protocol *protocol,
					       ip_port port)
{
	if (subnet_is_unset(subnet)) {
		return unset_selector;
	}
	ip_selector selector = {
		.is_set = true,
		.maskbits = subnet->maskbits,
		.version = subnet->version,
		.bytes = subnet->bytes,
		.ipproto = protocol->ipproto,
		.hport = port.hport,
	};
	pselector(&selector);
	return selector;
}

ip_selector selector_from_address_protoport(const ip_address *address,
					    const ip_protoport *protoport)
{
	ip_subnet subnet = subnet_from_address(address);
	return selector_from_subnet_protoport(&subnet, protoport);
}

ip_selector selector_from_subnet_protoport(const ip_subnet *subnet,
					   const ip_protoport *protoport)
{
	const ip_protocol *protocol = protocol_by_ipproto(protoport->ipproto);
	const ip_port port = ip_hport(protoport->hport);
	return selector_from_subnet_protocol_port(subnet, protocol, port);
}

const struct ip_info *selector_type(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(selector->version);
}

ip_port selector_port(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return unset_port;
	}
	return ip_hport(selector->hport);
}

const ip_protocol *selector_protocol(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return NULL;
	}
	return protocol_by_ipproto(selector->ipproto);
}

ip_range selector_range(const ip_selector *selector)
{
	const struct ip_info *afi = selector_type(selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_range;
	}

	ip_address start = address_from_blit(afi, selector->bytes,
					     /*routing-prefix*/&keep_bits,
					     /*host-identifier*/&clear_bits,
					     selector->maskbits);
	ip_address end = address_from_blit(afi, selector->bytes,
					   /*routing-prefix*/&keep_bits,
					   /*host-identifier*/&set_bits,
					   selector->maskbits);
	return range2(&start, &end);
}

ip_address selector_prefix(const ip_selector *selector)
{
	const struct ip_info *afi = selector_type(selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address;
	}

	return address_from_raw(afi, selector->bytes);
}

unsigned selector_prefix_bits(const ip_selector *selector)
{
	return selector->maskbits;
}

ip_address selector_prefix_mask(const ip_selector *selector)
{
	const struct ip_info *afi = selector_type(selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address;
	}

	return address_from_blit(afi, selector->bytes,
				 /*routing-prefix*/ &set_bits,
				 /*host-identifier*/ &clear_bits,
				 selector->maskbits);
}

bool selector_contains_all_addresses(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return false;
	}
	if (selector->hport != 0) {
		return false;
	}
	if (selector->maskbits != 0) {
		return false;
	}
	ip_address network = selector_prefix(selector);
	return address_is_any(&network);
}

bool selector_is_one_address(const ip_selector *selector)
{
	const struct ip_info *afi = selector_type(selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	/* Unlike selectorishost() this rejects 0.0.0.0/32. */
	if (selector->hport != 0) {
		return false;
	}
	if (selector->maskbits != afi->mask_cnt) {
		return false;
	}
	/* ignore port */
	ip_address network = selector_prefix(selector);
	/* address_is_set(&network) implied as afi non-NULL */
	return !address_is_any(&network); /* i.e., non-zero */
}

bool selector_is_address(const ip_selector *selector, const ip_address *address)
{
	ip_selector address_selector = selector_from_address(address);
	return selector_eq(selector, &address_selector);
}

bool selector_contains_no_addresses(const ip_selector *selector)
{
	const struct ip_info *afi = selector_type(selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	if (selector->maskbits != afi->mask_cnt) {
		return false;
	}

	if (selector->hport != 0) {
		return false; /* weird one */
	}

	ip_address network = selector_prefix(selector);
	return address_is_any(&network);
}

bool selector_in_selector(const ip_selector *l, const ip_selector *r)
{
	const struct ip_info *afi = selector_type(l);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	/* version wild card? (actually version is 4/6) */
	if (selector_type(r) != afi) {
		return false;
	}

	/* protocol wildcards */
	if (r->ipproto != 0 && l->ipproto != r->ipproto) {
		return false;
	}
	/* port wildcards */
	if (r->hport != 0 && l->hport != r->hport) {
		return false;
	}
	/* exclude any(zero), other than for any/0 */
	ip_address ra = selector_prefix(r);
	if (address_is_any(&ra) && r->maskbits > 0) {
		return false;
	}
	/* more maskbits => more prefix & smaller subnet */
	if (l->maskbits < r->maskbits) {
		return false;
	}

	/* l.prefix[r.bits] == r.prefix */
	ip_address lp = address_from_blit(afi,
					  /*LEFT*/l->bytes,
					  /*routing-prefix*/&keep_bits,
					  /*host-identifier*/&clear_bits,
					  /*RIGHT*/r->maskbits);
	ip_address rp = selector_prefix(r);
	if (!address_eq(&lp,&rp)) {
		return false;
	}
	return true;
}

bool address_in_selector(const ip_address *address, const ip_selector *selector)
{
	/* HACK: use same protocol/port as selector so they always match */
	const ip_protocol *protocol = selector_protocol(selector);
	const ip_port port = selector_port(selector);
	ip_selector inner = selector_from_address_protocol_port(address, protocol, port);
	return selector_in_selector(&inner, selector);
}

bool endpoint_in_selector(const ip_endpoint *endpoint, const ip_selector *selector)
{
	ip_selector inner = selector_from_endpoint(endpoint);
	return selector_in_selector(&inner, selector);
}

bool selector_eq(const ip_selector *l, const ip_selector *r)
{
	if (selector_is_unset(l) && selector_is_unset(r)) {
		/* NULL/unset selectors are equal */
		return true;
	}
	if (selector_is_unset(l) || selector_is_unset(r)) {
		return false;
	}
	/* must compare individual fields */
	return (l->version == r->version &&
		thingeq(l->bytes, r->bytes) &&
		l->maskbits == r->maskbits &&
		l->ipproto == r->ipproto &&
		l->hport == r->hport);
}

void pexpect_selector(const ip_selector *s, const char *t, where_t where)
{
	if (s == NULL) {
		return;
	}

	/* more strict than is_unset() */
	if (selector_eq(s, &unset_selector)) {
		return;
	}

	if (s->is_set == false ||
	    s->version == 0) {
		selector_buf b;
		log_pexpect(where, "invalid selector: %s; "PRI_SELECTOR,
			    t, pri_selector(s, &b));
	}
}

int selector_hport(const ip_selector *s)
{
	return s->hport;
}

#define DEFAULTSUBNET "%default"

/*
 * Parse the selector:
 *
 *  <address>
 *  <address>/<prefix-bits>
 *  <address>/<prefix-bits>:<protocol>/ <- NOTE
 *  <address>/<prefix-bits>:<protocol>/<port>
 *
 * new syntax required for:
 *
 *  <address>-<address>:<protocol>/<port>-<port>
 *
 */

err_t numeric_to_selector(shunk_t input,
			  const struct ip_info *afi, /* could be NULL */
			  ip_selector *dst)
{
	err_t oops;

	/*
	 * <address> / ...
	 */

	char address_term;
	shunk_t address_token = shunk_token(&input, &address_term, "/");
	/* fprintf(stderr, "address="PRI_SHUNK"\n", pri_shunk(address_token)); */

	ip_address address;
	oops = numeric_to_address(address_token, afi/*possibly NULL*/, &address);
	if (oops != NULL) {
		return oops;
	}

	if (afi == NULL) {
		afi = address_type(&address);
	}
	if (!pexpect(afi != NULL)) {
		return "confused address family";
	}

	/*
	 * ... <prefix-bits> : ...
	 */

	char prefix_bits_term;
	shunk_t prefix_bits_token = shunk_token(&input, &prefix_bits_term, ":");
	/* fprintf(stderr, "prefix-bits="PRI_SHUNK"\n", pri_shunk(prefix_bits_token)); */

	uintmax_t prefix_bits = afi->mask_cnt;
	if (prefix_bits_token.len > 0) {
		oops = shunk_to_uintmax(prefix_bits_token, NULL, 0, &prefix_bits, afi->mask_cnt);
		if (oops != NULL) {
			return oops;
		}
	} else if (prefix_bits_token.ptr != NULL) {
		/* found but empty */
		pexpect(prefix_bits_token.len == 0);
		return "missing prefix bit size";
	}

	ip_address host = address_from_blit(afi, address.bytes,
					    /*routing-prefix*/&clear_bits,
					    /*host-identifier*/&keep_bits,
					    prefix_bits);
	if (!address_eq(&host, &afi->address.any)) {
		return "host-identifier must be zero";
	}

	/*
	 * ... <protocol> / ...
	 */

	char protocol_term;
	shunk_t protocol_token = shunk_token(&input, &protocol_term, "/");
	/* fprintf(stderr, "protocol="PRI_SHUNK"\n", pri_shunk(protocol_token)); */

	const ip_protocol *protocol = &ip_protocol_unset; /*0*/
	if (protocol_token.len > 0) {
		if (protocol_term != '/') {
			return "protocol must be followed by '/'";
		}
		protocol = protocol_by_shunk(protocol_token);
		if (protocol == NULL) {
			return "unknown protocol";
		}
	} else if (protocol_token.ptr != NULL) {
		/* found but empty */
		pexpect(protocol_token.len == 0);
		return "missing protocol/port following ':'";
	}

	/*
	 * ... <port>
	 */

	shunk_t port_token = input;
	/* fprintf(stderr, "port="PRI_SHUNK"\n", pri_shunk(port_token)); */

	ip_port port = unset_port;
	if (port_token.len > 0) {
		uintmax_t hport;
		err_t oops = shunk_to_uintmax(port_token, NULL, 0, &hport, 0xFFFF);
		if (oops != NULL) {
			return oops;
		}
		if (protocol == &ip_protocol_unset && hport != 0) {
			return "a non-zero port requires a valid protocol";
		}
		port = ip_hport(hport);
	} else if (port_token.ptr != NULL) {
		/* found but empty */
		pexpect(port_token.len == 0);
		return "missing port following protocol/";
	}

	ip_subnet subnet = subnet_from_address_prefix_bits(&address, prefix_bits);
	*dst = selector_from_subnet_protocol_port(&subnet, protocol, port);
	return NULL;
}

ip_subnet selector_subnet(const ip_selector selector)
{
	ip_address address = selector_prefix(&selector);
	int prefix_bits = selector_prefix_bits(&selector);
	return subnet_from_address_prefix_bits(&address, prefix_bits);
}

bool selector_subnet_eq(const ip_selector *lhs, const ip_selector *rhs)
{
	ip_range lhs_range = selector_range(lhs);
	ip_range rhs_range = selector_range(rhs);
	return range_eq(lhs_range, rhs_range);
}

bool selector_subnet_in(const ip_selector *lhs, const ip_selector *rhs)
{
	ip_subnet lhs_subnet = selector_subnet(*lhs);
	ip_subnet rhs_subnet = selector_subnet(*rhs);
	return subnet_in(&lhs_subnet, &rhs_subnet);
}

bool selector_subnet_is_address(const ip_selector *selector, const ip_address *address)
{
	ip_subnet subnet = selector_subnet(*selector);
	return subnetishost(&subnet) && addrinsubnet(address, &subnet);
}
