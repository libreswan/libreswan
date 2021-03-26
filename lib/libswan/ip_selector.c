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

bool selector_is_zero(const ip_selector selector)
{
	const struct ip_info *afi = selector_type(&selector);
	if (afi == NULL) {
		/* NULL+unset+unknown+any */
		return false;
	}

	/* ::/128 or 0.0.0.0/32 */
	return selector_eq_selector(selector, afi->selector.zero);
}

bool selector_is_all(const ip_selector selector)
{
	const struct ip_info *afi = selector_type(&selector);
	if (afi == NULL) {
		/* NULL+unset+unknown+any */
		return false;
	}

	/* ::/0 or 0.0.0.0/0 */
	return selector_eq_selector(selector, afi->selector.all);
}

bool selector_contains_one_address(const ip_selector selector)
{
	const struct ip_info *afi = selector_type(&selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	/* Unlike subnetishost() this rejects 0.0.0.0/32. */
	return (!thingeq(selector.bytes, unset_bytes) &&
		selector.maskbits == afi->mask_cnt &&
		selector.ipproto == 0 &&
		selector.hport == 0);
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
	ip_address sa = selector_prefix(*selector);
	s += jam_address(buf, &sa); /* sensitive? */
	s += jam(buf, "/%u", selector->maskbits);
	if (selector->ipproto != 0 || selector->hport != 0) {
		s += jam(buf, ":%d", selector->hport);
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
	if (selector_is_unset(selector)) {
		return jam_string(buf, "<unset-selector>");
	}

	ip_address address = selector_prefix(*selector);
	unsigned prefix_bits = selector_prefix_bits(*selector);
	ip_subnet subnet = subnet_from_address_prefix_bits(address, prefix_bits);
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
	if (selector_is_unset(src) || selector_is_unset(dst)) {
		return jam_string(buf, "<unset-selectors>");
	}

	const struct ip_protocol *srcp = selector_protocol(*src);
	const struct ip_protocol *dstp = selector_protocol(*dst);
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

static ip_selector selector_from_raw(where_t where, enum ip_version version,
				     const struct ip_bytes bytes, unsigned prefix_bits,
				     const struct ip_protocol *protocol, const ip_port port)
{
	ip_selector selector = {
		.is_set = true,
		.maskbits = prefix_bits,
		.version = version,
		.bytes = bytes,
		.ipproto = protocol->ipproto,
		.hport = port.hport,
	};
	pexpect_selector(&selector, where);
	return selector;
}

ip_selector selector_from_address(const ip_address address)
{
	const struct ip_info *afi = address_type(&address);
	if (afi == NULL) {
		return unset_selector;
	}

	return selector_from_raw(HERE, address.version,
				 address.bytes, afi->mask_cnt,
				 &ip_protocol_unset, unset_port);
}

ip_selector selector_from_address_protocol(const ip_address address,
					   const struct ip_protocol *protocol)
{
	const struct ip_info *afi = address_type(&address);
	if (afi == NULL) {
		return unset_selector;
	}

	return selector_from_raw(HERE, address.version,
				 address.bytes, afi->mask_cnt,
				 protocol, unset_port);
}

ip_selector selector_from_address_protocol_port(const ip_address address,
						const struct ip_protocol *protocol,
						const ip_port port)
{	const struct ip_info *afi = address_type(&address);
	if (afi == NULL) {
		return unset_selector;
	}

	return selector_from_raw(HERE, address.version,
				 address.bytes, afi->mask_cnt,
				 protocol, port);
}

ip_selector selector_from_endpoint(const ip_endpoint endpoint)
{
	const struct ip_info *afi = endpoint_type(&endpoint);
	if (afi == NULL) {
		return unset_selector;
	}

	return selector_from_raw(HERE, endpoint.version,
				 endpoint.bytes, afi->mask_cnt,
				 endpoint_protocol(endpoint),
				 endpoint_port(endpoint));
}

ip_selector selector_from_subnet(const ip_subnet subnet)
{
	if (subnet_is_unset(&subnet)) {
		return unset_selector;
	}

	return selector_from_raw(HERE, subnet.version,
				 subnet.bytes, subnet.maskbits,
				 &ip_protocol_unset, unset_port);
}

ip_selector selector_from_range(const ip_range range)
{
	if (range_is_unset(&range)) {
		return unset_selector;
	}

	ip_subnet subnet;
	happy(range_to_subnet(range, &subnet));
	return selector_from_subnet_protocol_port(subnet, &ip_protocol_unset, unset_port);
}

ip_selector selector_from_subnet_protocol_port(const ip_subnet subnet,
					       const struct ip_protocol *protocol,
					       const ip_port port)
{
	if (subnet_is_unset(&subnet)) {
		return unset_selector;
	}

	return selector_from_raw(HERE, subnet.version,
				 subnet.bytes, subnet.maskbits,
				 protocol, port);
}

ip_selector selector_from_address_protoport(const ip_address address,
					    const ip_protoport protoport)
{
	if (address_is_unset(&address)) {
		return unset_selector;
	}

	ip_subnet subnet = subnet_from_address(address);
	return selector_from_subnet_protoport(subnet, protoport);
}

ip_selector selector_from_subnet_protoport(const ip_subnet subnet,
					   const ip_protoport protoport)
{
	const struct ip_protocol *protocol = protocol_by_ipproto(protoport.ipproto);
	const ip_port port = ip_hport(protoport.hport);
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

ip_port selector_port(const ip_selector selector)
{
	if (selector_is_unset(&selector)) {
		return unset_port;
	}

	return ip_hport(selector.hport);
}

const ip_protocol *selector_protocol(const ip_selector selector)
{
	if (selector_is_unset(&selector)) {
		return NULL;
	}

	return protocol_by_ipproto(selector.ipproto);
}

ip_range selector_range(const ip_selector selector)
{
	const struct ip_info *afi = selector_type(&selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_range;
	}

	struct ip_bytes start = bytes_from_blit(afi, selector.bytes,
						/*routing-prefix*/&keep_bits,
						/*host-identifier*/&clear_bits,
						selector.maskbits);
	struct ip_bytes end = bytes_from_blit(afi, selector.bytes,
					      /*routing-prefix*/&keep_bits,
					      /*host-identifier*/&set_bits,
					      selector.maskbits);
	return range_from_raw(HERE, afi->ip_version, start, end);
}

ip_address selector_prefix(const ip_selector selector)
{
	const struct ip_info *afi = selector_type(&selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address;
	}

	return address_from_raw(HERE, selector.version, selector.bytes);
}

unsigned selector_prefix_bits(const ip_selector selector)
{
	return selector.maskbits;
}

ip_address selector_prefix_mask(const ip_selector selector)
{
	const struct ip_info *afi = selector_type(&selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address;
	}

	struct ip_bytes prefix = bytes_from_blit(afi, selector.bytes,
						 /*routing-prefix*/ &set_bits,
						 /*host-identifier*/ &clear_bits,
						 selector.maskbits);
	return address_from_raw(HERE, afi->ip_version, prefix);
}

bool selector_eq_address(const ip_selector selector, const ip_address address)
{
	ip_selector s = selector_from_address(address);
	return selector_eq_selector(selector, s);
}

bool selector_eq_endpoint(const ip_selector selector, const ip_endpoint endpoint)
{
	ip_selector es = selector_from_endpoint(endpoint);
	return selector_eq_selector(selector, es);
}

bool selector_eq_subnet(const ip_selector selector, const ip_subnet subnet)
{
	ip_selector ss = selector_from_subnet(subnet);
	return selector_eq_selector(selector, ss);
}

bool selector_eq_range(const ip_selector selector, const ip_range range)
{
	ip_selector s = selector_from_range(range);
	return selector_eq_selector(selector, s);
}

bool address_in_selector(const ip_address address, const ip_selector selector)
{
	ip_selector as = selector_from_address(address);
	return selector_in_selector(as, selector);
}

bool subnet_in_selector(const ip_subnet subnet, const ip_selector selector)
{
	ip_selector ss = selector_from_subnet(subnet);
	return selector_in_selector(ss, selector);
}

bool range_in_selector(const ip_range range, const ip_selector selector)
{
	ip_selector rs = selector_from_range(range);
	return selector_in_selector(rs, selector);
}

bool selector_in_selector(const ip_selector i, const ip_selector o)
{
	const struct ip_info *afi = selector_type(&i);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	/* version wild card? (actually version is 4/6) */

	/* work in */
	if (selector_type(&o) != afi) {
		return false;
	}

	/* more maskbits => more prefix & smaller subnet */
	if (i.maskbits < o.maskbits) {
		return false;
	}

	/* ib=i.prefix[0 .. o.bits] == ob=o.prefix[0 .. o.bits] */
	struct ip_bytes ib = bytes_from_blit(afi,
					     /*INNER*/i.bytes,
					     /*routing-prefix*/&keep_bits,
					     /*host-identifier*/&clear_bits,
					     /*OUTER*/o.maskbits);
	if (!thingeq(ib, o.bytes)) {
		return false;
	}

	/* protocol wildcards */
	if (o.ipproto != 0 && i.ipproto != o.ipproto) {
		return false;
	}

	/* port wildcard; XXX: assumes UDP/TCP */
	if (o.hport != 0 && i.hport != o.hport) {
		return false;
	}

	return true;
}

bool address_in_selector_subnet(const ip_address address, const ip_selector selector)
{
	if (address_is_unset(&address) || selector_is_unset(&selector)) {
		return false;
	}

	ip_subnet subnet = selector_subnet(selector);
	return address_in_subnet(address, subnet);
}

bool endpoint_in_selector(const ip_endpoint endpoint, const ip_selector selector)
{
	if (endpoint_is_unset(&endpoint) || selector_is_unset(&selector)) {
		return false;
	}

	ip_selector inner = selector_from_endpoint(endpoint);
	return selector_in_selector(inner, selector);
}

bool selector_eq_selector(const ip_selector l, const ip_selector r)
{
	if (selector_is_unset(&l) && selector_is_unset(&r)) {
		/* NULL/unset selectors are equal */
		return true;
	}

	if (selector_is_unset(&l) || selector_is_unset(&r)) {
		return false;
	}

	/* must compare individual fields */
	return (l.version == r.version &&
		thingeq(l.bytes, r.bytes) &&
		l.maskbits == r.maskbits &&
		l.ipproto == r.ipproto &&
		l.hport == r.hport);
}

bool selector_overlaps_selector(const ip_selector l, const ip_selector r)
{
	/* since these are just subnets */
	return (selector_in_selector(l, r) || selector_in_selector(r, l));
}

void pexpect_selector(const ip_selector *s, where_t where)
{
	if (s == NULL) {
		return;
	}

	/* more strict than is_unset() */
	if (selector_eq_selector(*s, unset_selector)) {
		return;
	}

	if (s->is_set == false ||
	    s->version == 0) {
		selector_buf b;
		log_pexpect(where, "invalid selector: "PRI_SELECTOR,
			    pri_selector(s, &b));
	}
}

int selector_hport(const ip_selector s)
{
	return s.hport;
}

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
	oops = ttoaddress_num(address_token, afi/*possibly NULL*/, &address);
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

	struct ip_bytes host = bytes_from_blit(afi, address.bytes,
					       /*routing-prefix*/&clear_bits,
					       /*host-identifier*/&keep_bits,
					       prefix_bits);
	if (!thingeq(host, unset_bytes)) {
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

	ip_subnet subnet = subnet_from_address_prefix_bits(address, prefix_bits);
	*dst = selector_from_subnet_protocol_port(subnet, protocol, port);
	return NULL;
}

ip_subnet selector_subnet(const ip_selector selector)
{
	ip_address address = selector_prefix(selector);
	unsigned prefix_bits = selector_prefix_bits(selector);
	return subnet_from_address_prefix_bits(address, prefix_bits);
}

bool selector_subnet_eq_subnet(const ip_selector lhs, const ip_selector rhs)
{
	if (selector_is_unset(&lhs) || selector_is_unset(&rhs)) {
		return false;
	}

	ip_range lhs_range = selector_range(lhs);
	ip_range rhs_range = selector_range(rhs);
	return range_eq_range(lhs_range, rhs_range);
}

bool selector_subnet_in_subnet(const ip_selector lhs, const ip_selector rhs)
{
	if (selector_is_unset(&lhs) || selector_is_unset(&rhs)) {
		return false;
	}

	ip_subnet lhs_subnet = selector_subnet(lhs);
	ip_subnet rhs_subnet = selector_subnet(rhs);
	return subnet_in_subnet(lhs_subnet, rhs_subnet);
}

bool selector_subnet_eq_address(const ip_selector selector, const ip_address address)
{
	if (address_is_unset(&address) || selector_is_unset(&selector)) {
		return false;
	}

	ip_subnet subnet = selector_subnet(selector);
	return subnet_eq_address(subnet, address);
}
