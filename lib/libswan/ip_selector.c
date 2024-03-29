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
	return (!thingeq(selector.bytes, unset_ip_bytes) &&
		selector.maskbits == afi->mask_cnt &&
		selector.ipproto == 0 &&
		selector.hport == 0);
}

size_t jam_selector(struct jambuf *buf, const ip_selector *selector)
{
	if (selector == NULL) {
		return jam_string(buf, "<null-selector>");
	}

	if (!selector->is_set) {
		return jam_string(buf, "<unset-selector>");
	}

	const struct ip_info *afi = selector_type(selector);
	if (afi == NULL) {
		return jam(buf, PRI_SELECTOR, pri_selector(selector));
	}

	size_t s = 0;

	/* always <address>/<length> */
	ip_address sa = selector_prefix(*selector);
	s += jam_address(buf, &sa);
	s += jam(buf, "/%u", selector->maskbits);

	/* optionally /<protocol>/<port> */
	if (selector->ipproto != 0 || selector->hport != 0) {
		const struct ip_protocol *protocol = selector_protocol(*selector);
		if (selector->hport == 0 && protocol->zero_port_is_any) {
			s += jam(buf, "/%s", protocol->name);
		} else {
			s += jam(buf, "/%s/%d", protocol->name, selector->hport);
		}
	}

	return s;
}

const char *str_selector(const ip_selector *selector, selector_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector(&buf, selector);
	return out->buf;
}

size_t jam_selector_subnet(struct jambuf *buf, const ip_selector *selector)
{
	if (selector == NULL) {
		return jam_string(buf, "<null-selector>");
	}
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
	return s;
}

const char *str_selector_subnet(const ip_selector *selector, subnet_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector_subnet(&buf, selector);
	return out->buf;
}

size_t jam_selector_subnet_port(struct jambuf *buf, const ip_selector *selector)
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
	s += jam_address(buf, &sa);
	s += jam(buf, "/%u", selector->maskbits);
	if (selector->ipproto != 0 || selector->hport != 0) {
		s += jam(buf, ":%d", selector->hport);
	}
	return s;
}

const char *str_selector_subnet_port(const ip_selector *selector, selector_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector_subnet_port(&buf, selector);
	return out->buf;
}

size_t jam_selector_pair(struct jambuf *buf,
			 const ip_selector *src,
			 const ip_selector *dst)
{
	if (selector_is_unset(src) || selector_is_unset(dst)) {
		return jam_string(buf, "<unset-selectors>");
	}

	size_t s = 0;
	const char *sep = "";
	FOR_EACH_THING(selector, src, dst) {
		s += jam_string(buf, sep); sep = "===";
		jam_selector(buf, selector);
	}
	return s;
}

const char *str_selector_pair(const ip_selector *src,
			      const ip_selector *dst,
			      selector_pair_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector_pair(&buf, src, dst);
	return out->buf;
}

size_t jam_selector_pair_sensitive(struct jambuf *buf,
				   const ip_selector *src,
				   const ip_selector *dst)
{
	if(!log_ip) {
		return jam_string(buf, "<selectors>");
	}

	return jam_selector_pair(buf, src, dst);
}

const char *str_selector_pair_sensitive(const ip_selector *src,
					const ip_selector *dst,
					selector_pair_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector_pair_sensitive(&buf, src, dst);
	return out->buf;
}

size_t jam_selectors(struct jambuf *buf, ip_selectors selectors)
{
	size_t s = 0;
	s += jam_string(buf, "[");
	const char *sep = "";
	for (unsigned i = 0; i < selectors.len; i++) {
		s += jam_string(buf, sep);
		sep = " ";
		s += jam_selector(buf, &selectors.list[i]);
	}
	s += jam_string(buf, "]");
	return s;
}


ip_selector selector_from_raw(where_t where, enum ip_version version,
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
				 &ip_protocol_all, unset_port);
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

ip_selector selector_from_cidr(const ip_cidr cidr)
{
	const struct ip_info *afi = cidr_info(cidr);
	if (afi == NULL) {
		return unset_selector;
	}

	return selector_from_raw(HERE, cidr.version,
				 ip_bytes_blit(afi, cidr.bytes,
					       &keep_routing_prefix,
					       &clear_host_identifier,
					       cidr.prefix_len),
				 cidr.prefix_len,
				 &ip_protocol_all, unset_port);
}

ip_selector selector_from_subnet(const ip_subnet subnet)
{
	const struct ip_info *afi = subnet_info(subnet);
	if (afi == NULL) {
		return unset_selector;
	}

	return selector_from_raw(HERE, subnet.version,
				 subnet.bytes, subnet.maskbits,
				 &ip_protocol_all, unset_port);
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

ip_selector selector_from_range(const ip_range range)
{
	return selector_from_range_protocol_port(range, &ip_protocol_all, unset_port);
}

ip_selector selector_from_range_protocol_port(const ip_range range,
					      const struct ip_protocol *protocol,
					      const ip_port port)
{
	if (range_is_unset(&range)) {
		return unset_selector;
	}

	ip_subnet subnet;
	happy(range_to_subnet(range, &subnet));
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
	const struct ip_protocol *protocol = protocol_from_ipproto(protoport.ipproto);
	const ip_port port = ip_hport(protoport.hport);
	return selector_from_subnet_protocol_port(subnet, protocol, port);
}

const struct ip_info *selector_type(const ip_selector *selector)
{
	if (selector == NULL) {
		return NULL;
	}

	/* may return NULL */
	return selector_info(*selector);
}

const struct ip_info *selector_info(const ip_selector selector)
{
	if (!selector.is_set) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(selector.version);
}

ip_port selector_port(const ip_selector selector)
{
	if (selector_is_unset(&selector)) {
		return unset_port;
	}

	return ip_hport(selector.hport);
}

const struct ip_protocol *selector_protocol(const ip_selector selector)
{
	if (selector_is_unset(&selector)) {
		return NULL;
	}

	return protocol_from_ipproto(selector.ipproto);
}

ip_range selector_range(const ip_selector selector)
{
	const struct ip_info *afi = selector_type(&selector);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_range;
	}

	struct ip_bytes start = ip_bytes_blit(afi, selector.bytes,
					      &keep_routing_prefix,
					      &clear_host_identifier,
					      selector.maskbits);
	struct ip_bytes end = ip_bytes_blit(afi, selector.bytes,
					    &keep_routing_prefix,
					    &set_host_identifier,
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

	struct ip_bytes prefix = ip_bytes_blit(afi, selector.bytes,
					       &set_routing_prefix,
					       &clear_host_identifier,
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
	struct ip_bytes ib = ip_bytes_blit(afi,
					   /*INNER*/i.bytes,
					   &keep_routing_prefix,
					   &clear_host_identifier,
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

bool address_in_selector_range(const ip_address address, const ip_selector selector)
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
		llog_pexpect(&global_logger, where, "invalid selector: "PRI_SELECTOR, pri_selector(s));
	}
}

int selector_hport(const ip_selector s)
{
	return s.hport;
}

ip_subnet selector_subnet(const ip_selector selector)
{
	const struct ip_info *afi = selector_info(selector);
	if (afi == NULL) {
		return unset_subnet;
	}

	return subnet_from_raw(HERE, selector.version,
			       selector.bytes, selector.maskbits);
}

bool selector_range_eq_selector_range(const ip_selector lhs, const ip_selector rhs)
{
	if (selector_is_unset(&lhs) || selector_is_unset(&rhs)) {
		return false;
	}

	ip_range lhs_range = selector_range(lhs);
	ip_range rhs_range = selector_range(rhs);
	return range_eq_range(lhs_range, rhs_range);
}

bool selector_range_in_selector_range(const ip_selector lhs, const ip_selector rhs)
{
	if (selector_is_unset(&lhs) || selector_is_unset(&rhs)) {
		return false;
	}

	ip_subnet lhs_subnet = selector_subnet(lhs);
	ip_subnet rhs_subnet = selector_subnet(rhs);
	return subnet_in_subnet(lhs_subnet, rhs_subnet);
}

bool selector_range_eq_address(const ip_selector selector, const ip_address address)
{
	if (address_is_unset(&address) || selector_is_unset(&selector)) {
		return false;
	}

	ip_subnet subnet = selector_subnet(selector);
	return subnet_eq_address(subnet, address);
}
