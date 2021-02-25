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
	return thingeq(*selector, unset_selector);
}

size_t jam_selector(struct jambuf *buf, const ip_selector *selector)
{
	size_t s = 0;
	if (selector_is_unset(selector)) {
		return jam_string(buf, "<unset-selector>");
	}
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
		.is_selector = true,
		.maskbits = subnet->maskbits,
		.addr = {
			.version = subnet->addr.version,
			.bytes = subnet->addr.bytes,
			.ipproto = protocol->ipproto,
			.hport = port.hport,
		},
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
	return ip_version_info(selector->addr.version);
}

ip_port selector_port(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return unset_port;
	}
	return ip_hport(selector->addr.hport);
}

const ip_protocol *selector_protocol(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return NULL;
	}
	return protocol_by_ipproto(selector->addr.ipproto);
}

ip_range selector_range(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return unset_range;
	}
	const struct ip_info *afi = selector_type(selector);
	ip_address start = address_from_blit(afi, selector->addr.bytes,
					     /*routing-prefix*/&keep_bits,
					     /*host-identifier*/&clear_bits,
					     selector->maskbits);
	ip_address end = address_from_blit(afi, selector->addr.bytes,
					   /*routing-prefix*/&keep_bits,
					   /*host-identifier*/&set_bits,
					   selector->maskbits);
	return range(&start, &end);
}

ip_address selector_prefix(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return unset_address;
	}
	const struct ip_info *afi = selector_type(selector);
	return address_from_raw(afi, &selector->addr.bytes);
}

unsigned selector_prefix_bits(const ip_selector *selector)
{
	return selector->maskbits;
}

ip_address selector_prefix_mask(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return unset_address;
	}
	const struct ip_info *afi = selector_type(selector);
	return address_from_blit(afi, selector->addr.bytes,
				 /*routing-prefix*/ &set_bits,
				 /*host-identifier*/ &clear_bits,
				 selector->maskbits);
}

bool selector_contains_all_addresses(const ip_selector *selector)
{
	if (selector_is_unset(selector)) {
		return false;
	}
	if (selector->addr.hport != 0) {
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
	/* Unlike selectorishost() this rejects 0.0.0.0/32. */
	if (selector_is_unset(selector)) {
		return false;
	}
	const struct ip_info *afi = selector_type(selector);
	if (selector->addr.hport != 0) {
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
	if (selector_is_unset(selector)) {
		return false;
	}
	const struct ip_info *afi = selector_type(selector);
	if (selector->maskbits != afi->mask_cnt) {
		return false;
	}
	if (selector->addr.hport != 0) {
		return false; /* weird one */
	}
	ip_address network = selector_prefix(selector);
	return address_is_any(&network);
}

bool selector_in_selector(const ip_selector *l, const ip_selector *r)
{
	/* exclude unset */
	if (selector_is_unset(l) || selector_is_unset(r)) {
		return false;
	}
	/* version wild card (actually version is 4/6) */
	if (/*r->addr.version != 0 &&*/ l->addr.version != r->addr.version) {
		return false;
	}
	/* protocol wildcards */
	if (r->addr.ipproto != 0 && l->addr.ipproto != r->addr.ipproto) {
		return false;
	}
	/* port wildcards */
	if (r->addr.hport != 0 && l->addr.hport != r->addr.hport) {
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
	const struct ip_info *afi = selector_type(l);
	ip_address lp = address_from_blit(afi,
					  /*LEFT*/l->addr.bytes,
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
	pselector(l);
	pselector(r);
	const struct ip_info *lt = selector_type(l);
	const struct ip_info *rt = selector_type(r);
	if (lt == NULL || rt == NULL) {
		/* NULL/unset selectors are equal */
		return (lt == NULL && rt == NULL);
	}
	/* strict check */
	return (l->maskbits == r->maskbits &&
		l->addr.version == r->addr.version &&
		l->addr.ipproto == r->addr.ipproto &&
		thingeq(l->addr.bytes, r->addr.bytes));
}

void pexpect_selector(const ip_selector *s, const char *t, where_t where)
{
	if (s != NULL && s->addr.version != 0) { /* non-zero */
		if (s->is_subnet == true ||
		    s->is_selector == false) {
			selector_buf b;
			dbg("EXPECTATION FAILED: %s is not a selector; "PRI_SELECTOR" "PRI_WHERE,
			    t, pri_selector(s, &b), pri_where(where));
		}
	}
}

int selector_hport(const ip_selector *s)
{
	return endpoint_hport(&s->addr);
}

#define DEFAULTSUBNET "%default"

/*
 * ttosubnet - convert text "addr/mask" to address and mask
 * Mask can be integer bit count.
 */
err_t numeric_to_selector(shunk_t src,
			  const struct ip_info *afi, /* could be NULL */
			  ip_selector *dst)
{
	err_t oops;

	/*
	 * Match %default, can't work when AFI=NULL.
	 *
	 * you cannot use af==AF_UNSPEC and src=0/0,
	 * makes no sense as will it be AF_INET
	 */
	if (hunk_strcaseeq(src, DEFAULTSUBNET)) {
		if (afi == NULL) {
			return "unknown address family with " DEFAULTSUBNET " subnet not allowed.";
		}
		*dst = afi->selector.all; /* 0.0.0.0/0 or ::/0 */
		return NULL;
	}

	/* split the input into ADDR "/" (mask)... */
	char slash;
	shunk_t addr = shunk_token(&src, &slash, "/");
	if (slash == '\0') {
		/* consumed entire input */
		return "no / in subnet specification";
	}

	ip_address addrtmp;
	oops = numeric_to_address(addr, afi, &addrtmp);
	if (oops != NULL) {
		return oops;
	}

	if (afi == NULL) {
		afi = address_type(&addrtmp);
	}
	if (afi == NULL) {
		/* XXX: pexpect()? */
		return "unknown address family in ttosubnet";
	}

	/* split the input into MASK [ ":" (port) ... ] */
	char colon;
	shunk_t mask = shunk_token(&src, &colon, ":");
	uintmax_t maskbits;
	oops = shunk_to_uintmax(mask, NULL, 10, &maskbits, afi->mask_cnt);
	if (oops != NULL) {
		if (afi == &ipv4_info) {
			ip_address masktmp;
			oops = numeric_to_address(mask, afi, &masktmp);
			if (oops != NULL) {
				return oops;
			}

			int i = masktocount(&masktmp);
			if (i < 0) {
				return "non-contiguous or otherwise erroneous mask";
			}
			maskbits = i;
		} else {
			return "masks are not permitted for IPv6 addresses";
		}
	}

	/* the :PORT */
	uintmax_t port;
	if (colon != '\0') {
		err_t oops = shunk_to_uintmax(src, NULL, 0, &port, 0xFFFF);
		if (oops != NULL) {
			return oops;
		}
	} else {
		port = 0;
	}

	chunk_t addr_chunk = address_as_chunk(&addrtmp);
	unsigned n = addr_chunk.len;
	uint8_t *p = addr_chunk.ptr; /* cast void* */
	if (n == 0)
		return "unknown address family";

	unsigned c = maskbits / 8;
	if (c > n)
		return "impossible mask count";

	p += c;
	n -= c;

	unsigned m = 0xff;
	c = maskbits % 8;
	if (n > 0 && c != 0)	/* partial byte */
		m >>= c;

	for (; n > 0; n--) {
		if ((*p & m) != 0) {
			return "improper subnet, host-part bits on";
		}
		m = 0xff;
		p++;
	}

	/*
	 * XXX: see above, this isn't a true subnet as addrtmp can
	 * have its port set.
	 */
	dst->addr = endpoint3(&ip_protocol_unset, &addrtmp, ip_hport(port));
	dst->maskbits = maskbits;

	return NULL;
}
