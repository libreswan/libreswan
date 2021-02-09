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

void jam_selector(struct jambuf *buf, const ip_selector *selector)
{
	if (selector == NULL) {
		jam(buf, "<none>/0");
		return;
	}
	ip_address sa = selector_prefix(selector);
	jam_address(buf, &sa); /* sensitive? */
	jam(buf, "/%u", selector->maskbits);
	int port = selector_hport(selector);
	if (port >= 0) {
		jam(buf, ":%d", port);
	}
}

const char *str_selector(const ip_selector *selector, selector_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector(&buf, selector);
	return out->buf;
}

ip_selector selector_from_address_protoport(const ip_address *address,
					    const ip_protoport *protoport)
{
	const struct ip_info *afi = address_type(address);
	if (!pexpect(afi != NULL)) {
		return unset_selector;
	}
	ip_subnet subnet = subnet_from_address(address);
	return selector_from_subnet(&subnet, protoport);
}

ip_selector selector_from_address(const ip_address *address)
{
	return selector_from_address_protoport(address, &unset_protoport);
}

ip_selector selector_from_endpoint(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (!pexpect(afi != NULL)) {
		return unset_selector;
	}
	const ip_protocol *protocol = endpoint_protocol(endpoint);
	ip_port port = endpoint_port(endpoint);
	ip_protoport protoport = protoport2(protocol->ipproto, port);
	ip_address address = endpoint_address(endpoint);
	ip_subnet subnet = subnet_from_address(&address);
	return selector_from_subnet(&subnet, &protoport);
}

ip_selector selector_from_subnet(const ip_subnet *subnet,
				 const ip_protoport *protoport)
{
	const struct ip_info *afi = subnet_type(subnet);
	if (!pexpect(afi != NULL)) {
		return unset_selector;
	}
	ip_selector selector = {
		.is_selector = true,
		.maskbits = subnet->maskbits,
		.addr = {
			.version = subnet->addr.version,
			.bytes = subnet->addr.bytes,
			.ipproto = protoport->ipproto,
			.hport = protoport->hport,
		},
	};
	pselector(&selector);
	return selector;
}

err_t range_to_selector(const ip_range *range,
			const ip_protoport *protoport,
			ip_selector *selector)
{
	const struct ip_info *afi = range_type(range);
	if (!pexpect(afi != NULL)) {
		return "range has unknown type";
	}
	/* XXX: hack while code cleaned up - subnet should have range */
	ip_subnet subnet;
	err_t err = rangetosubnet(&range->start, &range->end, &subnet);
	if (err != NULL) {
		return err;
	}
	*selector = selector_from_subnet(&subnet, protoport);
	return NULL;
}

#if 0
ip_selector selector_from_range()
{
}
#endif

const struct ip_info *selector_type(const ip_selector *selector)
{
	if (selector == NULL) {
		return NULL;
	}
	return ip_version_info(selector->addr.version);
}

ip_protoport selector_protoport(const ip_selector *selector)
{
	return protoport2(selector->addr.ipproto,
			  ip_hport(selector->addr.hport));
}

ip_port selector_port(const ip_selector *selector)
{
	return ip_hport(selector->addr.hport);
}

void update_selector_hport(ip_selector *selector, unsigned hport)
{
	selector->addr.hport = hport;
}

unsigned selector_ipproto(const ip_selector *selector)
{
	return selector->addr.ipproto;
}

const ip_protocol *selector_protocol(const ip_selector *selector)
{
	return protocol_by_ipproto(selector->addr.ipproto);
}

ip_range selector_range(const ip_selector *selector)
{
	return range_from_subnet(selector);
}

ip_address selector_prefix(const ip_selector *selector)
{
	const struct ip_info *afi = selector_type(selector);
	if (afi == NULL) {
		return unset_address;
	}
	return address_from_raw(afi, &selector->addr.bytes);
}

unsigned selector_maskbits(const ip_selector *selector)
{
	return selector->maskbits;
}

bool selector_contains_all_addresses(const ip_selector *selector)
{
	return subnet_contains_all_addresses(selector);
}

bool selector_contains_one_address(const ip_selector *selector)
{
	return subnet_contains_one_address(selector);
}

bool selector_contains_no_addresses(const ip_selector *selector)
{
	return subnet_contains_no_addresses(selector);
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
	/* l.address < range */
	ip_address la = selector_prefix(l);
	if (!addrinsubnet(&la, r)) {
		return false;
	}
	/* more maskbits => more prefix & smaller subnet */
	if (l->maskbits < r->maskbits) {
		return false;
	}
	return true;
}

bool address_in_selector(const ip_address *address, const ip_selector *selector)
{
	ip_protoport protoport = selector_protoport(selector);
	/* HACK: use same ipprot/port as selector so they always match */
	ip_selector inner = selector_from_address_protoport(address, &protoport);
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
		*dst = afi->all_addresses; /* 0.0.0.0/0 or ::/0 */
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
