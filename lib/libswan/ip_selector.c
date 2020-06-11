/* ip selector, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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
	return memeq(&unset_selector, selector, sizeof(unset_selector));
}

void jam_selector(jambuf_t *buf, const ip_subnet *subnet)
{
	jam_address(buf, &subnet->addr); /* sensitive? */
	jam(buf, "/%u", subnet->maskbits);
	int port = subnet_hport(subnet);
	if (port >= 0) {
		jam(buf, ":%d", port);
	}
}

const char *str_selector(const ip_selector *selector, selector_buf *out)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector(&buf, selector);
	return out->buf;
}

ip_selector selector_from_address(const ip_address *address,
				  const ip_protoport *protoport)
{
	const struct ip_info *afi = address_type(address);
	if (!pexpect(afi != NULL)) {
		return unset_selector;
	}
	ip_subnet subnet = subnet_from_address(address);
	return selector_from_subnet(&subnet, protoport);
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
			.ipproto = protoport->protocol,
			.hport = protoport->port,
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
	return endpoint_type(&selector->addr);
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
	return strip_endpoint(&selector->addr, HERE);
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
	return (/* exclude unset */
		selector_is_set(r) &&
		/* version (4/6) wildcards!?! */
		(r->addr.version == 0 || l->addr.version == r->addr.version) &&
		/* protocol wildcards */
		(r->addr.ipproto == 0 || l->addr.ipproto == r->addr.ipproto) &&
		/* port wildcards */
		(r->addr.hport == 0 || l->addr.hport == r->addr.hport) &&
		/* exclude any(zero), other than for any/0 */
		(address_is_any(&r->addr) ? r->maskbits == 0 : r->maskbits > 0) &&
		/* address < range */
		addrinsubnet(&l->addr, r) &&
		/* more maskbits => more address & smaller subnet */
		l->maskbits >= r->maskbits);
}

bool address_in_selector(const ip_address *address, const ip_selector *selector)
{
	ip_protoport protoport = selector_protoport(selector);
	/* HACK: use same prot/port as selector so they always match */
	ip_selector inner = selector_from_address(address, &protoport);
	return selector_in_selector(&inner, selector);
}

bool endpoint_in_selector(const ip_endpoint *endpoint, const ip_selector *selector)
{
	ip_selector inner = selector_from_endpoint(endpoint);
	return selector_in_selector(&inner, selector);
}

#if 0
bool endpoint_in_selector(const ip_endpoint *l, const ip_selector *r)
{
}
#endif

bool selector_eq(const ip_selector *l, const ip_selector *r)
{
	return samesubnet(l, r);
}

bool selector_address_eq(const ip_selector *l, const ip_selector *r)
{
	return subnetishost(l) && subnetishost(r) && sameaddr(&l->addr, &r->addr);
}
