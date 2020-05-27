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
	ip_subnet subnet = subnet_from_address(address);
	return selector_from_subnet(&subnet, protoport);
}

ip_selector selector_from_subnet(const ip_subnet *subnet,
				 const ip_protoport *protoport)
{
	const struct ip_info *afi = subnet_type(subnet);
	if (!pexpect(afi != NULL)) {
		return unset_selector;
	}
	ip_selector selector = *subnet;
	selector.addr.ipproto = protoport->protocol;
	selector.addr.hport = protoport->port;
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
	/* XXX: hack while code cleaned up */
	ip_subnet subnet;
	err_t err = rangetosubnet(&range->start, &range->end, &subnet);
	if (err != NULL) {
		return err;
	}
	*selector = subnet;
	selector->addr.ipproto = protoport->protocol;
	selector->addr.hport = protoport->port;
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

unsigned selector_hport(const ip_selector *selector)
{
	return selector->addr.hport;
}

unsigned selector_ipproto(const ip_selector *selector)
{
	return selector->addr.ipproto;
}

ip_range selector_range(const ip_selector *selector)
{
	return range_from_subnet(selector);
}

bool selector_has_all_addresses(const ip_selector *selector)
{
	return subnet_contains_all_addresses(selector);
}

bool selector_has_one_address(const ip_selector *selector)
{
	/*
	 * Unlike subnetishost() this rejects 0.0.0.0/32.
	 */
	return (subnetishost(selector) &&
		!subnet_contains_no_addresses(selector));
}

bool selector_has_no_addresses(const ip_selector *selector)
{
	return subnet_contains_no_addresses(selector);
}

bool selector_in_selector(const ip_selector *l, const ip_selector *r)
{
	return subnetinsubnet(l, r);
}

bool address_in_selector(const ip_address *l, const ip_selector *r)
{
	return addrinsubnet(l, r);
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
