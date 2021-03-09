/* ip subnet, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2020 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include "jambuf.h"
#include "ip_subnet.h"
#include "passert.h"
#include "lswlog.h"	/* for pexpect() */
#include "ip_info.h"

const ip_subnet unset_subnet; /* all zeros */

ip_subnet subnet_from_address_prefix_bits(const ip_address *address, unsigned prefix_bits)
{
	if (address_is_unset(address)) {
		return unset_subnet;
	}
	ip_subnet s = {
		.is_set = true,
		.version = address->version,
		.bytes = address->bytes,
		.maskbits = prefix_bits,
	};
	psubnet(&s);
	return s;
}

ip_subnet subnet_from_address(const ip_address *address)
{
	if (address_is_unset(address)) {
		return unset_subnet;
	}
	const struct ip_info *afi = address_type(address);
	return subnet_from_address_prefix_bits(address, afi->mask_cnt);
}

err_t address_mask_to_subnet(const ip_address *address,
			     const ip_address *mask,
			     ip_subnet *subnet)
{
	*subnet = unset_subnet;
	if (address_is_unset(address)) {
		return "invalid address type";
	}
	const struct ip_info *afi = address_type(address);
	if (address_type(mask) != afi) {
		return "invalid mask type";
	}
	int prefix_bits =  masktocount(mask);
	if (prefix_bits < 0) {
		return "invalid mask";
	}
	ip_address prefix = address_from_blit(afi, address->bytes,
					      /*routing-prefix*/&keep_bits,
					      /*host-identifier*/&clear_bits,
					      prefix_bits);
	*subnet = subnet_from_address_prefix_bits(&prefix, prefix_bits);
	return NULL;
}

ip_address subnet_prefix(const ip_subnet *subnet)
{
	if (subnet_is_unset(subnet)) {
		return unset_address;
	}
	const struct ip_info *afi = subnet_type(subnet);
	return address_from_blit(afi, subnet->bytes,
				 /*routing-prefix*/&keep_bits,
				 /*host-identifier*/&clear_bits,
				 subnet->maskbits);
}

const struct ip_info *subnet_type(const ip_subnet *subnet)
{
	if (subnet_is_unset(subnet)) {
		return NULL;
	}
	return ip_version_info(subnet->version);
}

bool subnet_is_unset(const ip_subnet *subnet)
{
	if (subnet == NULL) {
		return true;
	}
	return !subnet->is_set;
}

bool subnet_is_specified(const ip_subnet *subnet)
{
	if (subnet_is_unset(subnet)) {
		return false;
	}
	const struct ip_info *afi = subnet_type(subnet);
	if (afi == NULL) {
		return false; /* need IPv4 or IPv6 */
	}
	if (thingeq(subnet->bytes, afi->address.any.bytes)) {
		/* any address (but we know it is zero) */
		return false;
	}
	return true;
}

bool subnet_contains_all_addresses(const ip_subnet *subnet)
{
	if (subnet_is_unset(subnet)) {
		return false;
	}
	if (subnet->maskbits != 0) {
		return false;
	}
	ip_address network = subnet_prefix(subnet);
	return address_is_any(&network);
}

bool subnet_contains_no_addresses(const ip_subnet *subnet)
{
	if (subnet_is_unset(subnet)) {
		return false;
	}
	const struct ip_info *afi = subnet_type(subnet);
	if (subnet->maskbits != afi->mask_cnt) {
		return false;
	}
	ip_address network = subnet_prefix(subnet);
	return address_is_any(&network);
}

bool subnet_contains_one_address(const ip_subnet *subnet)
{
	/* Unlike subnetishost() this rejects 0.0.0.0/32. */
	if (subnet_is_unset(subnet)) {
		return false;
	}
	const struct ip_info *afi = subnet_type(subnet);
	if (subnet->maskbits != afi->mask_cnt) {
		return false;
	}
	/* ignore port */
	ip_address network = subnet_prefix(subnet);
	/* address_is_set(&network) implied as afi non-NULL */
	return !address_is_any(&network); /* i.e., non-zero */
}

/*
 * subnet mask - get the mask of a subnet, as an address
 *
 * For instance 1.2.3.4/24 -> 255.255.255.0.
 */

ip_address subnet_prefix_mask(const ip_subnet *subnet)
{
	if (subnet_is_unset(subnet)) {
		return unset_address;
	}
	const struct ip_info *afi = subnet_type(subnet);
	return address_from_blit(afi, subnet->bytes,
				 /*routing-prefix*/ &set_bits,
				 /*host-identifier*/ &clear_bits,
				 subnet->maskbits);
}

unsigned subnet_prefix_bits(const ip_subnet subnet)
{
	return subnet.maskbits;
}

size_t jam_subnet(struct jambuf *buf, const ip_subnet *subnet)
{
	if (subnet_is_unset(subnet)) {
		return jam_string(buf, "<unset-subnet>");
	}
	size_t s = 0;
	ip_address sa = subnet_prefix(subnet);
	s += jam_address(buf, &sa); /* sensitive? */
	s += jam(buf, "/%u", subnet->maskbits);
	return s;
}

const char *str_subnet(const ip_subnet *subnet, subnet_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_subnet(&buf, subnet);
	return out->buf;
}

void pexpect_subnet(const ip_subnet *subnet, const char *t, where_t where)
{
	if (subnet_is_unset(subnet)) {
		return;
	}
	if (subnet->is_set == false ||
	    subnet->version == 0) {
		subnet_buf b;
		dbg("EXPECTATION FAILED: %s is not a subnet; "PRI_SUBNET" "PRI_WHERE,
		    t, pri_subnet(subnet, &b),
		    pri_where(where));
	}
}

bool subnet_eq(const ip_subnet *l, const ip_subnet *r)
{
	if (subnet_is_unset(l) && subnet_is_unset(r)) {
		/* NULL/unset subnets are equal */
		return true;
	}
	if (subnet_is_unset(l) || subnet_is_unset(r)) {
		return false;
	}
	/* must compare individual fields */
	return (l->version == r->version &&
		thingeq(l->bytes, r->bytes) &&
		l->maskbits == r->maskbits);
}

bool subnet_in(const ip_subnet *l, const ip_subnet *r)
{
	return subnetinsubnet(l, r);
}
