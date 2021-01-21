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

ip_subnet subnet_from_address_maskbits(const ip_address *address, unsigned maskbits)
{
	ip_subnet s = {
		.is_subnet = true,
		.addr = {
			.version = address->version,
			.bytes = address->bytes,
		},
		.maskbits = maskbits,
	};
	psubnet(&s);
	return s;
}

ip_subnet subnet_from_address(const ip_address *address)
{
	const struct ip_info *afi = address_type(address);
	if (!pexpect(afi != NULL)) {
		return unset_subnet;
	}
	return subnet_from_address_maskbits(address, afi->mask_cnt);
}

err_t address_mask_to_subnet(const ip_address *address,
			     const ip_address *mask,
			     ip_subnet *subnet)
{
	*subnet = unset_subnet;
	const struct ip_info *afi = address_type(address);
	if (afi == NULL) {
		return "invalid address type";
	}
	if (address_type(mask) != afi) {
		return "invalid mask type";
	}
	int maskbits =  masktocount(mask);
	if (maskbits < 0) {
		return "invalid mask";
	}
	ip_address prefix = address_from_blit(afi, address->bytes,
					      /*routing-prefix*/&keep_bits,
					      /*host-identifier*/&clear_bits,
					      maskbits);
	*subnet = subnet_from_address_maskbits(&prefix, maskbits);
	return NULL;
}

ip_address subnet_prefix(const ip_subnet *subnet)
{
	const struct ip_info *afi = subnet_type(subnet);
	if (afi == NULL) {
		return unset_address;
	}
	return address_from_blit(afi, subnet->addr.bytes,
				 /*routing-prefix*/&keep_bits,
				 /*host-identifier*/&clear_bits,
				 subnet->maskbits);
}

ip_address subnet_address(const ip_subnet *subnet)
{
	const struct ip_info *afi = subnet_type(subnet);
	if (afi == NULL) {
		return unset_address;
	}
	return address_from_raw(afi, &subnet->addr.bytes);
}

const struct ip_info *subnet_type(const ip_subnet *subnet)
{
	if (subnet == NULL) {
		return NULL;
	}
	return ip_version_info(subnet->addr.version);
}

bool subnet_is_unset(const ip_subnet *subnet)
{
	if (subnet == NULL) {
		return true;
	}
	return thingeq(*subnet, unset_subnet);
}

bool subnet_is_specified(const ip_subnet *subnet)
{
	if (subnet == NULL) {
		return false;
	}
	return endpoint_is_specified(&subnet->addr);
}

bool subnet_contains_all_addresses(const ip_subnet *s)
{
	const struct ip_info *afi = subnet_type(s);
	if (afi == NULL) {
		return false;
	}
	if (s->addr.hport != 0) {
		return false;
	}
	if (s->maskbits != 0) {
		return false;
	}
	ip_address network = subnet_prefix(s);
	return address_is_any(&network);
}

bool subnet_contains_no_addresses(const ip_subnet *s)
{
	const struct ip_info *afi = subnet_type(s);
	if (afi == NULL) {
		return false;
	}
	if (s->maskbits != afi->mask_cnt) {
		return false;
	}
	if (s->addr.hport != 0) {
		return false; /* weird one */
	}
	ip_address network = subnet_prefix(s);
	return address_is_any(&network);
}

bool subnet_contains_one_address(const ip_subnet *s)
{
	/* Unlike subnetishost() this rejects 0.0.0.0/32. */
	const struct ip_info *afi = subnet_type(s);
	if (afi == NULL) {
		return false;
	}
	if (s->addr.hport != 0) {
		return false;
	}
	if (s->maskbits != afi->mask_cnt) {
		return false;
	}
	/* ignore port */
	ip_address network = subnet_prefix(s);
	/* address_is_set(&network) implied as afi non-NULL */
	return !address_is_any(&network); /* i.e., non-zero */
}

/*
 * subnet mask - get the mask of a subnet, as an address
 *
 * For instance 1.2.3.4/24 -> 255.255.255.0.
 */

ip_address subnet_mask(const ip_subnet *subnet)
{
	const struct ip_info *afi = subnet_type(subnet);
	if (afi == NULL) {
		return unset_address;
	}
	return address_from_blit(afi, subnet->addr.bytes,
				 /*routing-prefix*/ &set_bits,
				 /*host-identifier*/ &clear_bits,
				 subnet->maskbits);
}

size_t jam_subnet(struct jambuf *buf, const ip_subnet *subnet)
{
	if (subnet == NULL) {
		return jam(buf, "<none>/0");
	}
	size_t s = 0;
	ip_address sa = subnet_address(subnet);
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

void pexpect_subnet(const ip_subnet *s, const char *t, where_t where)
{
	if (s != NULL && s->addr.version != 0) {
		if (s->is_subnet == false ||
		    s->is_selector == true) {
			subnet_buf b;
			dbg("EXPECTATION FAILED: %s is not a subnet; "PRI_SUBNET" "PRI_WHERE,
			    t, pri_subnet(s, &b),
			    pri_where(where));
		}
	}
}

bool subnet_eq(const ip_subnet *l, const ip_subnet *r)
{
	psubnet(l);
	psubnet(r);
	const struct ip_info *lt = subnet_type(l);
	const struct ip_info *rt = subnet_type(r);
	if (lt == NULL || rt == NULL) {
		/* NULL/unset subnets are equal */
		return (lt == NULL && rt == NULL);
	}
	return (l->maskbits == r->maskbits &&
		l->addr.version == r->addr.version &&
		thingeq(l->addr.bytes, r->addr.bytes));
}
