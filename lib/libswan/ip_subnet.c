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

ip_subnet subnet_from_raw(where_t where,
			  const struct ip_info *afi,
			  const struct ip_bytes bytes,
			  unsigned prefix_len)
{
	ip_subnet s = {
		.ip.is_set = true,
		.ip.version = afi->ip.version,
		.bytes = bytes,
		.maskbits = prefix_len,
	};
	pexpect_subnet(&s, where);
	return s;
}

ip_subnet subnet_from_address(const ip_address address)
{
	const struct ip_info *afi = address_info(address);
	if (afi == NULL) {
		return unset_subnet;
	}

	return subnet_from_raw(HERE, afi, address.bytes, afi->mask_cnt);
}

ip_subnet subnet_from_cidr(const ip_cidr cidr)
{
	const struct ip_info *afi = cidr_info(cidr);
	if (afi == NULL) {
		return unset_subnet;
	}

	return subnet_from_raw(HERE, afi,
			       ip_bytes_blit(afi, cidr.bytes,
					     &keep_routing_prefix,
					     &clear_host_identifier,
					     cidr.prefix_len),
			       cidr.prefix_len);
}

err_t address_mask_to_subnet(const ip_address address,
			     const ip_address mask,
			     ip_subnet *subnet)
{
	*subnet = unset_subnet;
	const struct ip_info *afi = address_info(address);
	if (afi == NULL) {
		return "invalid address";
	}

	if (address_info(mask) != afi) {
		return "invalid mask";
	}

	int prefix_len =  ip_bytes_mask_len(afi, mask.bytes);
	if (prefix_len < 0) {
		return "invalid mask";
	}

	struct ip_bytes prefix = ip_bytes_blit(afi, address.bytes,
					       &keep_routing_prefix,
					       &clear_host_identifier,
					       prefix_len);
	*subnet = subnet_from_raw(HERE, afi, prefix, prefix_len);
	return NULL;
}

ip_address subnet_prefix(const ip_subnet subnet)
{
	const struct ip_info *afi = subnet_info(subnet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address;
	}

	struct ip_bytes prefix = ip_bytes_blit(afi, subnet.bytes,
					       &keep_routing_prefix,
					       &clear_host_identifier,
					       subnet.maskbits);
	return address_from_raw(HERE, afi, prefix);
}

const struct ip_info *subnet_type(const ip_subnet *subnet)
{
	if (subnet == NULL) {
		return NULL;
	}

	/* may return NULL */
	return subnet_info(*subnet);
}

const struct ip_info *subnet_info(const ip_subnet subnet)
{
	if (!subnet.ip.is_set) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(subnet.ip.version);
}

bool subnet_is_unset(const ip_subnet *subnet)
{
	if (subnet == NULL) {
		return true;
	}

	return !subnet->ip.is_set;
}

bool subnet_is_zero(const ip_subnet subnet)
{
	const struct ip_info *afi = subnet_info(subnet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	return subnet_eq_subnet(subnet, afi->subnet.zero);
}

bool subnet_is_all(const ip_subnet subnet)
{
	const struct ip_info *afi = subnet_info(subnet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	return subnet_eq_subnet(subnet, afi->subnet.all);
}

uintmax_t subnet_size(const ip_subnet subnet)
{
	ip_range range = range_from_subnet(subnet);
	return range_size(range);
}

/*
 * subnet mask - get the mask of a subnet, as an address
 *
 * For instance 1.2.3.4/24 -> 255.255.255.0.
 */

ip_address subnet_prefix_mask(const ip_subnet subnet)
{
	const struct ip_info *afi = subnet_info(subnet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address;
	}

	struct ip_bytes mask = ip_bytes_blit(afi, subnet.bytes,
					     &set_routing_prefix,
					     &clear_host_identifier,
					     subnet.maskbits);
	return address_from_raw(HERE, afi, mask);
}

unsigned subnet_prefix_bits(const ip_subnet subnet)
{
	return subnet.maskbits;
}

size_t jam_subnet(struct jambuf *buf, const ip_subnet *subnet)
{
	const struct ip_info *afi = subnet_type(subnet);
	if (afi == NULL) {
		return jam_string(buf, "<unset-subnet>");
	}

	size_t s = 0;
	ip_address sa = subnet_prefix(*subnet);
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

size_t jam_subnets(struct jambuf *buf, ip_subnets subnets)
{
	size_t s = 0;
	const char *sep = "";
	for (unsigned i = 0; i < subnets.len; i++) {
		s += jam_string(buf, sep);
		sep = ",";
		s += jam_subnet(buf, &subnets.list[i]);
	}
	return s;
}

void pexpect_subnet(const ip_subnet *s, where_t where)
{
	if (s == NULL) {
		return;
	}

	/* more strict than is_unset() */
	if (subnet_eq_subnet(*s, unset_subnet)) {
		return;
	}

	if (s->ip.is_set == false ||
	    s->ip.version == 0) {
		llog_pexpect(&global_logger, where, "invalid subnet: "PRI_SUBNET, pri_subnet(s));
	}
}

bool subnet_eq_subnet(const ip_subnet l, const ip_subnet r)
{
	if (subnet_is_unset(&l) && subnet_is_unset(&r)) {
		/* NULL/unset subnets are equal */
		return true;
	}

	if (subnet_is_unset(&l) || subnet_is_unset(&r)) {
		return false;
	}

	/* must compare individual fields */
	return (l.ip.version == r.ip.version &&
		thingeq(l.bytes, r.bytes) &&
		l.maskbits == r.maskbits);
}

bool subnet_eq_address(const ip_subnet subnet, const ip_address address)
{
	const struct ip_info *afi = subnet_info(subnet);
	if (afi == NULL) {
		return false;
	}

	/* XXX: reject any? */
	/* must compare individual fields */
	return (subnet.ip.version == address.ip.version &&
		thingeq(subnet.bytes, address.bytes) &&
		subnet.maskbits == afi->mask_cnt);
}

bool subnet_in_subnet(const ip_subnet l, const ip_subnet r)
{
	const struct ip_info *afi = subnet_info(l);
	if (afi == NULL) {
		return false;
	}

	if (subnet_info(r) != afi) {
		return false;
	}

	/* l's prefix needs to be longer than r's */
	if (l.maskbits < r.maskbits) {
		return false;
	}

	/* L.prefix[0 .. R.bits] == R.prefix[0.. R.bits] */
	struct ip_bytes lb = ip_bytes_blit(afi,
					   /*LEFT*/l.bytes,
					   &keep_routing_prefix,
					   &clear_host_identifier,
					   /*RIGHT*/r.maskbits);
	return thingeq(lb, r.bytes);
}

bool address_in_subnet(const ip_address l, const ip_subnet r)
{
	const struct ip_info *afi = address_info(l);
	if (afi == NULL) {
		return false;
	}

	if (subnet_info(r) != afi) {
		return false;
	}

	/* L.prefix[0 .. R.bits] == R.prefix[0.. R.bits] */
	struct ip_bytes lb = ip_bytes_blit(afi,
					   /*LEFT*/l.bytes,
					   &keep_routing_prefix,
					   &clear_host_identifier,
					   /*RIGHT*/r.maskbits);
	return thingeq(lb, r.bytes);
}

err_t addresses_to_nonzero_subnet(const ip_address start, const ip_address end, ip_subnet *dst)
{
	*dst = unset_subnet;
	ip_range range;
	err_t err = addresses_to_nonzero_range(start, end, &range);
	if (err != NULL) {
		return err;
	}

	return range_to_subnet(range, dst);
}
