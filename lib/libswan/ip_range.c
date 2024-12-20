/* ip_range type, for libreswan
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2000 Henry Spencer.
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

/*
 * convert from text form of IP address range specification to binary;
 * and more minor utilities for mask length calculations for IKEv2
 */

#include <string.h>
#include <arpa/inet.h>		/* for ntohl() */

#include "jambuf.h"
#include "ip_range.h"
#include "ip_info.h"
#include "passert.h"
#include "lswlog.h"		/* for pexpect() */

const ip_range unset_range; /* all zeros */

ip_range range_from_raw(where_t where, const struct ip_info *afi,
			const struct ip_bytes lo,
			const struct ip_bytes hi)
{
	ip_range r = {
		.is_set = true,
		.version = afi->ip_version,
		.lo = lo,
		.hi = hi,
	};
	pexpect_range(&r, where);
	return r;
}

/*
 * Calculate the number of significant bits in the size of the range.
 * floor(lg(|high-low| + 1)); or -1.
 */

int range_prefix_len(const ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return -1;
	}

	return ip_bytes_prefix_len(afi, range.lo, range.hi);
}

int range_host_len(const ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return -1;
	}

	return ip_bytes_host_len(afi, range.lo, range.hi);
}

size_t jam_range(struct jambuf *buf, const ip_range *range)
{
	const struct ip_info *afi = range_type(range);
	if (afi == NULL) {
		return jam_string(buf, "<unset-range>");
	}

	return jam_ip_bytes_range(buf, afi, range->lo, range->hi);
}

const char *str_range(const ip_range *range, range_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_range(&buf, range);
	return out->buf;
}

ip_range range_from_address(const ip_address address)
{
	const struct ip_info *afi = address_info(address);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_range;
	}

	return range_from_raw(HERE, afi,
			      address.bytes, address.bytes);
}

ip_range range_from_subnet(const ip_subnet subnet)
{
	const struct ip_info *afi = subnet_info(subnet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_range;
	}

	return range_from_raw(HERE, afi,
			      ip_bytes_blit(afi, subnet.bytes,
					    &keep_routing_prefix,
					    &clear_host_identifier,
					    subnet.maskbits),
			      ip_bytes_blit(afi, subnet.bytes,
					    &keep_routing_prefix,
					    &set_host_identifier,
					    subnet.maskbits));
}

const struct ip_info *range_type(const ip_range *range)
{
	if (range == NULL) {
		return NULL;
	}

	/* may return NULL */
	return range_info(*range);
}

const struct ip_info *range_info(const ip_range range)
{
	if (!range.is_set) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(range.version);
}

bool range_is_unset(const ip_range *range)
{
	if (range == NULL) {
		return true;
	}

	return !range->is_set;
}

bool range_is_zero(const ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return false;
	}

	return range_eq_range(range, afi->range.zero);
}

bool range_is_all(const ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return false;
	}

	return range_eq_range(range, afi->range.all);
}

bool range_is_cidr(ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return false;
	}

	return ip_bytes_prefix_len(afi, range.lo, range.hi) >= 0;
}

uintmax_t range_size(const ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return 0;
	}

	struct ip_bytes diff_bytes = ip_bytes_sub(afi, range.hi, range.lo);

	/* more than uintmax_t-bits of host-prefix always overflows. */
	unsigned prefix_bits = ip_bytes_first_set_bit(afi, diff_bytes);
	unsigned host_bits = afi->mask_cnt - prefix_bits;
	if (host_bits > sizeof(uintmax_t) * 8) {
		return UINTMAX_MAX;
	}

	/*
	 * can't overflow; but could be 0xf..f and adding one will
	 * overflow
	 */
	uintmax_t diff = raw_ntoh(diff_bytes.byte, afi->ip_size);
	if (diff >= UINTMAX_MAX) {
		/* size+1 would overflow */
		return UINTMAX_MAX;
	}

	return diff + 1;
}

bool range_eq_address(const ip_range range, const ip_address address)
{
	ip_range address_range = range_from_address(address);
	return range_eq_range(range, address_range);
}

bool range_eq_subnet(const ip_range range, const ip_subnet subnet)
{
	ip_range subnet_range = range_from_subnet(subnet);
	return range_eq_range(range, subnet_range);
}

bool range_eq_range(const ip_range l, const ip_range r)
{
	if (range_is_unset(&l) && range_is_unset(&r)) {
		/* unset/NULL ranges are equal */
		return true;
	}
	if (range_is_unset(&l) || range_is_unset(&r)) {
		return false;
	}

	return (ip_bytes_cmp(l.version, l.lo,
			     r.version, r.lo) == 0 &&
		ip_bytes_cmp(l.version, l.hi,
			     r.version, r.hi) == 0);
}

bool address_in_range(const ip_address address, const ip_range range)
{
	ip_range address_range = range_from_address(address);
	return range_in_range(address_range, range);
}

bool subnet_in_range(const ip_subnet subnet, const ip_range range)
{
	ip_range subnet_range = range_from_subnet(subnet);
	return range_in_range(subnet_range, range);
}

bool range_in_range(const ip_range inner, const ip_range outer)
{
	if (range_is_unset(&inner) || range_is_unset(&outer)) {
		return false;
	}

	return (ip_bytes_cmp(inner.version, inner.lo,
			     outer.version, outer.lo) >= 0 &&
		ip_bytes_cmp(inner.version, inner.hi,
			     outer.version, outer.hi) <= 0);
}

ip_address range_start(const ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return unset_address;
	}

	return address_from_raw(HERE, afi, range.lo);
}

ip_address range_end(const ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return unset_address;
	}

	return address_from_raw(HERE, afi, range.hi);
}

bool range_overlaps_range(const ip_range l, const ip_range r)
{
	if (range_is_unset(&l) || range_is_unset(&r)) {
		/* presumably overlap is bad */
		return false;
	}

	/* l before r */
	if (ip_bytes_cmp(l.version, l.hi,
			 r.version, r.lo) < 0) {
		return false;
	}
	/* l after r */
	if (ip_bytes_cmp(l.version, l.lo,
			 r.version, r.hi) > 0) {
		return false;
	}

	return true;
}

err_t addresses_to_nonzero_range(const ip_address lo, const ip_address hi, ip_range *dst)
{
	*dst = unset_range;

	const struct ip_info *lo_afi = address_info(lo);
	if (lo_afi == NULL) {
		/* NULL+unset+unknown */
		return "start address invalid";
	}

	const struct ip_info *hi_afi = address_info(hi);
	if (hi_afi == NULL) {
		/* NULL+unset+unknown */
		return "end address invalid";
	}

	if (lo_afi != hi_afi) {
		return "conflicting address types";
	}

	/* reject both 0 */
	if (thingeq(lo.bytes, unset_ip_bytes) &&
	    thingeq(hi.bytes, unset_ip_bytes)) {
		return "zero address range";
	}

	if (addrcmp(&lo, &hi) > 0) {
		return "out-of-order";
	}

	*dst = range_from_raw(HERE, lo_afi, lo.bytes, hi.bytes);
	return NULL;
}

err_t range_to_subnet(const ip_range range, ip_subnet *dst)
{
	*dst = unset_subnet;
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return "invalid range";
	}

	/*
	 * Determine the prefix_bits (the CIDR network part) by
	 * matching leading bits of FROM and TO.  Trailing bits
	 * (subnet address) must be either all 0 (from) or 1 (to).
	 */
	int prefix_bits = ip_bytes_prefix_len(afi, range.lo, range.hi);
	if (prefix_bits < 0) {
		return "address range is not a subnet";
	}

	*dst = subnet_from_raw(HERE, afi, range.lo, prefix_bits);
	return NULL;
}

err_t range_offset_to_address(const ip_range range, uintmax_t offset, ip_address *address)
{
	*address = unset_address;

	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return "invalid range";
	}

	int carry = 0;
	struct ip_bytes sum = unset_ip_bytes;/*be safe*/
	for (int j = afi->ip_size - 1; j >= 0; j--) {
		/* extract the next byte to add */
		unsigned add = offset & 0xff;
		offset >>= 8;
		/* update */
		unsigned val = range.lo.byte[j] + add + carry;
		carry = val > 0xff;
		sum.byte[j] = val; /* truncates */
	}

	if (offset > 0) {
		return "offset overflow";
	}

	if (carry > 0) {
		return "address overflow";
	}

	ip_address tmp = address_from_raw(HERE, afi, sum);
	if (!address_in_range(tmp, range)) {
		return "range overflow";
	}

	*address = tmp;
	return NULL;
}

err_t address_to_range_offset(const ip_range range, const ip_address address, uintmax_t *offset)
{
	*offset = UINTMAX_MAX;

	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		return "range invalid";
	}

	if (address_info(address) != afi) {
		return "address is not from range";
	}

	if (!address_in_range(address, range)) {
		return "address out-of-bounds";
	}

	struct ip_bytes diff = ip_bytes_sub(afi, address.bytes, range.lo);

	*offset = raw_ntoh(diff.byte, afi->ip_size);

	if (*offset == UINTMAX_MAX) {
		return "offset overflow";
	}

	return NULL;
}

void pexpect_range(const ip_range *r, where_t where)
{
	if (r == NULL) {
		return;
	}

	/* more strict than is_unset() */
	if (range_eq_range(*r, unset_range)) {
		return;
	}

	if (r->is_set == false ||
	    r->version == 0 ||
	    ip_bytes_cmp(r->version, r->lo, r->version, r->hi) > 0) {
		llog_pexpect(&global_logger, where, "invalid range: "PRI_RANGE, pri_range(r));
	}
}
