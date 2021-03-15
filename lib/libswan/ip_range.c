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

static ip_range range_from_raw(enum ip_version version,
			       const struct ip_bytes start,
			       const struct ip_bytes end)
{
	ip_range r = {
		.is_set = true,
		.version = version,
		.start = start,
		.end = end,
	};
#if 0
	prange(&r);
#endif
	return r;
}

ip_range range2(const ip_address *start, const ip_address *end)
{
 	/* does the caller know best? */
	const struct ip_info *afi = address_type(start);
	if (afi == NULL) {
		return unset_range;
	}

	if (!pexpect(afi == address_type(end))) {
		return unset_range;
	}

	return range_from_raw(afi->ip_version, start->bytes, end->bytes);
}

/*
 * Calculate the number of significant bits in the size of the range.
 * floor(lg(|high-low| + 1))
 */

int range_host_bits(const ip_range range)
{
	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return -1;
	}

	struct ip_bytes diff = bytes_diff(afi, range.end, range.start);
	int fsb = bytes_first_set_bit(afi, diff);
	return (afi->ip_size * 8) - fsb;
}

/*
 * ttorange - convert text v4 "addr1-addr2" to address_start address_end
 *            v6 allows "subnet/mask" to address_start address_end
 */
err_t ttorange(const char *src, const struct ip_info *afi, ip_range *dst)
{
	*dst = unset_range;
	err_t err;

	/* START or START/MASK or START-END */
	shunk_t end = shunk1(src);
	char sep = '\0';
	shunk_t start = shunk_token(&end, &sep, "/-");

	/* convert start address */
	ip_address start_address;
	err = numeric_to_address(start, afi, &start_address);
	if (err != NULL) {
		return err;
	}

	if (address_is_any(&start_address)) {
		/* XXX: being more specific would mean diag_t */
		return "0.0.0.0 or :: not allowed in range";
	}

	/* get real AFI */
	afi = address_type(&start_address);
	if (afi == NULL) {
		/* should never happen */
		return "INTERNAL ERROR: ttorange() encountered an unknown type";
	}

	switch (sep) {
	case '\0':
	{
		/* single address */
		*dst = range_from_raw(start_address.version,
				      start_address.bytes,
				      start_address.bytes);
		return NULL;
	}
	case '/':
	{
		/* START/MASK */
		uintmax_t maskbits = afi->mask_cnt;
		err = shunk_to_uintmax(end, NULL, 0, &maskbits, afi->mask_cnt);
		if (err != NULL) {
			return err;
		}
		/* XXX: should this reject bad addresses */
		*dst = range_from_raw(afi->ip_version,
				      bytes_from_blit(afi, start_address.bytes,
						      /*routing-prefix*/&keep_bits,
						      /*host-identifier*/&clear_bits,
						      maskbits),
				      bytes_from_blit(afi, start_address.bytes,
						      /*routing-prefix*/&keep_bits,
						      /*host-identifier*/&set_bits,
						      maskbits));
		dst->is_subnet = (afi == &ipv6_info);
		return NULL;
	}
	case '-':
	{
		/* START-END */
		ip_address end_address;
		err = numeric_to_address(end, afi, &end_address);
		if (err != NULL) {
			return err;
		}
		if (addrcmp(&start_address, &end_address) > 0) {
			return "start of range must not be greater than end";
		}
		*dst = range_from_raw(afi->ip_version,
				      start_address.bytes,
				      end_address.bytes);
		return NULL;
	}
	}
	/* SEP is invalid, but being more specific means diag_t */
	return "error";
}

size_t jam_range(struct jambuf *buf, const ip_range *range)
{
	if (range_is_unset(range)) {
		return jam_string(buf, "<unset-range>");
	}

	const struct ip_info *afi = range_type(range);
	if (afi == NULL) {
		return jam_string(buf, "<unknown-range>");
	}

	size_t s = 0;
	s += afi->jam_address(buf, afi, &range->start);
	/* when a subnet, try to calculate the prefix-bits */
	int prefix_bits = (range->is_subnet ? bytes_prefix_bits(afi, range->start, range->end) : -1);
	if (prefix_bits >= 0) {
		s += jam(buf, "/%d", prefix_bits);
	} else {
		s += jam(buf, "-");
		s += afi->jam_address(buf, afi, &range->end);
	}
	return s;
}

const char *str_range(const ip_range *range, range_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_range(&buf, range);
	return out->buf;
}

ip_range range_from_subnet(const ip_subnet subnet)
{
	const struct ip_info *afi = subnet_type(&subnet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_range;
	}

	return range_from_raw(afi->ip_version,
			      bytes_from_blit(afi, subnet.bytes,
					      /*routing-prefix*/&keep_bits,
					      /*host-identifier*/&clear_bits,
					      subnet.maskbits),
			      bytes_from_blit(afi, subnet.bytes,
					      /*routing-prefix*/&keep_bits,
					      /*host-identifier*/&set_bits,
					      subnet.maskbits));
}

const struct ip_info *range_type(const ip_range *range)
{
	if (range_is_unset(range)) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(range->version);
}

bool range_is_unset(const ip_range *range)
{
	if (range == NULL) {
		return true;
	}

	return !range->is_set;
}

bool range_is_specified(const ip_range range)
{
	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	/* don't allow 0 aka %any aka unspecified */
	if (thingeq(range.start, afi->address.any.bytes) ||
	    thingeq(range.end, afi->address.any.bytes)) {
		return false;
	}

	return true;
}

bool range_size(const ip_range range, uint32_t *size)
{
	*size = 0;

	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		return true; /*return what?!?!?*/
	}

	struct ip_bytes diff = bytes_diff(afi, range.start, range.end);

	/* more than 32-bits of host-prefix always overflows. */
	unsigned prefix_bits = bytes_first_set_bit(afi, diff);
	unsigned host_bits = afi->mask_cnt - prefix_bits;
	if (host_bits > 32) {
		*size = UINT32_MAX;
		return true;
	}

	/* can't overflow; but could be 0xffffffff */
	uint32_t n = ntoh_bytes(diff.byte, afi->ip_size);

	/* adding 1 to 0xffffffff overflows */
	if (n == UINT32_MAX) {
		*size = UINT32_MAX;
		return true;
	}

	/* ::1-::1 is one address */
	*size = n + 1;
	return false;
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

	return (bytes_cmp(l.version, l.start,
			  r.version, r.start) == 0 &&
		bytes_cmp(l.version, l.end,
			  r.version, r.end) == 0);
}

bool address_in_range(const ip_address address, const ip_range range)
{
	if (address_is_unset(&address) || range_is_unset(&range)) {
		return false;
	}

	return (bytes_cmp(address.version, address.bytes,
			  range.version, range.start) >= 0 &&
		bytes_cmp(address.version, address.bytes,
			  range.version, range.end) <= 0);
}

bool range_in_range(const ip_range inner, const ip_range outer)
{
	if (range_is_unset(&inner) || range_is_unset(&outer)) {
		return false;
	}

	return (bytes_cmp(inner.version, inner.start,
			  outer.version, outer.start) >= 0 &&
		bytes_cmp(inner.version, inner.end,
			  outer.version, outer.end) <= 0);
}

ip_address range_start(const ip_range range)
{
	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		return unset_address;
	}

	return address_from_raw(range.version, range.start);
}

ip_address range_end(const ip_range range)
{
	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		return unset_address;
	}

	return address_from_raw(range.version, range.end);
}

bool range_overlap(const ip_range l, const ip_range r)
{
	if (range_is_unset(&l) || range_is_unset(&r)) {
		/* presumably overlap is bad */
		return false;
	}

	/* l before r */
	if (bytes_cmp(l.version, l.end,
		      r.version, r.start) < 0) {
		return false;
	}
	/* l after r */
	if (bytes_cmp(l.version, l.start,
		      r.version, r.end) > 0) {
		return false;
	}

	return true;
}

err_t addresses_to_range(const ip_address start, const ip_address end,
			 ip_range *dst)
{
	*dst = unset_range;

	if (address_is_unset(&start)) {
		/* NULL+unset+unknown */
		return "start address invalid";
	}

	if (address_is_unset(&end)) {
		/* NULL+unset+unknown */
		return "end address invalid";
	}

	if (start.version != end.version) {
		return "conflicting address types";
	}

	/* need both 0 */
	if (address_is_any(&start) && address_is_any(&end)) {
		return "empty address range";
	}

	if (addrcmp(&start, &end) > 0) {
		return "out-of-order";
	}

	*dst = range2(&start, &end);
	return NULL;
}

err_t range_to_subnet(const ip_range range, ip_subnet *dst)
{
	*dst = unset_subnet;
	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		return "invalid range";
	}

	/*
	 * Determine the prefix_bits (the CIDR network part) by
	 * matching leading bits of FROM and TO.  Trailing bits
	 * (subnet address) must be either all 0 (from) or 1 (to).
	 */
	int prefix_bits = bytes_prefix_bits(afi, range.start, range.end);
	if (prefix_bits < 0) {
		return "address range is not a subnet";
	}

	*dst = subnet_from_raw(afi->ip_version, range.start, prefix_bits);
	return NULL;
}

err_t range_to_address(const ip_range range, uintmax_t offset, ip_address *address)
{
	*address = unset_address;

	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		return "invalid range";
	}

	int carry = 0;
	struct ip_bytes sum = unset_bytes;/*be safe*/
	for (int j = afi->ip_size - 1; j >= 0; j--) {
		/* extract the next byte to add */
		unsigned add = offset & 0xff;
		offset >>= 8;
		/* update */
		unsigned val = range.start.byte[j] + add + carry;
		carry = val > 0xff;
		sum.byte[j] = val; /* truncates */
	}

	if (offset > 0) {
		return "offset overflow";
	}

	if (carry > 0) {
		return "address overflow";
	}

	ip_address tmp = address_from_raw(range.version, sum);
	if (!address_in_range(tmp, range)) {
		return "range overflow";
	}

	*address = tmp;
	return NULL;
}

err_t range_to_offset(const ip_range range, const ip_address address, uintmax_t *offset)
{
	*offset = UINTMAX_MAX;

	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		return "range invalid";
	}

	if (address_type(&address) != afi) {
		return "address is not from range";
	}

	if (!address_in_range(address, range)) {
		return "address out-of-bounds";
	}

	struct ip_bytes diff = bytes_diff(afi, address.bytes, range.start);

	*offset = ntoh_bytes(diff.byte, afi->ip_size);

	if (*offset == UINTMAX_MAX) {
		return "offset overflow";
	}

	return NULL;
}

bool range_contains_all_addresses(const ip_range range)
{
	if (range_is_unset(&range)) {
		return false;
	}

	const struct ip_info *afi = range_type(&range);
	if (afi == NULL) {
		return false;
	}

	return range_eq_range(range, afi->range.all);
}
