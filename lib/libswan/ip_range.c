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

ip_range range(const ip_address *start, const ip_address *end)
{
	/* does the caller know best? */
	const struct ip_info *st = address_type(start);
	const struct ip_info *et = address_type(end);
	passert(st == et);
	bool ss = address_is_unset(start);
	bool es = address_is_unset(end);
	passert(ss == es);
	ip_range r = {
		.start = *start,
		.end = *end,
	};
	return r;
}

/*
 * Calculate the number of significant bits in the size of the range.
 * floor(lg(|high-low| + 1))
 *
 * ??? this really should use ip_range rather than a pair of ip_address values
 */

int range_significant_bits(const ip_range *range)
{
	const struct ip_info *afi = range_type(range);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return -1;
	}

	struct ip_bytes diff = bytes_diff(afi, range->end.bytes, range->start.bytes);
	int fsb = bytes_first_set_bit(afi, diff);
#if 0
	fprintf(stderr, "fsb = %d diff="PRI_BYTES"\n", fsb, pri_bytes(diff));
#endif
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
		*dst = (ip_range) {
			.start = start_address,
			.end = start_address,
		};
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
		*dst = (ip_range) {
			.start = address_from_blit(afi, start_address.bytes,
						   /*routing-prefix*/&keep_bits,
						   /*host-identifier*/&clear_bits,
						   maskbits),
			.end = address_from_blit(afi, start_address.bytes,
						 /*routing-prefix*/&keep_bits,
						 /*host-identifier*/&set_bits,
						 maskbits),
		};
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
		*dst = (ip_range) {
			.start = start_address,
			.end = end_address,
		};
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
	size_t s = 0;
	s += jam_address(buf, &range->start);
	if (range->is_subnet) {
		ip_subnet tmp_subnet;
		rangetosubnet(&range->start, &range->end, &tmp_subnet);
		s += jam(buf, "/%u", tmp_subnet.maskbits);
	} else {
		s += jam(buf, "-");
		s += jam_address(buf, &range->end);
	}
	return s;
}

const char *str_range(const ip_range *range, range_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_range(&buf, range);
	return out->buf;
}

ip_range range_from_subnet(const ip_subnet *subnet)
{
	const struct ip_info *afi = subnet_type(subnet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_range;
	}

	ip_range r = {
		.start = address_from_blit(afi, subnet->bytes,
					   /*routing-prefix*/&keep_bits,
					   /*host-identifier*/&clear_bits,
					   subnet->maskbits),
		.end = address_from_blit(afi, subnet->bytes,
					 /*routing-prefix*/&keep_bits,
					 /*host-identifier*/&set_bits,
					 subnet->maskbits),
	};
	return r;
}

const struct ip_info *range_type(const ip_range *range)
{
	if (range_is_unset(range)) {
		return NULL;
	}

	/* may return NULL */
	const struct ip_info *start = ip_version_info(range->start.version);
	const struct ip_info *end = ip_version_info(range->end.version);
	if (!pexpect(start == end)) {
		return NULL;
	}
	return start;
}

bool range_is_unset(const ip_range *range)
{
	if (range == NULL) {
		return true;
	}
	return thingeq(*range, unset_range);
}

bool range_is_specified(const ip_range *range)
{
	const struct ip_info *afi = range_type(range);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return false;
	}

	bool start = address_is_specified(&range->start);
	bool end = address_is_specified(&range->end);
	if (!pexpect(start == end)) {
		return false;
	}
	return start;
}

bool range_size(ip_range *r, uint32_t *size)
{
	*size = 0;

	const struct ip_info *afi = range_type(r);
	if (afi == NULL) {
		return true; /*return what?!?!?*/
	}

	struct ip_bytes diff = bytes_diff(afi, r->start.bytes, r->end.bytes);

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

bool range_eq(const ip_range *l, const ip_range *r)
{
	if (range_is_unset(l) && range_is_unset(r)) {
		/* unset/NULL ranges are equal */
		return true;
	}
	const struct ip_info *lt = range_type(l);
	const struct ip_info *rt = range_type(r);
	if (lt != rt) {
		return false;
	}
	/* ignore .is_subnet */
	return (address_eq(&l->start, &r->start) &&
		address_eq(&l->end, &r->end));
}
