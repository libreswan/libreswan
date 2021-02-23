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

int iprange_bits(ip_address low, ip_address high)
{
	const struct ip_info *ht = address_type(&high);
	const struct ip_info *lt = address_type(&low);
	if (ht == NULL || lt == NULL) {
		/* either invalid */
		return -1;
	}
	if (ht != lt) {
		return -1;
	}

	shunk_t hs = address_as_shunk(&high);
	const uint8_t *hp = hs.ptr; /* cast const void * */
	passert(hs.len > 0);
	size_t n = hs.len;

	shunk_t ls = address_as_shunk(&low);
	const uint8_t *lp = ls.ptr; /* cast const void * */
	passert(hs.len == ls.len);

	ip_address diff = low;	/* initialize all the contents to sensible values */
	unsigned char *dp;
	chunk_t diff_chunk = address_as_chunk(&diff);
	dp = diff_chunk.ptr; /* cast void* */

	unsigned lastnz = n;

	/* subtract: d = h - l */
	int carry = 0;
	unsigned j;
	for (j = n; j > 0; ) {
		j--;
		int val = hp[j] - lp[j] - carry;
		if (val < 0) {
			val += 0x100u;
			carry = 1;
		} else {
			carry = 0;
		}
		dp[j] = val;
		if (val != 0)
			lastnz = j;
	}

	/* if the answer was negative, complement it */
	if (carry != 0) {
		lastnz = n;	/* redundant, but not obviously so */
		for (j = n; j > 0; ) {
			j--;
			int val = 0xFFu - dp[j] + carry;
			if (val >= 0x100) {
				val -= 0x100;
				carry = 1;	/* redundant, but not obviously so */
			} else {
				carry = 0;
			}
			dp[j] = val;
			if (val != 0)
				lastnz = j;
		}
	}

	/* find leftmost bit in dp[lastnz] */
	unsigned bo = 0;
	if (lastnz != n) {
		bo = 0;
		for (unsigned m = 0x80u; (m & dp[lastnz]) == 0;  m >>=1)
			bo++;
	}
	return (n - lastnz) * 8 - bo;
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
		return unset_range;
	}
	ip_range r = {
		.start = address_from_blit(afi, subnet->addr.bytes,
					   /*routing-prefix*/&keep_bits,
					   /*host-identifier*/&clear_bits,
					   subnet->maskbits),
		.end = address_from_blit(afi, subnet->addr.bytes,
					 /*routing-prefix*/&keep_bits,
					 /*host-identifier*/&set_bits,
					 subnet->maskbits),
	};
	return r;
}

const struct ip_info *range_type(const ip_range *range)
{
	if (range == NULL) {
		return NULL;
	}
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

bool range_is_specified(const ip_range *r)
{
	if (r == NULL) {
		return false;
	}
	bool start = address_is_specified(&r->start);
	bool end = address_is_specified(&r->end);
	if (!pexpect(start == end)) {
		return false;
	}
	return start;
}

bool range_size(ip_range *r, uint32_t *size) {

	bool truncated = false;
	uint32_t n = *size = 0;

	n = (ntohl_address(&r->end) - ntohl_address(&r->start));
	if (address_type(&r->start) == &ipv6_info) {
		int prefix_len = ipv6_info.mask_cnt - iprange_bits(r->start, r->end);
		if (prefix_len < IPV6_MIN_POOL_PREFIX_LEN) {
			truncated = true;
			uint32_t s = ntohl_address(&r->start);
			n = UINT32_MAX - s;
		}

		if (n < UINT32_MAX)
			n++;
		else
			truncated = true;
	} else {
		/* IPv4 */
		n++;
	}

	*size = n;
	return truncated;
}

bool range_eq(const ip_range *l, const ip_range *r)
{
	const struct ip_info *lt = range_type(l);
	const struct ip_info *rt = range_type(r);
	if (lt == NULL && rt == NULL) {
		/* unset/NULL ranges are equal */
		return true;
	}
	if (lt != rt) {
		return false;
	}
	/* ignore .is_subnet */
	return (address_eq(&l->start, &r->start) &&
		address_eq(&l->end, &r->end));
}
