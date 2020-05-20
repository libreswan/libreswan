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
	bool ss = address_is_specified(start);
	bool es = address_is_specified(end);
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

static err_t extract_ends(const char *src, const struct ip_info *afi, ip_range *dst)
{
	const char *dash;
	const char *high;
	size_t hlen;
	const char *oops;
	size_t srclen = strlen(src);

	dash = memchr(src, '-', srclen);
	if (dash == NULL)
		return "not ipv4 address range with '-' or ipv6 subnet";

	high = dash + 1;
	hlen = srclen - (high - src);

	/* extract start ip address */
	oops = ttoaddr_num(src, dash - src, afi->af, &dst->start);
	if (oops != NULL)
		return oops;

	/* extract end ip address */
	oops = ttoaddr_num(high, hlen, afi->af, &dst->end);
	if (oops != NULL)
		return oops;

	return NULL;
}

/*
 * ttorange - convert text v4 "addr1-addr2" to address_start address_end
 *            v6 allows "subnet/mask" to address_start address_end
 */
err_t ttorange(const char *src, const struct ip_info *afi, ip_range *dst)
{
	err_t er = NULL;

	zero(dst);
	ip_range tmp = *dst; /* clear it */

	ip_subnet v6_subnet;
	er = ttosubnet(src, 0, AF_INET6, '6', &v6_subnet);
	if (er == NULL) {
		if (v6_subnet.addr.hport != 0)
			return "port must be zero for IPv6 addresspool";
		tmp = range_from_subnet(&v6_subnet);
		tmp.is_subnet = true;
		afi = &ipv6_info;
	} else  {
		if (afi == NULL) {
			afi = &ipv4_info;
			if (extract_ends(src, afi, &tmp) != NULL) {
				afi = &ipv6_info;
				er = extract_ends(src, afi, &tmp);
				if (er != NULL)
					return er; /* v4 error is ignored */

			}
		} else {
			er = extract_ends(src, afi, &tmp);
			if (er != NULL)
				return er;
		}
	}

	if (addrcmp(&tmp.start, &tmp.end) > 0) {
		return "start of range must not be greater than end";
	}

	if (address_is_any(&tmp.start) ||
	    address_is_any(&tmp.end)) {
		return "'0.0.0.0 or ::0' not allowed in range";
	}

	/* We have validated the range. Now put bounds in dst. */
	*dst = tmp;
	return NULL;
}

void jam_range(jambuf_t *buf, const ip_range *range)
{
	jam_address(buf, &range->start);
	if (range_type(range) == &ipv6_info && range->is_subnet) {
		ip_subnet tmp_subnet;
		rangetosubnet(&range->start, &range->end, &tmp_subnet);
		jam(buf, "/%u", tmp_subnet.maskbits);
	} else {
		jam(buf, "-");
		jam_address(buf, &range->end);
	}
}

const char *str_range(const ip_range *range, range_buf *out)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(out->buf);
	jam_range(&buf, range);
	return out->buf;
}

ip_range range_from_subnet(const ip_subnet *subnet)
{
	ip_range r = {
		/* SHHHHH */
		.start = address_blit(endpoint_address(&subnet->addr),
				      &keep_bits, &clear_bits,
				      subnet->maskbits),
		.end = address_blit(endpoint_address(&subnet->addr),
				    &keep_bits, &set_bits,
				    subnet->maskbits),
	};
	return r;
}

const struct ip_info *range_type(const ip_range *range)
{
	const struct ip_info *start = address_type(&range->start);
	const struct ip_info *end = address_type(&range->end);
	if (!pexpect(start == end)) {
		return NULL;
	}
	return start;
}

bool range_is_set(const ip_range *r)
{
	return range_type(r) != NULL;
}

bool range_is_specified(const ip_range *r)
{
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
