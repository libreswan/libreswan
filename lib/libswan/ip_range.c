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
#include "libreswan/passert.h"

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
 * ttorange - convert text "addr1-addr2" to address_start address_end
 */
err_t ttorange(const char *src,
	       size_t srclen /* 0 means "apply strlen" */,
	       int af /* AF_INET only.  AF_INET6 not supported yet. */,
	       ip_range *dst,
	       bool non_zero /* is 0.0.0.0 allowed? */)
{
	const char *dash;
	const char *high;
	size_t hlen;
	const char *oops;

	ip_address addr_start_tmp;
	ip_address addr_end_tmp;

	/* this should be a passert */
	if (af != AF_INET)
		return "ttorange only supports IPv4 addresses";

	if (srclen == 0)
		srclen = strlen(src);

	dash = memchr(src, '-', srclen);
	if (dash == NULL)
		return "missing '-' in ip address range";

	high = dash + 1;
	hlen = srclen - (high - src);
	oops = ttoaddr_num(src, dash - src, af, &addr_start_tmp);
	if (oops != NULL)
		return oops;

	/*
	 * If we allowed af == AF_UNSPEC,
	 * set it to addrtypeof(&addr_start_tmp)
	 */

	/* extract end ip address */
	oops = ttoaddr_num(high, hlen, af, &addr_end_tmp);
	if (oops != NULL)
		return oops;

	if (ntohl(addr_end_tmp.u.v4.sin_addr.s_addr) <
		ntohl(addr_start_tmp.u.v4.sin_addr.s_addr))
		return "start of range must not be greater than end";

	if (non_zero) {
		uint32_t addr  = ntohl(addr_start_tmp.u.v4.sin_addr.s_addr);

		if (addr == 0)
			return "'0.0.0.0' not allowed in range";
	}

	/* We have validated the range. Now put bounds in dst. */
	dst->start = addr_start_tmp;
	dst->end = addr_end_tmp;
	return NULL;
}

void jam_range(jambuf_t *buf, const ip_range *range)
{
	jam_address(buf, &range->start);
	jam(buf, "-");
	jam_address(buf, &range->end);
}

const char *str_range(const ip_range *range, range_buf *out)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(out->buf);
	jam_range(&buf, range);
	return out->buf;
}
