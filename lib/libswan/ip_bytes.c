/* low-level ip_byte ugliness
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2018, 2021  Andrew Cagney.
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include "lswlog.h"		/* for pexpect() */
#include "ip_bytes.h"
#include "ip_info.h"

const struct ip_bytes unset_ip_bytes;

/*
 * mashup() notes:
 *
 * - mashup operates on network-order IP address bytes.
 */

struct ip_routing_prefix_blit {
	uint8_t and;	/* first operation */
	uint8_t or;	/* second operation */
};

struct ip_host_identifier_blit {
	uint8_t and;	/* first operation */
	uint8_t or;	/* second operation */
};

const struct ip_routing_prefix_blit clear_routing_prefix = { .and = 0x00, .or = 0x00, };
const struct ip_routing_prefix_blit set_routing_prefix = { .and = 0x00/*don't care*/, .or = 0xff, };
const struct ip_routing_prefix_blit keep_routing_prefix = { .and = 0xff, .or = 0x00, };

const struct ip_host_identifier_blit clear_host_identifier = { .and = 0x00, .or = 0x00, };
const struct ip_host_identifier_blit set_host_identifier = { .and = 0x00/*don't care*/, .or = 0xff, };
const struct ip_host_identifier_blit keep_host_identifier = { .and = 0xff, .or = 0x00, };

struct ip_bytes ip_bytes_blit(const struct ip_info *afi,
			      const struct ip_bytes in,
			      const struct ip_routing_prefix_blit *routing_prefix,
			      const struct ip_host_identifier_blit *host_identifier,
			      unsigned prefix_len)
{
	if (!pexpect(prefix_len <= afi->mask_cnt)) {
		return unset_ip_bytes;	/* "can't happen" */
	}

	struct ip_bytes out = in;
	uint8_t *p = out.byte;

	/*
	 * Split the byte array into:
	 *
	 *    leading | xbyte:xbit | trailing
	 *
	 * where LEADING only contains ROUTING_PREFIX bits, TRAILING
	 * only contains HOST_ID bits, and XBYTE is the cross over and
	 * contains the first HOST_ID bit at big (aka PPC) endian
	 * position XBIT.
	 */
	size_t xbyte = prefix_len / BITS_IN_BYTE;
	unsigned xbit = prefix_len % BITS_IN_BYTE;

	/* leading bytes only contain the ROUTING_PREFIX */
	for (unsigned b = 0; b < xbyte; b++) {
		p[b] &= routing_prefix->and;
		p[b] |= routing_prefix->or;
	}

	/*
	 * Handle the cross over byte:
	 *
	 *    & {ROUTING_PREFIX,HOST_ID}->and | {ROUTING_PREFIX,HOST_ID}->or
	 *
	 * the hmask's shift is a little counter intuitive - it clears
	 * the first (most significant) XBITs.
	 *
	 * tricky logic:
	 * - if xbyte == raw.len we must not access p[xbyte]
	 */
	if (xbyte < afi->ip_size) {
		uint8_t hmask = 0xFF >> xbit; /* clear MSBs */
		uint8_t pmask = ~hmask; /* set MSBs */
		p[xbyte] &= (routing_prefix->and & pmask) | (host_identifier->and & hmask);
		p[xbyte] |= (routing_prefix->or & pmask) | (host_identifier->or & hmask);
	}

	/* trailing bytes only contain the HOST_ID */
	for (unsigned b = xbyte + 1; b < afi->ip_size; b++) {
		p[b] &= host_identifier->and;
		p[b] |= host_identifier->or;
	}

	return out;
}

/*
 * Calculate l-r using unsigned arithmetic
 */

struct ip_bytes ip_bytes_sub(const struct ip_info *afi,
			     const struct ip_bytes l,
			     const struct ip_bytes r)
{
	struct ip_bytes diff = unset_ip_bytes;

	/* subtract: diff = hi - lo */
	unsigned borrow = 0;
	for (int j = afi->ip_size - 1; j >= 0; j--) {
		unsigned val = l.byte[j] - r.byte[j] - borrow;
		diff.byte[j] = val;
		borrow = (val >> 8) & 1u;
	}

	/* ??? what should happen if l > r?  borrow will be 1. */
	pexpect(borrow == 0);

	return diff;
}

int ip_bytes_first_set_bit(const struct ip_info *afi, const struct ip_bytes bytes)
{
	for (unsigned i = 0; i < afi->ip_size; i++) {
		uint8_t byte = bytes.byte[i];
		if (byte != 0) {
			/* find leftmost set bit in non-zero B */
			unsigned bo = 0;
			for (unsigned bit = 0x80u; (bit & byte) == 0; bit >>=1) {
				bo++;
			}
			return i * 8 + bo;
		}
	}
	return afi->ip_size * 8;
}

int ip_bytes_prefix_len(const struct ip_info *afi,
			const struct ip_bytes lo,
			const struct ip_bytes hi)
{
	/*
	 * Determine the prefix_bits (the CIDR network part) by
	 * matching leading bits of FROM and TO.  Trailing bits
	 * (subnet address) must be either all 0 (from) or 1 (to).
	 */

	/* look for a mismatching byte */
	unsigned prefix_bits = 0;
	unsigned i;
	for (i = 0; i < afi->ip_size && lo.byte[i] == hi.byte[i]; i++) {
		prefix_bits += 8;
	}

	/* mid-byte boundary? */
	if (i < afi->ip_size && (lo.byte[i] != 0x00 || hi.byte[i] != 0xff)) {
		/*
		 * clear each LB bit, and set each HB as it is matched
		 * so that, at the end FB==0x00 and TB=0xFF
		 */
		uint8_t lb = lo.byte[i];
		uint8_t hb = hi.byte[i];
		uint8_t bit = 0x80;
		while ((lb & bit) == (hb & bit)) {
			lb &= ~bit;
			hb |= bit;
			bit >>= 1;
			prefix_bits++;
		}
		if (lb != 0x00 || hb != 0xff) {
			return -1;
		}
		i++; /* skip boundary */
	}
	/* check trailing bytes are correct */
	for (; i < afi->ip_size; i++) {
		if (lo.byte[i] != 0x00 || hi.byte[i] != 0xff) {
			return -1;
		}
	}
	return prefix_bits;
}

int ip_bytes_host_len(const struct ip_info *afi,
		      const struct ip_bytes lo,
		      const struct ip_bytes hi)
{
	int prefix_len = ip_bytes_prefix_len(afi, lo, hi);
	if (prefix_len < 0) {
		return -1;
	}

	return afi->mask_cnt - prefix_len;
}

/*
 * bytes_cmp - compare two raw addresses
 */

int ip_bytes_cmp(enum ip_version l_version, const struct ip_bytes l_bytes,
		 enum ip_version r_version, const struct ip_bytes r_bytes)
{
	int cmp = l_version - r_version;
	if (cmp != 0) {
		return cmp;
	}

	/* just compare everything */
	return memcmp(l_bytes.byte, r_bytes.byte, sizeof(l_bytes));
}

bool ip_bytes_is_zero(const struct ip_bytes *bytes)
{
	return thingeq(*bytes, unset_ip_bytes);
}

size_t jam_ip_bytes_range(struct jambuf *buf,
			  const struct ip_info *afi,
			  const struct ip_bytes lo,
			  const struct ip_bytes hi)
{
	int prefix_len = ip_bytes_prefix_len(afi, lo, hi);
	size_t s = 0;
	if (prefix_len >= 0) {
		/* always <address>/<length> */
		s += afi->jam.address(buf, afi, &lo);
		s += jam(buf, "/%u", prefix_len);
	} else {
		s += afi->jam.address(buf, afi, &lo);
		s += jam_string(buf, "-");
		s += afi->jam.address(buf, afi, &hi);
	}
	return s;
}
