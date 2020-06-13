/* low-level address byte manipulation, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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

/*
 * mashup() notes:
 * - mashup operates on network-order IP addresses
 */

struct ip_blit {
	uint8_t and;
	uint8_t or;
};

const struct ip_blit clear_bits = { .and = 0x00, .or = 0x00, };
const struct ip_blit set_bits = { .and = 0x00/*don't care*/, .or = 0xff, };
const struct ip_blit keep_bits = { .and = 0xff, .or = 0x00, };

ip_bytes bytes_blit(ip_bytes bytes, size_t len,
		    const struct ip_blit *routing_prefix,
		    const struct ip_blit *host_id,
		    unsigned nr_mask_bits)
{
	if (!pexpect(len <= sizeof(bytes.byte/*array*/))) {
		return unset_bytes;
	}
	if (!pexpect(nr_mask_bits <= len * 8)) {
		return unset_bytes;	/* "can't happen" */
	}

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
	size_t xbyte = nr_mask_bits / BITS_PER_BYTE;
	unsigned xbit = nr_mask_bits % BITS_PER_BYTE;

	/* leading bytes only contain the ROUTING_PREFIX */
	for (unsigned b = 0; b < xbyte; b++) {
		bytes.byte[b] &= routing_prefix->and;
		bytes.byte[b] |= routing_prefix->or;
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
	 * - if xbyte == raw.len we must not access bytes.byte[xbyte]
	 */
	if (xbyte < len) {
		uint8_t hmask = 0xFF >> xbit; /* clear MSBs */
		uint8_t pmask = ~hmask; /* set MSBs */
		bytes.byte[xbyte] &= (routing_prefix->and & pmask) | (host_id->and & hmask);
		bytes.byte[xbyte] |= (routing_prefix->or & pmask) | (host_id->or & hmask);
	}

	/* trailing bytes only contain the HOST_ID */
	for (unsigned b = xbyte + 1; b < len; b++) {
		bytes.byte[b] &= host_id->and;
		bytes.byte[b] |= host_id->or;
	}

	return bytes;
}
