/* ip traffic selector, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#ifndef IP_SELECTOR_H
#define IP_SELECTOR_H

#include "jambuf.h"

/*
 * IKEv2 style traffic selectors can describe.
 *
 *    LO_ADDRESS..HI_ADDRESS : LO_PORT..HI_PORT
 *
 * However, this is currently implemented using a subnet which,
 * bizarely, can describe:
 *
 *    NETWORK_PREFIX | 0 / MASK : PORT
 *
 * where PORT==0 imples 0..65535, and (presumably) port can only be
 * non-zero when the NETWORK_PREFIX/MASK is for a single address.
 */

/*
 * Define SELECTOR_TYPE to enable a proper selector structure; expect
 * everything to break.
 */

#ifdef SELECTOR_TYPE

struct {
	/*
	 * XXX: Data structure sufficient for IKEv2?
	 */
	const struct ip_protocol * protocol;
	ip_address lo_address, hi_address;
	uint16_t lo_hport, hi_hport;
} ip_selector;

#else

#include "ip_subnet.h"
typedef ip_subnet ip_selector;

#endif

typedef struct {
	char buf[sizeof(address_buf) + 4/*"/NNN"*/ + 6/*:65535*/];
} selector_buf;
const char *str_selector(const ip_selector *selector, selector_buf *out);
void jam_selector(jambuf_t *buf, const ip_selector *selector);

#endif
