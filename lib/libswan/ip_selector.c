/* ip selector, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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

#include "lswlog.h"

#include "ip_selector.h"
#include "ip_info.h"

const ip_selector unset_selector;

void jam_selector(jambuf_t *buf, const ip_subnet *subnet)
{
	jam_address(buf, &subnet->addr); /* sensitive? */
	jam(buf, "/%u", subnet->maskbits);
	int port = subnet_hport(subnet);
	if (port >= 0) {
		jam(buf, ":%d", port);
	}
}

const char *str_selector(const ip_selector *selector, selector_buf *out)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(out->buf);
	jam_selector(&buf, selector);
	return out->buf;
}

ip_selector selector_from_ipproto_address_hport(unsigned ipproto,
						const ip_address *address,
						unsigned hport)
{
#ifdef SELECTOR_TYPE
#else
	const struct ip_info *afi = address_type(address);
	if (!pexpect(afi != NULL)) {
		return unset_selector;
	}
	ip_selector selector = afi->no_addresses; /* ::/128 or 0.0.0.0/32 */
	selector.addr = *address;
	selector.addr.ipproto = ipproto;
	selector.addr.hport = hport;
#endif
	return selector;
}
