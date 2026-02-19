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
 * and more minor utilities for prefix length calculations for IKEv2
 */

#include "jambuf.h"
#include "ip_range.h"
#include "ip_info.h"
#include "passert.h"
#include "lswlog.h"		/* for pexpect() */

/*
 * ttorange_num()
 *
 * Convert "addr1-addr2" or subnet/prefix[/subprefix] to an address range.
 */
diag_t ttorange_num(shunk_t input, const struct ip_info *afi, ip_range *dst)
{
	*dst = unset_range;
	err_t err;
	diag_t d;

	shunk_t cursor = input;

	/* START or START"/"PREFIX... or START"-"END */
	char sep = '\0';
	shunk_t start_token = shunk_token(&cursor, &sep, "/-");

	/* convert start address */
	ip_address start_address;
	d = ttoaddress_num(start_token, afi/*possibly NULL*/, &start_address);
	if (d != NULL) {
		return d;
	}

	/* get real AFI */
	afi = address_info(start_address);
	passert(afi != NULL);

	switch (sep) {
	case '\0':
	{
		/* single address */
		*dst = range_from_raw(HERE, afi,
				      start_address.bytes,
				      start_address.bytes);
		return NULL;
	}
	case '/':
	{
		/* START/PREFIX[/SUBPREFIX] */
		uintmax_t prefix = afi->mask_cnt; /* TBD */
		err = shunk_to_uintmax(cursor, NULL, 0, &prefix);
		if (err != NULL) {
			return diag("%s", err);
		}

		if (prefix > afi->mask_cnt) {
			return diag("too large");
		}

		/* XXX: should this reject bad addresses */
		*dst = range_from_raw(HERE, afi,
				      ip_bytes_blit(afi, start_address.bytes,
						    &keep_routing_prefix,
						    &clear_host_identifier,
						    prefix),
				      ip_bytes_blit(afi, start_address.bytes,
						    &keep_routing_prefix,
						    &set_host_identifier,
						    prefix));
		return NULL;
	}
	case '-':
	{
		/* START-END */
		ip_address end_address;
		diag_t d = ttoaddress_num(cursor, afi, &end_address);
		if (d != NULL) {
			/* includes IPv4 vs IPv6 */
			return d;
		}
		passert(afi == address_info(end_address));
		if (ip_bytes_cmp(start_address.ip.version, start_address.bytes,
				 end_address.ip.version, end_address.bytes) > 0) {
			return diag("start of range is greater than end");
		}
		*dst = range_from_raw(HERE, afi,
				      start_address.bytes,
				      end_address.bytes);
		return NULL;
	}
	default:
		/* SEP is invalid, but being more specific means diag_t */
		return diag("expecting '-' or '/'");
	}
}
