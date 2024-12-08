/* ip selector, for libreswan
 *
 * Copyright (C) 2020  Andrew Cagney
 * Copyright (C) 2000  Henry Spencer.
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

/*
 * Parse the selector:
 *
 *  <address>
 *  <address>/<prefix-bits>
 *  <address>/<prefix-bits>:<protocol>/ <- NOTE
 *  <address>/<prefix-bits>:<protocol>/<port>
 *
 * new syntax required for:
 *
 *  <address>-<address>:<protocol>/<port>-<port>
 *
 */

err_t ttoselector_num(shunk_t cursor,
		      const struct ip_info *afi, /* could be NULL */
		      ip_selector *dst, ip_address *nonzero_host)
{
	*dst = unset_selector;
	*nonzero_host = unset_address;
	err_t oops;

	/*
	 * <address> [ / <prefix-length> [ / <protocol> [ / <port> ] ] ]
	 */

	char prefix_length_separator;
	shunk_t address_token = shunk_token(&cursor, &prefix_length_separator, "/");
#if 0
	fprintf(stderr, "address="PRI_SHUNK"\n", pri_shunk(address_token));
#endif

	ip_address address;
	oops = ttoaddress_num(address_token, afi/*possibly NULL*/, &address);
	if (oops != NULL) {
		return oops;
	}

	if (afi == NULL) {
		afi = address_info(address);
	}
	passert(afi != NULL);

	/*
	 * <prefix-length> [ / <protocol> [ / <port> ] ]
	 *
	 * XXX: also allow :protocol/port for now.
	 */

	uintmax_t prefix_length;
	shunk_t prefix_length_token = shunk_token(&cursor, NULL, "/:");
#if 0
	fprintf(stderr, "prefix-bits="PRI_SHUNK"\n", pri_shunk(prefix_length_token));
#endif
	if (prefix_length_token.len > 0) {
		/* "1.2.3.4/123" or "1.2.3.4/123/..." */
		uintmax_t tmp = 0;
		oops = shunk_to_uintmax(prefix_length_token, NULL, 0, &tmp);
		if (oops != NULL) {
			return oops;
		}
		if (tmp > afi->mask_cnt) {
			return "too large";
		}
		prefix_length = tmp;
	} else {
		prefix_length = afi->mask_cnt;
	}

	/*
	 * <protocol> / <port>
	 */

	const struct ip_protocol *protocol;
	shunk_t protocol_token = shunk_token(&cursor, NULL, "/");
#if 0
	fprintf(stderr, "protocol="PRI_SHUNK"\n", pri_shunk(protocol_token));
#endif
	if (protocol_token.len > 0) {
		/* "1.2.3.4//udp" or "1.2.3.4//udp/" */
		protocol = protocol_from_shunk(protocol_token);
		if (protocol == NULL) {
			return "unknown protocol";
		}
	} else {
		protocol = &ip_protocol_all;
	}

	/*
	 * ... <port>
	 */

	ip_port port;
	shunk_t port_token = cursor;
#if 0
	fprintf(stderr, "port="PRI_SHUNK"\n", pri_shunk(port_token));
#endif
	if (port_token.len > 0) {
		/* 1.2.3.4/32/udp/10 */
		uintmax_t hport;
		err_t oops = shunk_to_uintmax(port_token, NULL, 0, &hport);
		if (oops != NULL) {
			return oops;
		}
		if (hport > 65535) {
			return "too large";
		}
		if (protocol == &ip_protocol_all && hport != 0) {
			return "a non-zero port requires a valid protocol";
		}
		port = ip_hport(hport);
	} else {
		port = unset_port;
	}

	/*
	 * Now form the routing prefix.  If it has less bits than the
	 * address, zero them but return original address.  Caller can
	 * use that to log message when so desired.
	 */

	struct ip_bytes routing_prefix = ip_bytes_blit(afi, address.bytes,
						       &keep_routing_prefix,
						       &clear_host_identifier,
						       prefix_length);
	if (ip_bytes_cmp(afi->ip_version, routing_prefix,
			 afi->ip_version, address.bytes) != 0) {
		*nonzero_host = address;
	}

	/* check host-part is zero */

	*dst = selector_from_raw(HERE, afi,
				 routing_prefix, prefix_length,
				 protocol, port);
	return NULL;
}
