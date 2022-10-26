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

err_t ttoselector_num(shunk_t input,
		      const struct ip_info *afi, /* could be NULL */
		      ip_selector *dst)
{
	err_t oops;

	/*
	 * <address> / ...
	 */

	char address_term;
	shunk_t address_token = shunk_token(&input, &address_term, "/");
	/* fprintf(stderr, "address="PRI_SHUNK"\n", pri_shunk(address_token)); */

	ip_address address;
	oops = ttoaddress_num(address_token, afi/*possibly NULL*/, &address);
	if (oops != NULL) {
		return oops;
	}

	if (afi == NULL) {
		afi = address_type(&address);
	}
	if (!pexpect(afi != NULL)) {
		return "confused address family";
	}

	/*
	 * ... <prefix-bits> : ...
	 */

	char prefix_bits_term;
	shunk_t prefix_bits_token = shunk_token(&input, &prefix_bits_term, ":");
	/* fprintf(stderr, "prefix-bits="PRI_SHUNK"\n", pri_shunk(prefix_bits_token)); */

	uintmax_t prefix_bits = afi->mask_cnt;
	if (prefix_bits_token.len > 0) {
		oops = shunk_to_uintmax(prefix_bits_token, NULL, 0, &prefix_bits);
		if (oops != NULL) {
			return oops;
		}
		if (prefix_bits > afi->mask_cnt) {
			return "too large";
		}
	} else if (prefix_bits_token.ptr != NULL) {
		/* found but empty */
		pexpect(prefix_bits_token.len == 0);
		return "missing prefix bit size";
	}

	struct ip_bytes host = ip_bytes_from_blit(afi, address.bytes,
						  /*routing-prefix*/&clear_bits,
						  /*host-identifier*/&keep_bits,
						  prefix_bits);
	if (!thingeq(host, unset_ip_bytes)) {
		return "host-identifier must be zero";
	}

	/*
	 * ... <protocol> / ...
	 */

	char protocol_term;
	shunk_t protocol_token = shunk_token(&input, &protocol_term, "/");
	/* fprintf(stderr, "protocol="PRI_SHUNK"\n", pri_shunk(protocol_token)); */

	const ip_protocol *protocol = &ip_protocol_all; /*0*/
	if (protocol_token.len > 0) {
		if (protocol_term != '/') {
			return "protocol must be followed by '/'";
		}
		protocol = protocol_by_shunk(protocol_token);
		if (protocol == NULL) {
			return "unknown protocol";
		}
	} else if (protocol_token.ptr != NULL) {
		/* found but empty */
		pexpect(protocol_token.len == 0);
		return "missing protocol/port following ':'";
	}

	/*
	 * ... <port>
	 */

	shunk_t port_token = input;
	/* fprintf(stderr, "port="PRI_SHUNK"\n", pri_shunk(port_token)); */

	ip_port port = unset_port;
	if (port_token.len > 0) {
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
	} else if (port_token.ptr != NULL) {
		/* found but empty */
		pexpect(port_token.len == 0);
		return "missing port following protocol/";
	}

	ip_subnet subnet = subnet_from_address_prefix_bits(address, prefix_bits);
	*dst = selector_from_subnet_protocol_port(subnet, protocol, port);
	return NULL;
}
