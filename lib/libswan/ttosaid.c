/*
 * convert from text form of SA ID to binary
 *
 * Copyright (C) 2000, 2001  Henry Spencer.
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

#include <string.h>
#include <stdio.h>

#include "ip_said.h"
#include "ip_info.h"

static struct magic {
	char *name;
	char *really;
} magic[] = {
	{ PASSTHROUGHNAME, PASSTHROUGH4IS },
	{ PASSTHROUGH4NAME, PASSTHROUGH4IS },
	{ PASSTHROUGH6NAME, PASSTHROUGH6IS },
	{ "%pass", "int256@0.0.0.0" },
	{ "%drop", "int257@0.0.0.0" },
	{ "%reject", "int258@0.0.0.0" },
	{ "%hold", "int259@0.0.0.0" },
	{ "%trap", "int260@0.0.0.0" },
	{ "%ignore", "int261@0.0.0.0" },
	{ "%trapsubnet", "int262@0.0.0.0" },
	{ NULL, NULL }
};

/*
 * ttosa - convert text "ah507@10.0.0.1" to SA identifier
 *
 * NULL for success, else string literal
 */

diag_t ttosaid(shunk_t src, ip_said *said)
{
	*said = unset_said;
	err_t oops;

	if (src.len == 0) {
		return diag("empty string");
	}

#       define  MINLEN  strlen("ah0@0"/*is as short as it can get */)
	if (src.len < MINLEN) {
		return diag("string too short to be SA identifier");
	}

	/*
	 * Try to turn %... into its equivalent.
	 */
	shunk_t input;
	if (hunk_char(src, 0) == '%') {
		struct magic *mp;
		for (mp = magic; mp->name != NULL; mp++) {
			if (hunk_streq(src, mp->name)) {
				break;
			}
		}
		if (mp->name == NULL) {
			return diag("keyword "PRI_SHUNK" unknown", pri_shunk(src));
		}
		/* now parse the real string */
		input = shunk1(mp->really);
	} else {
		input = src;
	}

	const struct ip_protocol *protocol = protocol_by_caseeat_prefix(&input);
	if (protocol == NULL) {
		return diag("SA specifier "PRI_SHUNK" lacks valid protocol prefix", pri_shunk(src));
	}

	if (input.len == 0) {
		return diag("no SPI in SA specifier "PRI_SHUNK, pri_shunk(src));
	}

	unsigned base;
	const struct ip_info *afi;
	if (shunk_strcaseeat(&input, ".")) {
		afi = &ipv4_info;
		base = 16;
	} else if (shunk_strcaseeat(&input, ":")) {
		afi = &ipv6_info;
		base = 16;
	} else {
		afi = NULL;	/* not known yet */
		base = 0;
	}
	if (input.len == 0) {
		return diag("no SPI following protocol in SA specifier "PRI_SHUNK, pri_shunk(src));
	}

	uintmax_t hspi;
	shunk_t spis = input;
	oops = shunk_to_uintmax(input, &input, base, &hspi, 0);
	if (oops != NULL) {
		return diag("SPI "PRI_SHUNK" invalid: %s", pri_shunk(spis), oops);
	}

	if (!shunk_strcaseeat(&input, "@")) {
		return diag("missing @ in SA specifier");
	}

	ip_address dst;
	shunk_t dsts = input;
	oops = ttoaddress_num(input, afi, &dst);
	if (oops != NULL) {
		return diag("address "PRI_SHUNK" invalid: %s", pri_shunk(dsts), oops);
	}

	*said = said_from_address_protocol_spi(dst, protocol, htonl(hspi));

	return NULL;
}
