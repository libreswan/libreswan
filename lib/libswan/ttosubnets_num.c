/* cloning an subnet list, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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

#include <stdarg.h>

#include "lswalloc.h"
#include "passert.h"
#include "ip_subnet.h"
#include "ip_info.h"

static err_t parse_subnets(shunk_t token, const struct ip_info *afi,
			   void **ptr, unsigned len)
{
	ip_subnet tmp_token;
	ip_address nonzero_host;
	err_t e = ttosubnet_num(token, afi, &tmp_token, &nonzero_host);
	if (e != NULL) {
		return e;
	}

	if (nonzero_host.ip.is_set) {
		return "subnet has non-zero address identifier";
	}

	/* save it */
	ip_subnet *subnets = (*ptr);
	realloc_things(subnets, len, len+1, "subnets");
	subnets[len] = tmp_token;
	(*ptr) = subnets;
	return NULL;
}

diag_t ttosubnets_num(shunk_t input, const struct ip_info *afi, ip_subnets *output)
{
	zero(output);
	void *ptr = NULL;
	unsigned len = 0;
	diag_t d = ttoips_num(input, afi, &ptr, &len, parse_subnets);
	if (d != NULL) {
		return d;
	}

	output->list = ptr;
	output->len = len;
	return NULL;
}
