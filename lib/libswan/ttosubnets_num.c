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
#include "lswlog.h"

diag_t ttosubnets_num(shunk_t input,
		      const struct ip_info *afi,
		      ip_subnets **output)
{
	(*output) = NULL;

	ldbg(&global_logger, "%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

	struct shunks *tokens = ttoshunks(input, ", ", EAT_EMPTY_SHUNKS); /* must free */
	ldbg(&global_logger, "%s() nr tokens %u", __func__, tokens->len);
	(*output) = table_alloc(ip_subnets, tokens->len);

	unsigned nr = 0;
	TABLE_FOR_EACH(token, tokens) {
		ip_subnet tmp;
		ip_address nonzero_host;
		diag_t d = ttosubnet_num(*token, afi, &tmp, &nonzero_host);
		if (d != NULL) {
			d = diag_diag(&d, PRI_SHUNK" invalid, ", pri_shunk(*token));
			pfree(tokens);
			pfreeany(*output);
			return d;
		}

		if (nonzero_host.ip.is_set) {
			pfree(tokens);
			pfreeany(*output);
			return diag("subnet has non-zero address identifier");
		}

		passert(nr < (*output)->len);
		(*output)->table[nr++] = tmp;
	}
	passert(nr == (*output)->len);

	pfree(tokens);
	return NULL;
}
