/* cloning an range list, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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
#include "lswlog.h"		/* for ldbg() */
#include "ip_range.h"
#include "ip_info.h"

diag_t ttoranges_num(shunk_t input,
		     const struct ip_info *input_afi,
		     ip_ranges **output)
{
	(*output) = NULL;

	ldbg(&global_logger, "%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

	struct shunks *tokens = ttoshunks(input, ", ", KEEP_EMPTY_SHUNKS); /* must free */
	if (tokens->kept_empty_shunks) {
		pfree(tokens);
		return diag("empty field");
	}

	ldbg(&global_logger, "%s() nr tokens %u", __func__, tokens->len);
	(*output) = table_alloc(ip_ranges, tokens->len);

	unsigned nr = 0;
	TABLE_FOR_EACH(token, tokens) {
		ip_range tmp;
		diag_t d = ttorange_num(*token, input_afi, &tmp);
		if (d != NULL) {
			d = diag_diag(&d, PRI_SHUNK" invalid, ", pri_shunk(*token));
			pfree(tokens);
			pfreeany(*output);
			return d;
		}

		passert(nr < (*output)->len);
		(*output)->table[nr++] = tmp;
	}
	passert(nr == (*output)->len);

	pfree(tokens);
	return NULL;
}
