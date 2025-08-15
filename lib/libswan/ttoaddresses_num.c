/* cloning an address list, for libreswan
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
#include "ip_address.h"
#include "ip_info.h"

diag_t ttoaddresses_num(shunk_t input, const char *delims,
			const struct ip_info *input_afi,
			ip_addresses *output)
{
	zero(output);

	if (input.ptr == NULL) {
		return NULL;
	}

	ldbg(&global_logger, "%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

	struct shunks *tokens = ttoshunks(input, delims, EAT_EMPTY_SHUNKS); /* must free */

	/* ignore empty!?! */

	if (tokens->len == 0) {
		pfree(tokens);
		return NULL;
	}

	ldbg(&global_logger, "%s() nr tokens %u", __func__, tokens->len);
	output->list = alloc_things(ip_address, tokens->len, "addresses");

	ITEMS_FOR_EACH(token, tokens) {
		err_t e = ttoaddress_num(*token, input_afi,
					 &output->list[output->len]);
		if (e != NULL) {
			diag_t d = diag(PRI_SHUNK" invalid, %s",
					pri_shunk(*token), e);
			pfree(tokens);
			pfree(output->list);
			zero(output);
			return d;
		}
		output->len++;
	}

	passert(output->len == tokens->len);
	pfree(tokens);
	return NULL;
}
