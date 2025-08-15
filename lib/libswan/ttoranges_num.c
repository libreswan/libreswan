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

#define ip_token ip_range
#define ip_tokens ip_ranges

diag_t ttoranges_num(shunk_t input, const char *delims,
		     const struct ip_info *input_afi,
		     ip_ranges *output)
{
	zero(output);

	if (input.ptr == NULL) {
		return NULL;
	}

	ldbg(&global_logger, "%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

	struct shunks *tokens = ttoshunks(input, delims, KEEP_EMPTY_SHUNKS); /* must free */
	if (tokens->kept_empty_shunks) {
		pfree(tokens);
		return diag("empty field");
	}

	if (tokens->len == 0) {
		pfree(tokens);
		return NULL;
	}

	ldbg(&global_logger, "%s() nr tokens %u", __func__, tokens->len);
	output->list = alloc_things(ip_token, tokens->len, "selectors");
	output->len = 0;

	ITEMS_FOR_EACH(token, tokens) {
		passert(token->len > 0);
		ip_token tmp_token;
		err_t e = ttorange_num(*token, input_afi, &tmp_token);
		/* validate during first pass */
		if (e != NULL) {
			diag_t d = diag(PRI_SHUNK" invalid, %s",
					pri_shunk(*token), e);
			pfree(tokens);
			pfree(output->list);
			zero(output);
			return d;
		}
		output->list[output->len++] = tmp_token;
	}

	pfree(tokens);
	return NULL;
}
