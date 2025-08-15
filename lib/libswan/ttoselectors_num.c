/* cloning an selector list, for libreswan
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
#include "ip_selector.h"
#include "ip_info.h"

#define ip_token ip_selector
#define ip_tokens ip_selectors

diag_t ttoselectors_num(shunk_t input, const char *delims,
			const struct ip_info *input_afi,
			ip_tokens *output,
			ip_address *nonzero_host)
{
	zero(output);
	*nonzero_host = unset_address;

	if (input.ptr == NULL) {
		return NULL;
	}

	ldbg(&global_logger, "%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

	/*
	 * Two passes:
	 *
	 *   Pass 1: determine the number of tokens.
	 *   Pass 1.5: allocate list pointers; zero counters
	 *   Pass 2: save the values in separate IPv[46] lists.
	 */

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
	output->len = tokens->len;

	unsigned nr = 0;
	ITEMS_FOR_EACH(token, tokens) {
		ip_address tmp_nonzero;
		err_t e = ttoselector_num(*token, input_afi,
					  &output->list[nr++],
					  &tmp_nonzero);
		/* validate during first pass */
		if (e != NULL) {
			diag_t d = diag(PRI_SHUNK" invalid, %s",
					pri_shunk(*token), e);
			pfree(tokens);
			pfree(output->list);
			zero(output);
			return d;
		}
		if (tmp_nonzero.ip.is_set && !nonzero_host->ip.is_set) {
			*nonzero_host = tmp_nonzero; /* save first */
		}
	}

	passert(output->len == tokens->len);
	pfree(tokens);
	return NULL;
}
