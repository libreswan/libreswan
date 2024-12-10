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
#include "lswlog.h"		/* for dbg() */
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

	dbg("%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

	/*
	 * Two passes:
	 *
	 *   Pass 1: determine the number of tokens.
	 *   Pass 1.5: allocate list pointers; zero counters
	 *   Pass 2: save the values.
	 */

	struct shunks *tokens = shunks(input, delims, KEEP_EMPTY_SHUNKS, HERE); /* must free */
	if (tokens->kept_empty_shunks) {
		pfree(tokens);
		return diag("empty field");
	}

	dbg("%s() nr tokens %u", __func__, tokens->len);
	output->list = alloc_things(ip_token, tokens->len, "selectors");
	output->len = tokens->len;

	unsigned nr = 0;
	FOR_EACH_ITEM(token, tokens) {
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
		output->list[nr++] = tmp_token;
	}

	pfree(tokens);
	return NULL;
}
