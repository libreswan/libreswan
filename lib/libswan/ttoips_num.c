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

#include "ip_info.h"
#include "diag.h"
#include "lswalloc.h"
#include "passert.h"
#include "lswlog.h"

diag_t ttoips_num(shunk_t input, const struct ip_info *afi,
		  void **ptr, unsigned *len,
		  err_t (*parse_token)(shunk_t, const struct ip_info *,
				       void **ptr, unsigned len))
{
	*ptr = NULL;
	*len = 0;

	/* #subnet= */
	if (input.ptr == NULL) {
		return NULL;
	}

	/* subnet= */
	if (input.len == 0) {
		return NULL;
	}

	/*
	 * Tokenisze.
	 *
	 * Reduce sequences such as "A ,, " to just A, and ", ," to an
	 * empty list.
	 */
	struct shunks *tokens = shunks(input, ", ", EAT_EMPTY_SHUNKS, HERE); /* must free */

	/*
	 * The result should be non-empty.
	 */
	if (tokens->len == 0) {
		pfree(tokens);
		return diag("empty field");
	}

	/*
	 * Now parse the fields and build the table.
	 */

	FOR_EACH_ITEM(token, tokens) {
		passert(token->len > 0);
		dbg("parsing "PRI_SHUNK" %p %u",
		    pri_shunk(*token), *ptr, (*len));
		err_t e = parse_token(*token, afi, ptr, (*len)++);
		/* validate during first pass */
		if (e != NULL) {
			diag_t d = diag(PRI_SHUNK" invalid, %s",
					pri_shunk(*token), e);
			pfree(tokens);
			pfreeany(*ptr);
			(*len) = 0;
			return d;
		}
		passert((*ptr) != NULL);
		passert((*len) > 0);
	}

	pfree(tokens);
	return NULL;
}
