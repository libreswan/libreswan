/* cloning a token list, for libreswan
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

shunk_t *clone_shunk_tokens(shunk_t input, const char *delims, where_t where)
{
	if (input.ptr == NULL) {
		return NULL;
	}

	ldbg(&global_logger, "%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

	/*
	 * Pass 1: determine the number of tokens.
	 */
	unsigned nr_tokens = 0;
	shunk_t cursor = input;
	while (true) {
		shunk_t token = shunk_token(&cursor, NULL/*delim*/, delims);
		if (token.ptr == NULL) {
			break;
		}
		if (token.len == 0) {
			continue;
		}
		nr_tokens++;
	}
	if (nr_tokens == 0) {
		return NULL;
	}
	/*
	 * Allocate.
	 */
	size_t sizeof_tokens = (nr_tokens + 1) * sizeof(shunk_t);
	void *buf = alloc_bytes(sizeof_tokens + input.len, where->func);
	shunk_t *tokens = buf;
	char *strings = buf + sizeof_tokens;
	ldbg(&global_logger, "%s() nr tokens %u, sizeof-tokens %zu sizeof-strings %zu",
	    __func__, nr_tokens, sizeof_tokens, input.len);

	/*
	 * pass 2: copy things over.
	 */
	memcpy(strings, input.ptr, input.len);
	cursor = shunk2(strings, input.len);
	unsigned nr = 0;
	while (true) {
		shunk_t token = shunk_token(&cursor, NULL/*delim*/, delims);
		if (token.ptr == NULL) {
			break;
		}
		if (token.len == 0) {
			continue;
		}
		tokens[nr] = token;
		ldbg(&global_logger, "%s() %d: "PRI_SHUNK, __func__, nr, pri_shunk(token));
		nr++;
	}
	tokens[nr] = null_shunk;
	return tokens;
}
