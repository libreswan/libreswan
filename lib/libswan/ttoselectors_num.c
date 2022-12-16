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
#include "lswlog.h"		/* for dbg() */
#include "ip_selector.h"

const ip_selectors empty_ip_selectors;

diag_t ttoselectors_num(shunk_t input, const char *delims,
			const struct ip_info *afi,
			ip_selectors *output, ip_address *nonzero_host)
{
	*output = empty_ip_selectors;
	*nonzero_host = unset_address;

	if (input.ptr == NULL) {
		return NULL;
	}

	dbg("%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

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
			return diag("empty field");
		}
		/* validate during first pass */
		ip_selector tmp;
		ip_address tmp_nonzero;
		err_t e = ttoselector_num(token, afi, &tmp, &tmp_nonzero);
		if (e != NULL) {
			return diag(PRI_SHUNK" invalid, %s",
				    pri_shunk(token), e);
		}
		if (tmp_nonzero.is_set && !nonzero_host->is_set) {
			*nonzero_host = tmp_nonzero; /* save first */
		}
		nr_tokens++;
	}
	if (nr_tokens == 0) {
		return NULL;
	}
	/*
	 * Allocate.
	 */
	dbg("%s() nr tokens %u", __func__, nr_tokens);
	output->len = nr_tokens;
	output->list = alloc_things(ip_selector, nr_tokens, "selectors");

	/*
	 * pass 2: copy things over.
	 */
	cursor = input;
	ip_selector *dst = output->list;
	while (true) {
		shunk_t token = shunk_token(&cursor, NULL/*delim*/, delims);
		if (token.ptr == NULL) {
			break;
		}
		if (token.len == 0) {
			continue;
		}
		passert(dst < output->list + output->len);
		ip_address tmp_nonzero;
		err_t e = ttoselector_num(token, afi, dst, &tmp_nonzero);
		passert(e == NULL);
		selector_buf b;
		dbg("%s() %s", __func__, str_selector(dst, &b));
		dst++;
	}
	passert(dst == output->list + output->len);
	return NULL;
}
