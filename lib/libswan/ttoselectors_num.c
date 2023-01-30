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

	dbg("%s() input: "PRI_SHUNK, __func__, pri_shunk(input));

	/*
	 * Two passes:
	 *
	 *   Pass 1: determine the number of tokens.
	 *   Pass 1.5: allocate list pointers; zero counters
	 *   Pass 2: save the values in separate IPv[46] lists.
	 */

	for (unsigned pass = 1; pass <= 2; pass++) {
		shunk_t cursor = input;
		unsigned nr_tokens = 0;
		while (true) {
			shunk_t token = shunk_token(&cursor, NULL/*delim*/, delims);
			if (token.ptr == NULL) {
				break;
			}
			if (token.len == 0) {
				return diag("empty field");
			}
			ip_token tmp_token;
			ip_address tmp_nonzero;
			err_t e = ttoselector_num(token, input_afi, &tmp_token, &tmp_nonzero);
			const struct ip_info *afi = selector_info(tmp_token);
			switch (pass) {
			case 1:
				/* validate during first pass */
				if (e != NULL) {
					return diag(PRI_SHUNK" invalid, %s",
						    pri_shunk(token), e);
				}
				if (tmp_nonzero.is_set && !nonzero_host->is_set) {
					*nonzero_host = tmp_nonzero; /* save first */
				}
				break;
			case 2:
				/* save value during second pass */
				passert(e == NULL);
				output->ip[afi->ip_index].list[output->ip[afi->ip_index].len] = tmp_token;
				break;
			}
			/* advance the lengths */
			output->ip[afi->ip_index].len++;
			nr_tokens++;
		}
		if (nr_tokens == 0) {
			return NULL;
		}
		switch (pass) {
		case 1:
			/*
			 * Pass 1.5: Allocate.
			 */
			dbg("%s() nr tokens %u", __func__, nr_tokens);
			output->list = alloc_things(ip_token, nr_tokens, "selectors");
			FOR_EACH_ELEMENT(afi, ip_families) {
				enum ip_index ip = afi->ip_index;
				output->ip[ip].list = output->list + output->len;
				output->len += output->ip[ip].len;
				output->ip[ip].len = 0; /* ready for second pass */
			}
			passert(output->len == nr_tokens);
			break;
		case 2:
			passert(nr_tokens == output->len);
			break;
		}
	}

	return NULL;
}
