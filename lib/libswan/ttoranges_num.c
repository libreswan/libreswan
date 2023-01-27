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
			err_t e = ttorange_num(token, input_afi, &tmp_token);
			const struct ip_info *afi = range_info(tmp_token);
			switch (pass) {
			case 1:
				/* validate during first pass */
				if (e != NULL) {
					return diag(PRI_SHUNK" invalid, %s",
						    pri_shunk(token), e);
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
			FOR_EACH_THING(ip, IPv4_INDEX, IPv6_INDEX) {
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
