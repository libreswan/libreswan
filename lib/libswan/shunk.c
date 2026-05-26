/* Constant string (octet) fragments, for libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <string.h>
#include <stdlib.h>	/* for strtoul() */
#include <limits.h>

#include "shunk.h"
#include "table.h"
#include "lswlog.h"	/* for pexpect() */

/*
 * Don't mistake a NULL_SHUNK for an EMPTY_SHUNK - just like when
 * manipulating strings they are different.
 */

const shunk_t null_shunk = NULL_HUNK;
static const uint8_t empty_shunk_byte;
const shunk_t empty_shunk = { .ptr = &empty_shunk_byte, .len = 0, };

shunk_t shunk1(const char *ptr)
{
	if (ptr == NULL) {
		return null_shunk;
	} else {
		return shunk2(ptr, strlen(ptr));
	}
}

shunk_t shunk2(const void *ptr, size_t len)
{
	/*
	 * Since a zero length string is not the same as a NULL
	 * string, don't try to be smart and convert the former into
	 * the latter.
	 */
	return (shunk_t) { .ptr = ptr, .len = len, };
}

shunk_t shunk_token(shunk_t *cursor, char *delim, const char *delims)
{
	unsigned pos = 0;
	while (true) {
		int d = hunk_byte(*cursor, pos);

		if (d < 0) {
			/*
			 * EOF
			 *
			 * The last token is any remaining input (per
			 * below, when CURSOR is the NULL_SHUNK token
			 * is set to NULL_SHUNK).
			 *
			 * Flag that the input has been exhausted by
			 * setting CURSOR to the NULL_SHUNK.  The next
			 * call will return the NULL_SHUNK CURSOR as
			 * the TOKEN terminating the LOOP.
			 */
			shunk_t token = *cursor;
			*cursor = null_shunk;
			if (delim != NULL) {
				*delim = '\0';
			}
			return token;
		}

		if (strchr(delims, d) != NULL) {
			/*
			 * TOKEN END
			 *
			 * Save the token and, optionally, delim
			 * character.  Advance CURSOR to next token.
			 */
			shunk_t token = shunk_slice(*cursor, 0, pos);
			if (delim != NULL) {
				*delim = d;
			}
			/* skip over TOKEN+DELIM */
			*cursor = shunk_slice(*cursor, pos+1, cursor->len);
			return token;
		}

		pos++;
	}
}

shunk_t shunk_span(shunk_t *cursor, const char *accept)
{
	unsigned pos = 0;
	while (true) {
		int d = hunk_byte(*cursor, pos);

		if (d < 0) {
			/*
			 * EOF
			 *
			 * The last token is just the CURSOR (i.e.,
			 * any remaining input).  Flag that input has
			 * been exhausted by setting CURSOR to the
			 * NULL_SHUNK; the next call will find there's
			 * no input and return that NULL_SHUNK.
			 */
			shunk_t token = *cursor;
			*cursor = null_shunk;
			return token;
		}

		if (strchr(accept, d) == NULL) {
			/* save the token */
			shunk_t token = shunk_slice(*cursor, 0, pos);
			/* skip over TOKEN+DELIM */
			*cursor = shunk_slice(*cursor, pos, cursor->len);
			return token;
		}

		pos++;
	}
}

/*
 * Convert INPUT to an unsigned.
 *
 * If OUTPUT is NULL, INPUT must only contain the numeric value, else
 * OUTPUT is set to any trailing characters.
 */

err_t shunk_to_uintmax(shunk_t input, shunk_t *output, unsigned draft_base, uintmax_t *dest)
{
	*dest = 0;
	if (output != NULL) {
		*output = (shunk_t) NULL_HUNK;
	}

	if (input.len == 0) {
		return "empty string";
	}

	if (hunk_streat(&input, "-1")) {
		if (output != NULL) {
			*output = input;
			*dest = UINTMAX_MAX;
			return NULL;
		}
		if (input.len == 0) {
			*dest = UINTMAX_MAX;
			return NULL;
		}
		return "trailing junk";
	}

	/*
	 * Detect standard prefixes.
	 *
	 * MIMIC BSD:
	 *
	 * Only auto detect the 0[xb] prefix when it is followed by at
	 * least one valid digit.  If the digit is missing, fall back
	 * to decimal, and not octal, so that decimal errors are
	 * returned.
	 */
	unsigned base;
	if (draft_base == 0) {
		if (hunk_strcasestarteq(input, "0x")) {
			if (char_isxdigit(hunk_char(input, 2))) {
				hunk_strcaseeat(&input, "0x");
				base = 16;
			} else {
				base = 10;
			}
		} else if (hunk_strcasestarteq(input, "0b")) {
			if (char_isbdigit(hunk_char(input, 2))) {
				hunk_strcaseeat(&input, "0b");
				base = 2;
			} else {
				base = 10;
			}
		} else if (hunk_char(input, 0) == '0') {
			/* so 0... is interpreted as 0 below */
			base = 8;
		} else {
			base = 10;
		}
#if 0 /* don't mimic this part of strtoul()? */
	} else if (base == 8) {
		shunk_strcaseeat(&input, "0");
	} else if (base == 16) {
		shunk_strcaseeat(&input, "0x");
#endif
	} else {
		base = draft_base;
	}

	/* something to convert */
	shunk_t cursor = input;

	/* something */
	uintmax_t u = 0;
	while (char_isprint(hunk_char(cursor, 0))) {
		unsigned char c = hunk_char(cursor, 0);
		/* convert to a digit; <0 will overflow */
		unsigned d;
		if (char_isdigit(c)) {
			d = c - '0';
		} else if (c >= 'a') {
			d = c - 'a' + 10;
		} else if (c >= 'A') {
			d = c - 'A' + 10;
		} else {
			break;
		}
		/* valid? */
		if (d >= base) {
			break;
		}
		/* will multiplying U by BASE overflow? */
		const uintmax_t rlimit = UINTMAX_MAX / base;
		if (u > rlimit) {
			return "uintmax_t overflow";
		}
		u = u * base;
		/* will adding D to U*BASE overflow? */
		const uintmax_t dlimit = UINTMAX_MAX - u;
		if (d > dlimit) {
			return "uintmax_t overflow";
		}
		u = u + d;
		cursor = shunk_slice(cursor, 1, cursor.len);
	}

	if (cursor.len == input.len) {
		/* nothing valid */
		switch (draft_base) {
		case 2:
			return "first binary digit invalid";
		case 8:
			return "first octal digit invalid";
		case 10:
			return "first decimal digit invalid";
		case 16:
			return "first hex digit invalid";
		default:
			return "first digit invalid";
		}
	}

	/* everything consumed? */
	if (output == NULL) {
		if (cursor.len > 0) {
			switch (base) {
			case 2:
				return "non-binary digit in number";
			case 8:
				return "non-octal digit in number";
			case 10:
				return "non-decimal digit in number";
			case 16:
				return "non-hex digit in number";
			default:
				return "non-digit in number";
			}
		}
	}

	*dest = u;
	if (output != NULL) {
		*output = cursor;
	}
	return NULL;
}

err_t shunk_to_intmax(shunk_t input, shunk_t *output, unsigned draft_base, intmax_t *dest)
{
	(*dest) = 0;
	bool negative = hunk_streat(&input, "-");
	uintmax_t u;

	err_t e = shunk_to_uintmax(input, output, draft_base, &u);
	if (e != NULL) {
		return e;
	}

	if (negative) {
		/* how to use INTMAX_MIN? */
		intmax_t s = -u;
		if (s > 0) {
			return "intmax_t underflow";
		}
		(*dest) = s;
		return NULL;
	}

	if (u > INTMAX_MAX) {
		return "intmax_t overflow";
	}

	(*dest) = u;
	return NULL;
}

struct shunks *ttoshunks(shunk_t input, const char *delims, enum shunks_opt opt)
{
	ldbgf(DBG_TMI, &global_logger,
	      "%s() input=\""PRI_SHUNK"\" delims=\"%s\"",
	      __func__, pri_shunk(input), delims);

	/*
	 * Allocate a minimal buffer.  Will grow it as more tokens are
	 * found.
	 *
	 * This means that NULL is never returned!
	 */
	struct shunks *tokens = table_alloc(struct shunks, 0);

	shunk_t cursor = input;
	while (true) {
		char delim;
		shunk_t token = shunk_token(&cursor, &delim, delims);
		if (token.ptr == NULL) {
			break;
		}
		if (token.len == 0) {
			if (opt == EAT_EMPTY_SHUNKS) {
				/* eat spaces when part of delims */
				ldbgf(DBG_TMI, &global_logger,
				      "%s() pass 1 eat empty", __func__);
				continue;
			}
			tokens->kept_empty_shunks = true;
		}
		ldbgf(DBG_TMI, &global_logger,
		      "%s() [%u] \""PRI_SHUNK"\"",
		      __func__, tokens->len, pri_shunk(token));
		/* grow by one shunk_t; and save the token */
		table_grow(tokens, token);
	}

	return tokens;
}
