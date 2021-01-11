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
#include "lswlog.h"	/* for pexpect() */

/*
 * Don't mistake a NULL_SHUNK for an EMPTY_SHUNK - just like when
 * manipulating strings they are different.
 */

const shunk_t null_shunk = NULL_SHUNK;
const shunk_t empty_shunk = { .ptr = "", .len = 0, };

shunk_t shunk1(const char *ptr)
{
	if (ptr == NULL) {
		return null_shunk;
	} else {
		return shunk2(ptr, strlen(ptr));
	}
}

shunk_t shunk2(const void *ptr, int len)
{
	/*
	 * Since a zero length string is not the same as a NULL
	 * string, don't try to be smart and convert the former into
	 * the latter.
	 */
	return (shunk_t) { .ptr = ptr, .len = len, };
}

shunk_t shunk_slice(shunk_t s, size_t start, size_t stop)
{
	pexpect(start <= stop);
	pexpect(stop <= s.len);
	const char *c = s.ptr;
	return shunk2(c + start, stop - start);
}

shunk_t shunk_token(shunk_t *input, char *delim, const char *delims)
{
	/*
	 * If INPUT is either empty, or the NULL_SHUNK, the loop is
	 * skipped.
	 */
	const char *const start = input->ptr;
	const char *pos = start;
	while (pos < start + input->len) {
		if (strchr(delims, *pos) != NULL) {
			/* save the token and stop character */
			shunk_t token = shunk2(start, pos-start);
			if (delim != NULL) {
				*delim = *pos;
			}
			/* skip over TOKEN+DELIM */
			*input = shunk_slice(*input, pos-start+1, input->len);
			return token;
		}
		pos++;
	}
	/*
	 * The last token is all of INPUT.  Flag that INPUT has been
	 * exhausted by setting INPUT to the NULL_SHUNK; the next call
	 * will return that NULL_SHUNK.
	 */
	shunk_t token = *input;
	*input = null_shunk;
	if (delim != NULL) {
		*delim = '\0';
	}
	return token;
}

shunk_t shunk_span(shunk_t *input, const char *accept)
{
	/*
	 * If INPUT is either empty, or the NULL_SHUNK, the loop is
	 * skipped.
	 */
	const char *const start = input->ptr;
	const char *pos = start;
	while (pos < start + input->len) {
		if (strchr(accept, *pos) == NULL) {
			/* save the token and stop character */
			shunk_t token = shunk2(start, pos - start);
			/* skip over TOKEN+DELIM */
			*input = shunk_slice(*input, pos - start, input->len);
			return token;
		}
		pos++;
	}
	/*
	 * The last token is all of INPUT.  Flag that INPUT has been
	 * exhausted by setting INPUT to the NULL_SHUNK; the next call
	 * will return that NULL_SHUNK.
	 */
	shunk_t token = *input;
	*input = null_shunk;
	return token;
}

bool shunk_caseeat(shunk_t *shunk, shunk_t dinner)
{
	if (shunk->ptr == NULL || dinner.ptr == NULL) {
		return false;
	}
	if (shunk->len < dinner.len) {
		return false;
	}
	if (strncasecmp(shunk->ptr, dinner.ptr, dinner.len) != 0) {
		return false;
	}
	*shunk = shunk_slice(*shunk, dinner.len, shunk->len);
	return true;
}

bool shunk_strcaseeat(shunk_t *shunk, const char *dinner)
{
	return shunk_caseeat(shunk, shunk1(dinner));
}

/*
 * Convert INPUT to an unsigned.
 *
 * If OUTPUT is NULL, INPUT must only contain the numeric value, else
 * OUTPUT is set to any trailing characters.
 *
 * If CEILING is non-ZERO, *dest cann't be greater than CEILING.
 */
err_t shunk_to_uintmax(shunk_t input, shunk_t *output, unsigned base,
		       uintmax_t *dest, uintmax_t ceiling)
{
	*dest = 0;
	if (output != NULL) {
		*output = (shunk_t) NULL_HUNK;
	}

	if (input.len == 0) {
		return "empty string";
	}

	/*
	 * Detect standard prefixes.
	 *
	 * MIMIC BSD - only auto detect the prefix when the number has
	 * at least one valid digit.
	 */
	if (base == 0) {
		if (hunk_strcasestarteq(input, "0x") &&
		    char_isxdigit(hunk_char(input, 2))) {
			shunk_strcaseeat(&input, "0x");
			base = 16;
		} else if (hunk_strcasestarteq(input, "0b") &&
			   char_isbdigit(hunk_char(input, 2))) {
			shunk_strcaseeat(&input, "0b");
			base = 2;
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
			return "unsigned-long overflow";
		}
		u = u * base;
		/* will adding D to U*BASE overflow? */
		const uintmax_t dlimit = UINTMAX_MAX - u;
		if (d > dlimit) {
			return "unsigned-long overflow";
		}
		u = u + d;
		cursor = shunk_slice(cursor, 1, cursor.len);
	}

	if (cursor.len == input.len) {
		/* nothing valid */
		switch (base) {
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

	/* in range? */
	if (ceiling > 0 && u > ceiling) {
		return "too large";
	}

	*dest = u;
	if (output != NULL) {
		*output = cursor;
	}
	return NULL;
}
