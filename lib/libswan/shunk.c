/* Constant string (octet) fragments, for libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney
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

/*
 * Don't mistake a NULL_SHUNK for an empty shunk - just like for
 * strings they are different.
 */

const shunk_t null_shunk = NULL_SHUNK;

shunk_t shunk1(const char *ptr)
{
	if (ptr == NULL) {
		return null_shunk;
	} else {
		return shunk2(ptr, strlen(ptr));
	}
}

shunk_t shunk2(const char *ptr, int len)
{
	/*
	 * Since a zero length string is not the same as a NULL
	 * string, don't try to be smart and convert the former into
	 * the latter.
	 */
	return (shunk_t) { .ptr = ptr, .len = len, };
}

shunk_t shunk_strsep(shunk_t *input, const char *delim)
{
	/*
	 * If INPUT is NULL, the loop is skipped and NULL is
	 * returned.
	 */
	shunk_t token = shunk2(input->ptr, 0);
	while (input->len > 0) {
		if (strchr(delim, *input->ptr) != NULL) {
			/* discard delim */
			input->ptr++;
			input->len--;
			return token;
		}
		/* advance, transfering the char */
		token.len++;
		input->ptr++;
		input->len--;
	}
	/*
	 * Flag this as the last token by setting INPUT to NULL; next
	 * call will return the NULL shunk.
	 */
	*input = null_shunk;
	return token;
}

bool shunk_caseeq(shunk_t lhs, shunk_t rhs)
{
	if (lhs.ptr == NULL || rhs.ptr == NULL) {
		return lhs.ptr == rhs.ptr;
	}
	if (lhs.len != rhs.len) {
		return false;
	}
	return strncasecmp(lhs.ptr, rhs.ptr, lhs.len) == 0;
}

bool shunk_strcaseeq(shunk_t shunk, const char *str)
{
	return shunk_caseeq(shunk, shunk1(str));
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
	shunk->ptr += dinner.len;
	shunk->len -= dinner.len;
	return true;
}

bool shunk_strcaseeat(shunk_t *shunk, const char *dinner)
{
	return shunk_caseeat(shunk, shunk1(dinner));
}

/*
 * Convert the entire shunk to an unsigned.
 *
 * Since strtou() expects a NUL terminated string (which a SHUNK is
 * not) fudge one up.  XXX: must be code to do this somewhere?
 */
bool shunk_tou(shunk_t shunk, unsigned *dest, int base)
{
	/* copy SHUNK into a NUL terminated STRING */
	char string[64] = ""; /* NUL fill */
	if (shunk.len + 1 >= sizeof(string)) {
		/* no-space for trailing NUL */
		return false;
	}
	strncpy(string, shunk.ptr, shunk.len);
	/* convert the string, expect entire shunk to be consumed */
	char *end = NULL;
	unsigned long ul = strtoul(string, &end, base);
	if (string + shunk.len > end) {
		return false;
	}
	if (ul > UINT_MAX) {
		return false;
	}
	*dest = (unsigned)ul;
	return true;
}
