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
#include <ctype.h>

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

bool shunk_caseeq(shunk_t lhs, shunk_t rhs)
{
	/* NULL and EMPTY("") are not the same */
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

bool shunk_memeq(shunk_t l, const void *r, size_t sizeof_r)
{
	/* NULL and EMPTY("") are not the same */
	if (l.ptr == NULL || r == NULL) {
		return l.ptr == r;
	}
	if (l.len != sizeof_r) {
		return false;
	}
	return memeq(l.ptr, r, sizeof_r);
}

bool shunk_eq(shunk_t l, shunk_t r)
{
	return shunk_memeq(l, r.ptr, r.len);
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

bool shunk_isdigit(shunk_t s, size_t i)
{
	pexpect(s.len > 0);
	pexpect(i < s.len);
	const char *c = s.ptr;
	return isdigit(c[i]);
}

bool shunk_ischar(shunk_t s, size_t i, const char *chars)
{
	pexpect(s.len > 0);
	pexpect(i < s.len);
	const char *c = s.ptr;
	return strchr(chars, c[i]) != NULL;
}
