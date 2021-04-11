/* hunk like buffers, for libreswan
 *
 * Copyright (C) 2018-2020 Andrew Cagney <cagney@gnu.org>
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

#include "lswalloc.h"		/* for clone_bytes() */
#include "hunk.h"

char *clone_bytes_as_string(const void *ptr, size_t len, const char *name)
{
	if (ptr == NULL) {
		return NULL;
	}

	/* NUL terminated (could also contain NULs, oops)? */
	const char *in = ptr;
	if (len > 0 && in[len - 1] == '\0') {
		return clone_bytes(in, len, name);
	}

	char *out = alloc_things(char, len + 1, name);
	memcpy(out, ptr, len);
	return out;
}

bool bytes_eq(const void *l_ptr, size_t l_len,
	      const void *r_ptr, size_t r_len)
{
	/* NULL and EMPTY("") are not the same */
	if (l_ptr == NULL || r_ptr == NULL) {
		return l_ptr == r_ptr;
	}
	if (l_len != r_len) {
		return false;
	}
	return memcmp(l_ptr, r_ptr, r_len) == 0;
}

bool case_eq(const void *l_ptr, size_t l_len,
	     const void *r_ptr, size_t r_len)
{
	/* NULL and EMPTY("") are not the same */
	if (l_ptr == NULL || r_ptr == NULL) {
		return l_ptr == r_ptr;
	}
	if (l_len != r_len) {
		return false;
	}
	return strncasecmp(l_ptr, r_ptr, r_len) == 0;
}

void hton_bytes(uintmax_t h, void *bytes, size_t size)
{
	uint8_t *byte = bytes;
	for (unsigned i = 0; i < size; i++) {
		unsigned j = size - i - 1;
		byte[j] = h & 0xff;
		h = h >> 8;
	}
}

uintmax_t ntoh_bytes(const void *bytes, size_t size)
{
	uintmax_t h = 0;
	const uint8_t *byte = bytes;
	for (unsigned i = 0; i < size; i++) {
		uintmax_t n = (h<<8) + byte[i];
		if (n < h) {
			h = UINTMAX_MAX;
		} else {
			h = n;
		}
	}
	return h;
}

bool char_isupper(char c)
{
	return (c >= 'A' && c <= 'Z');
}

bool char_islower(char c)
{
	return (c >= 'a' && c <= 'z');
}

bool char_isspace(char c)
{
	return (c == ' ' ||
		c == '\f' ||
		c == '\n' ||
		c == '\r' ||
		c == '\t' ||
		c == '\v');
}

bool char_isblank(char c)
{
	return (c == ' ' ||
		c == '\t');
}

bool char_isdigit(char c)
{
	return (c >= '0' && c <= '9');
}

bool char_isbdigit(char c)
{
	return (c >= '0' && c <= '1');
}

bool char_isodigit(char c)
{
	return (c >= '0' && c <= '7');
}

bool char_isxdigit(char c)
{
	return ((c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F'));
}

bool char_isprint(char c)
{
	return (c >= 0x20 && c <= 0x7e);
}

char char_tolower(char c)
{
	return char_isupper(c) ? c - 'A' + 'a' : c;
}

char char_toupper(char c)
{
	return char_islower(c) ? c - 'a' + 'A' : c;
}
