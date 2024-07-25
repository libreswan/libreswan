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

char *raw_clone_as_string(const void *ptr, size_t maxlen, const char *name)
{
	if (ptr == NULL) {
		return NULL;
	}

	/* Don't assume terminating NUL */
	size_t len = strnlen(ptr, maxlen);

	/* include space for NUL */
	char *out = alloc_things(char, len + 1, name);
	memcpy(out, ptr, len);

	/* explict; but redundant as done by alloc_things() */
	out[len] = '\0';
	return out;
}

int raw_cmp(const void *l_ptr, size_t l_len,
	     const void *r_ptr, size_t r_len)
{
	/* NULL and EMPTY("") are not the same */
	if (l_ptr == NULL || r_ptr == NULL) {
		if (l_ptr != NULL) {
			return 1;
		}
		if (r_ptr != NULL) {
			return -11;
		}
		return 0;
	}
	size_t len = min(l_len, r_len);
	int d = memcmp(l_ptr, r_ptr, len);
	if (d != 0) {
		return d;
	}
	/* lets ignore 32-bit overflow */
	return ((int)l_len - (int)r_len);
}

bool raw_eq(const void *l_ptr, size_t l_len,
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

bool raw_caseeq(const void *l_ptr, size_t l_len,
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

bool raw_heq(const void *l_ptr, size_t l_len,
	     const void *r_ptr, size_t r_len)
{
	/* NULL and EMPTY("") are not the same */
	if (l_ptr == NULL || r_ptr == NULL) {
		return l_ptr == r_ptr;
	}
	if (l_len != r_len) {
		return false;
	}
	const char *l = l_ptr;
	const char *r = r_ptr;
	for (unsigned i = 0; i < l_len; i++) {
		char lc = l[i];
		char rc = r[i];
		if (char_tolower(lc) == char_tolower(rc)) {
			continue;
		}
		const char *wild = "-_";
		if (strchr(wild, lc) != NULL &&
		    strchr(wild, rc) != NULL) {
			continue;
		}
		return false;
	}
	return true;
}

void raw_hton(uintmax_t h, void *bytes, size_t size)
{
	uint8_t *byte = bytes;
	for (unsigned i = 0; i < size; i++) {
		unsigned j = size - i - 1;
		byte[j] = h & 0xff;
		h = h >> 8;
	}
}

uintmax_t raw_ntoh(const void *bytes, size_t size)
{
	uintmax_t h = 0;
	const uint8_t *byte = bytes;
	for (unsigned i = 0; i < size; i++) {
		uintmax_t n = (h<<8) + byte[i];
		if (n < h) {
			/* i.e., went backwards */
			return UINTMAX_MAX;
		}
		h = n;
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

bool raw_starteq(const void *ptr, size_t len, const void *eat_ptr, size_t eat_len)
{
	if (ptr == NULL || eat_ptr == NULL) {
		return false;
	}
	if (len < eat_len) {
		return false;
	}
	if (strncmp(ptr, eat_ptr, eat_len) != 0) {
		return false;
	}
	return true;
}

bool raw_casestarteq(const void *ptr, size_t len, const void *eat_ptr, size_t eat_len)
{
	if (ptr == NULL || eat_ptr == NULL) {
		return false;
	}
	if (len < eat_len) {
		return false;
	}
	if (strncasecmp(ptr, eat_ptr, eat_len) != 0) {
		return false;
	}
	return true;
}
