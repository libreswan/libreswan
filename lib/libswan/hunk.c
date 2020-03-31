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
#include <ctype.h>

#include "hunk.h"

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
		h = (h<<8) + byte[i];
	}
	return h;
}
