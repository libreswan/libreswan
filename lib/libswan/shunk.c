/* string fragments, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <string.h>

#include "shunk.h"

const shunk_t empty_shunk;

shunk_t shunk1(const char *ptr)
{
	if (ptr == NULL) {
		return empty_shunk;
	} else {
		return shunk2(ptr, strlen(ptr));
	}
}

shunk_t shunk2(const char *ptr, int len)
{
	/*
	 * Since a zero length string and a NULL string pointer are
	 * considered to be different, don't convert the former into
	 * an empty_chunk.
	 */
	return (shunk_t) { .ptr = ptr, .len = len, };
}

shunk_t shunk_token(shunk_t *shunk, const char *delim)
{
	shunk_t token = shunk2(shunk->ptr, 0);
	while (shunk->len > 0) {
		if (strchr(delim, *shunk->ptr) != NULL) {
			/* discard delim */
			shunk->ptr++;
			shunk->len--;
			return token;
		}
		/* advance, transfering the char */
		token.len++;
		shunk->ptr++;
		shunk->len--;
	}
	return token;
}
