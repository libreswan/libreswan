/* memory chunks, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#include "chunk.h"
#include "lswalloc.h"

const chunk_t empty_chunk = { NULL, 0 };

chunk_t chunk(void *ptr, size_t len)
{
	return (chunk_t) { .ptr = ptr, .len = len, };
}

chunk_t alloc_chunk(size_t count, const char *name)
{
	uint8_t *ptr = alloc_things(uint8_t, count, name);
	return chunk(ptr, count);
}

void free_chunk_contents(chunk_t *chunk)
{
	pfreeany(chunk->ptr);
	*chunk = empty_chunk;
}

chunk_t clone_chunk(chunk_t chunk, const char *name)
{
	if (chunk.ptr == NULL) {
		return empty_chunk;
	} else {
		chunk_t clone = {
			.ptr = clone_bytes(chunk.ptr, chunk.len, name),
			.len = chunk.len,
		};
		return clone;
	}
}

chunk_t clone_chunk_chunk(chunk_t lhs, chunk_t rhs, const char *name)
{
	size_t len = lhs.len + rhs.len;
	chunk_t cat = {
		.len = len,
		.ptr = alloc_things(uint8_t, len, name),
	};
	memcpy(cat.ptr, lhs.ptr, lhs.len);
	memcpy(cat.ptr + lhs.len, rhs.ptr, rhs.len);
	return cat;
}

char *clone_chunk_as_string(chunk_t chunk, const char *name)
{
	if (chunk.ptr == NULL) {
		return NULL;
	} else if (chunk.len > 0 && chunk.ptr[chunk.len - 1] == '\0') {
		return clone_bytes(chunk.ptr, chunk.len, name);
	} else {
		char *string = alloc_things(char, chunk.len + 1, name);
		memcpy(string, chunk.ptr, chunk.len);
		return string;
	}
}

chunk_t clone_bytes_as_chunk(void *bytes, size_t sizeof_bytes, const char *name)
{
	return chunk(clone_bytes(bytes, sizeof_bytes, name), sizeof_bytes);
}

bool chunk_eq(chunk_t a, chunk_t b)
{
	return a.len == b.len && memeq(a.ptr, b.ptr, b.len);
}
