/* memory chunks, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include "lswlog.h"	/* for DBG_dump() */
#include "ctype.h"		/* for isxdigit() */
#include <stdlib.h>		/* for strtoul() */

/*
 * Compiler note: some older versions of GCC claim that EMPTY_CHUNK
 * isn't a constant so we cannot use it as an initializer for empty_chunk.
 */
const chunk_t empty_chunk = { .ptr = NULL, .len = 0 };

chunk_t chunk1(char *ptr)
{
	return (chunk_t) { .ptr = (void*) ptr, .len = strlen(ptr), };
}

chunk_t chunk2(void *ptr, size_t len)
{
	return (chunk_t) { .ptr = ptr, .len = len, };
}

chunk_t alloc_chunk(size_t count, const char *name)
{
	uint8_t *ptr = alloc_things(uint8_t, count, name);
	return chunk2(ptr, count);
}

void free_chunk_content(chunk_t *chunk)
{
	pfreeany(chunk->ptr);
	*chunk = EMPTY_CHUNK;
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

chunk_t clone_bytes_as_chunk(const void *bytes, size_t sizeof_bytes, const char *name)
{
	/*
	 * orig=NULL; size=0 -> NULL
	 * orig=PTR; size=0 -> new PTR (for instance a shunk with PTR = "")
	 * orig=PTR; size>0 -> new PTR
	 */
	return chunk2(clone_bytes(bytes, sizeof_bytes, name), sizeof_bytes);
}

/*
 * Given a HEX encoded string (there is no leading 0x prefix, but
 * there may be embedded spaces), decode it into a freshly allocated
 * chunk.
 *
 * If this function fails, crash and burn - it is fed static data so
 * should never ever have a problem.
 *
 * The caller must free the chunk.
 */
chunk_t chunk_from_hex(const char *hex, const char *name)
{
	/*
	 * The decoded buffer (consiting of can't be bigger than half the encoded
	 * string.
	 */
	chunk_t chunk = alloc_chunk((strlen(hex)+1)/2, name);
	chunk.len = 0;
	const char *pos = hex;
	for (;;) {
		/* skip leading/trailing space */
		while (*pos == ' ') {
			pos++;
		}
		if (*pos == '\0') {
			break;
		}
		/* Expecting <HEX><HEX> */
		if (!isxdigit(pos[0]) || !isxdigit(pos[1])) {
			/* friendly barf for debugging */
			PASSERT_FAIL("expected hex digit at offset %tu in hex buffer \"%s\" but found \"%.1s\"",
				     pos - hex, hex, pos);
		}

		char buf[3] = { pos[0], pos[1], '\0' };
		char *end;
		chunk.ptr[chunk.len] = strtoul(buf, &end, 16);
		passert(*end == '\0');
		chunk.len++;
		pos += 2;
	}
	return chunk;
}
