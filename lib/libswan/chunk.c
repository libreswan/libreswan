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
#include "lswlog.h"		/* for LDBG_dump() */
#include <stdlib.h>		/* for strtoul() */

const chunk_t empty_chunk = NULL_HUNK;

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
	if (chunk->ptr != NULL) {
		pfree(chunk->ptr);
	}
	*chunk = empty_chunk;
}

void replace_chunk_bytes(chunk_t *dest, const void *src, size_t sizeof_src, const char *name)
{
	free_chunk_content(dest);
	*dest = clone_bytes_as_chunk(src, sizeof_src, name);
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

chunk_t clone_bytes_bytes_as_chunk(const void *lhs_ptr, size_t lhs_len,
				   const void *rhs_ptr, size_t rhs_len,
				   const char *name)
{
	void *new = clone_bytes_bytes(lhs_ptr, lhs_len, rhs_ptr, rhs_len, name);
	return chunk2(new, lhs_len + rhs_len);
}

void append_chunk_bytes(const char *name, chunk_t *lhs,
			const void *rhs_ptr, size_t rhs_len)
{
	chunk_t new = clone_bytes_bytes_as_chunk(lhs->ptr, lhs->len, rhs_ptr, rhs_len, name);
	free_chunk_content(lhs);
	*lhs = new;
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
	 * The decoded buffer (consisting of can't be bigger than half the encoded
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
		if (!char_isxdigit(pos[0]) || !char_isxdigit(pos[1])) {
			/* friendly barf for debugging */
			llog_passert(&global_logger, HERE,
				     "expected hex digit at offset %tu in hex buffer \"%s\" but found \"%.1s\"",
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
