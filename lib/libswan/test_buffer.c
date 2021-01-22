/*
 * Copyright (C) 2014-2015,2017 Andrew Cagney <cagney@gnu.org>
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
 */

#include <stdlib.h>

#include "constants.h"
#include "lswalloc.h"
#include "pk11pub.h"

#include "crypt_symkey.h"
#include "test_buffer.h"
#include "ike_alg.h"

#include "lswlog.h"

static chunk_t zalloc_chunk(size_t length, const char *name)
{
	chunk_t chunk;
	chunk.len = length;
	chunk.ptr = alloc_bytes(length, name);
	memset(chunk.ptr, 0, chunk.len);
	return chunk;
}

/*
 * Given an ASCII string, convert it into a chunk of bytes.  If the
 * string is prefixed by 0x assume the contents are hex (with spaces)
 * and decode it; otherwise it is assumed that the ASCII (minus the
 * NUL) should be copied.
 * The caller must free the chunk.
 */
chunk_t decode_to_chunk(const char *prefix, const char *original)
{
	DBGF(DBG_CRYPT, "decode_to_chunk: %s: input \"%s\"",
	     prefix, original);
	chunk_t chunk;
	if (startswith(original, "0x")) {
		chunk = chunk_from_hex(original + strlen("0x"), original);
	} else {
		chunk = zalloc_chunk(strlen(original), original);
		memcpy(chunk.ptr, original, chunk.len);
	}
	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("decode_to_chunk: output: ", chunk);
	}
	return chunk;
}

PK11SymKey *decode_hex_to_symkey(const char *prefix, const char *string,
				 struct logger *logger)
{
	chunk_t chunk = chunk_from_hex(string, prefix);
	PK11SymKey *symkey = symkey_from_hunk(prefix, chunk, logger);
	free_chunk_content(&chunk);
	return symkey;
}

/*
 * Verify that the chunk's data is the same as actual.
 */

bool verify_bytes(const char *desc,
		  const void *expected, size_t expected_size,
		  const void *actual, size_t actual_size)
{
	if (expected_size != actual_size) {
		DBGF(DBG_CRYPT, "verify_chunk: %s: expected length %zd but got %zd",
		     desc, expected_size, actual_size);
		return false;
	}

	size_t i;
	for (i = 0; i < expected_size; i++) {
		uint8_t e = ((const uint8_t*)expected)[i];
		uint8_t a = ((const uint8_t*)actual)[i];
		if (e != a) {
			/* Caller should issue the real log message.  */
			DBGF(DBG_CRYPT, "verify_chunk_data: %s: bytes at %zd differ, expected %02x found %02x",
			     desc, i, e, a);
			return false;
		}
	}
	DBGF(DBG_CRYPT, "verify_chunk_data: %s: ok", desc);
	return true;
}

/* verify that expected is the same as actual */
bool verify_symkey(const char *desc, chunk_t expected, PK11SymKey *actual,
		   struct logger *logger)
{
	if (expected.len != sizeof_symkey(actual)) {
		DBGF(DBG_CRYPT, "%s: expected length %zd but got %zd",
		     desc, expected.len, sizeof_symkey(actual));
		return FALSE;
	}
	chunk_t chunk = chunk_from_symkey(desc, actual, logger);
	bool ok = verify_hunk(desc, expected, chunk);
	free_chunk_content(&chunk);
	return ok;
}

/*
 * Turn the raw key into SymKey.
 */
PK11SymKey *decode_to_key(const struct encrypt_desc *encrypt_desc,
			  const char *encoded_key, struct logger *logger)
{
	chunk_t raw_key = decode_to_chunk("raw_key", encoded_key);
	PK11SymKey *symkey = encrypt_key_from_hunk("symkey", encrypt_desc, raw_key, logger);
	free_chunk_content(&raw_key);
	return symkey;
}
