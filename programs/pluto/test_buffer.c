/*
 * Copyright (C) 2014 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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
 */

#include <stdlib.h>

#include "defs.h"
#include "constants.h"
#include "lswalloc.h"
#include "lswlog.h"

#include "nss.h"
#include "pk11pub.h"

#include "crypt_dbg.h"
#include "test_buffer.h"

static chunk_t zalloc_chunk(size_t length, const char *name)
{
	chunk_t chunk;
	chunk.len = length;
	chunk.ptr = alloc_bytes(length, name);
	memset(chunk.ptr, 0, chunk.len);
	return chunk;
}

/*
 * Given a hex encode string, decode it into a chunk.
 *
 * If this function fails, crash and burn.  Its been fed static data
 * so should never ever have a problem.
 */
chunk_t decode_hex_to_chunk(const char *original, const char *string)
{
	/* The decoded buffer can't be bigger than the encoded string.  */
	chunk_t chunk = zalloc_chunk(strlen(string), original);
	chunk.len = 0;
	const char *pos = string;
	while (*pos != '\0') {
		/* skip leading/trailing space */
		while (*pos == ' ') {
			pos++;
		}
		if (*pos == '\0') {
			break;
		}
		/* Expecting <HEX><HEX>, at least *pos is valid.  */
		char buf[3];
		int i = 0;
		do {
			buf[i++] = *pos++;
		} while (*pos != ' ' && *pos != '\0' && i < 2);
		buf[i] = '\0';
		if (i != 2) {
			loglog(RC_INTERNALERR,
			       "decode_hex_to_chunk: hex buffer \"%s\" contains unexpected space or NUL at \"%s\"\n", string, pos);
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		}
		char *end;
		chunk.ptr[chunk.len] = strtoul(buf, &end, 16);
		if (end - buf != 2) {
			loglog(RC_INTERNALERR,
			       "decode_hex_to_chunk: hex buffer \"%s\" invalid hex character at \"%s\"\n", string, pos);
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		}
		chunk.len++;
	}
	return chunk;
}

/*
 * Given an ASCII string, convert it onto a buffer of bytes.  If the
 * buffer is prefixed by 0x assume the contents are hex (with spaces)
 * and decode it; otherwise it is assumed that the ascii (minus the
 * NUL) should be copied.
 */
chunk_t decode_to_chunk(const char *prefix, const char *original)
{
	DBG(DBG_CRYPT, DBG_log("decode_to_chunk: %s: input \"%s\"",
			       prefix, original));
	chunk_t chunk;
	if (startswith(original, "0x")) {
		chunk = decode_hex_to_chunk(original, original + strlen("0x"));
	} else {
		chunk = zalloc_chunk(strlen(original), original);
		memcpy(chunk.ptr, original, chunk.len);
	}
	DBG(DBG_CRYPT, DBG_dump_chunk("decode_to_chunk: output: ", chunk));
	return chunk;
}

int compare_chunk(const char *prefix,
		  chunk_t expected,
		  u_char *actual)
{
	size_t i;
	for (i = 0; i < expected.len; i++) {
		u_char l = expected.ptr[i];
		u_char r = actual[i];
		if (l != r) {
			/* Caller should issue the real log message.  */
			DBG(DBG_CRYPT, DBG_log("compare_chunk: %s: bytes at %zd differ, expected %02x found %02x",
					       prefix, i, l, r));
			return 0;
		}
	}
	DBG(DBG_CRYPT, DBG_log("compare_chunk: %s: ok", prefix));
	return 1;
}

int compare_chunks(const char *prefix,
		   chunk_t expected,
		   chunk_t actual)
{
	if (expected.len != actual.len) {
		DBG(DBG_CRYPT,
		    DBG_log("compare_chunks: %s: expected length %zd but got %zd",
			    prefix, expected.len, actual.len));
		return 0;
	}
	return compare_chunk(prefix, expected, actual.ptr);
}

chunk_t extract_chunk(const char *prefix, const chunk_t input, size_t offset, size_t length)
{
	chunk_t output;
	DBG(DBG_CRYPT, DBG_log("extract_chunk: %s: offset %zd length %zd",
			       prefix, offset, length));
	passert(offset + length <= input.len);
	clonetochunk(output, input.ptr + offset, length, prefix);
	DBG(DBG_CRYPT, DBG_dump_chunk(prefix, output));
	return output;
}

/*
 * Turn the raw key into a SECItem and then SymKey.
 *
 * Since slots are referenced counted and ImportSymKey adds a
 * reference, immediate freeing of the local slot is possible.
 *
 * ImportSymKey makes a copy of the key chunk so that can also be
 * released.
 */
PK11SymKey *decode_to_key(CK_MECHANISM_TYPE cipher_mechanism,
			  const char *encoded_key)
{
	chunk_t raw_key = decode_to_chunk("key", encoded_key);
	PK11SymKey *sym_key = chunk_to_symkey(cipher_mechanism, raw_key);
	freeanychunk(raw_key);
	return sym_key;
}
