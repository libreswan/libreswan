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
#include "crypt_mac.h"
#include "test_buffer.h"
#include "ike_alg.h"

#include "lswlog.h"

/*
 * Given an ASCII string, convert it into a chunk of bytes.  If the
 * string is prefixed by 0x assume the contents are hex (with spaces)
 * and decode it; otherwise it is assumed that the ASCII (minus the
 * NUL) should be copied.
 *
 * The caller must free the chunk.
 */
chunk_t decode_to_chunk(const char *prefix, const char *original,
			struct logger *logger, where_t where UNUSED)
{
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s() %s: input \"%s\"",
			 __func__, prefix, original);
	}
	chunk_t chunk;
	if (startswith(original, "0x")) {
		chunk = chunk_from_hex(original + strlen("0x"), original);
	} else {
		chunk = alloc_chunk(strlen(original), original);
		memcpy(chunk.ptr, original, chunk.len);
	}
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s() output:", __func__);
		LDBG_hunk(logger, chunk);
	}
	return chunk;
}

/*
 * Given an ASCII string, convert it into a chunk of bytes.  If the
 * string is prefixed by 0x assume the contents are hex (with spaces)
 * and decode it; otherwise it is assumed that the ASCII (minus the
 * NUL) should be copied.
 *
 * The caller must free the chunk.
 */

struct crypt_mac decode_to_mac(const char *prefix, const char *original,
			       struct logger *logger, where_t where UNUSED)
{
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s() %s: input \"%s\"",
			 __func__, prefix, original);
	}
	struct crypt_mac mac;
	if (startswith(original, "0x")) {
		chunk_t chunk = chunk_from_hex(original + strlen("0x"), original);
		PASSERT(logger, chunk.len <= sizeof(mac.ptr/*array*/));
		mac.len = chunk.len;
		memcpy(mac.ptr, chunk.ptr, mac.len);
		free_chunk_content(&chunk);
	} else {
		mac.len = strlen(original);
		PASSERT(logger, mac.len <= sizeof(mac.ptr/*array*/));
		memcpy(mac.ptr, original, mac.len);
	}
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s() output:", __func__);
		LDBG_hunk(logger, mac);
	}
	return mac;
}

PK11SymKey *decode_hex_to_symkey(const char *prefix, const char *string,
				 struct logger *logger, where_t where UNUSED)
{
	chunk_t chunk = chunk_from_hex(string, prefix);
	PK11SymKey *symkey = symkey_from_hunk(prefix, chunk, logger);
	free_chunk_content(&chunk);
	return symkey;
}

/*
 * Verify that the chunk's data is the same as actual.
 */

bool verify_bytes(const char *desc, const char *verifying,
		  const void *expected, size_t expected_size,
		  const void *actual, size_t actual_size,
		  struct logger *logger, where_t where)
{
	if (expected_size != actual_size) {
		llog_pexpect(logger, where,
			     "%s: %s: expected length %zd but got %zd",
			     desc, verifying, expected_size, actual_size);
		return false;
	}

	size_t i;
	for (i = 0; i < expected_size; i++) {
		uint8_t e = ((const uint8_t*)expected)[i];
		uint8_t a = ((const uint8_t*)actual)[i];
		if (e != a) {
			/* Caller should issue the real log message. */
			llog_pexpect(logger, where,
				     "%s: %s: bytes at %zd differ, expected %02x found %02x",
				     desc, verifying, i, e, a);
			return false;
		}
	}
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s() %s: %s: ok", __func__, desc, verifying);
	}
	return true;
}

/* verify that expected is the same as actual */
bool verify_symkey(const char *desc, const char *verifying,
		   chunk_t expected, PK11SymKey *actual,
		   struct logger *logger, where_t where)
{
	if (expected.len != sizeof_symkey(actual)) {
		llog_pexpect(logger, where, "%s: %s: expected length %zd but got %zd",
			     desc, verifying, expected.len, sizeof_symkey(actual));
		return false;
	}
	chunk_t chunk = chunk_from_symkey(desc, actual, logger);
	bool ok = verify_hunk(desc, verifying, expected, chunk, logger, where);
	free_chunk_content(&chunk);
	return ok;
}

/*
 * Turn the raw key into SymKey.
 */
PK11SymKey *decode_to_key(const struct encrypt_desc *encrypt_desc,
			  const char *encoded_key,
			  struct logger *logger, where_t where)
{
	chunk_t raw_key = decode_to_chunk("raw_key", encoded_key, logger, where);
	PK11SymKey *symkey = encrypt_key_from_hunk("symkey", encrypt_desc, raw_key, logger);
	free_chunk_content(&raw_key);
	return symkey;
}
