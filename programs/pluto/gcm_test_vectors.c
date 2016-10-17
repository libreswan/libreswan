/*
 * Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <stdlib.h>
#include "constants.h"
#include "lswalloc.h"
#include "lswlog.h"

#include "ike_alg.h"
#include "test_buffer.h"
#include "gcm_test_vectors.h"

#include "nss.h"
#include "pk11pub.h"
#include "crypt_symkey.h"

const int salt_size = 4;

static bool test_gcm_vector(const struct encrypt_desc *encrypt_desc,
			    const struct gcm_test_vector *test)
{
	DBG(DBG_CRYPT, DBG_log("test_gcm_vector: enter"));

	bool ok = TRUE;

	PK11SymKey *sym_key = decode_to_key(encrypt_desc, test->key);

	chunk_t salted_iv = decode_to_chunk("salted IV", test->salted_iv);
	chunk_t salt = extract_chunk("salt", salted_iv, 0, salt_size);
	chunk_t wire_iv = extract_chunk("wire-IV", salted_iv, salt_size,
					salted_iv.len - salt_size);
	chunk_t aad = decode_to_chunk("AAD", test->aad);
	chunk_t plaintext = decode_to_chunk("plaintext", test->plaintext);
	chunk_t ciphertext = decode_to_chunk("ciphertext", test->ciphertext);
	passert(plaintext.len == ciphertext.len);
	chunk_t tag = decode_to_chunk("tag", test->tag);

	chunk_t text_and_tag;
	text_and_tag.len = plaintext.len + tag.len;
	text_and_tag.ptr = alloc_bytes(text_and_tag.len, "GCM data");

	int enc;
	for (enc = 0; enc < 2; enc++) {
		u_int8_t *ptr = text_and_tag.ptr;
		chunkcpy(ptr, (enc ? plaintext : ciphertext));
		if (enc) {
			memset(ptr, 0, tag.len);
			ptr += tag.len;
		} else {
			chunkcpy(ptr, tag);
		}
		passert(ptr == text_and_tag.ptr + text_and_tag.len);

		DBG(DBG_CRYPT,
		    DBG_log("test_gcm_vector: %s: aad-size=%zd salt-size=%zd wire-IV-size=%zd text-size=%zd tag-size=%zd",
			    enc ? "encrypt" : "decrypt",
			    aad.len, salt.len, wire_iv.len, plaintext.len, tag.len);
		    DBG_dump_chunk("test_gcm_vector: text+tag on call",
				   text_and_tag));
		if (!encrypt_desc->do_aead_crypt_auth(salt.ptr, salt.len,
						      wire_iv.ptr, wire_iv.len,
						      aad.ptr, aad.len,
						      text_and_tag.ptr,
						      plaintext.len, tag.len,
						      sym_key, enc)) {
			ok = FALSE;
		}
		DBG(DBG_CRYPT, DBG_dump_chunk("test_gcm_vector: text+tag on return",
					      text_and_tag));

		size_t offset = 0;
		if (enc) {
			if (!compare_chunk("output ciphertext",
					   ciphertext, text_and_tag.ptr + offset)) {
				ok = FALSE;
			}
			offset += ciphertext.len;
		} else {
			if (!compare_chunk("output plaintext",
					   plaintext,  text_and_tag.ptr + offset)) {
				ok = FALSE;
			}
			offset += plaintext.len;
		}
		if (!compare_chunk("TAG", tag, text_and_tag.ptr + offset)) {
			ok = FALSE;
		}
		offset += tag.len;

		passert(offset == text_and_tag.len);
	}

	freeanychunk(salted_iv);
	freeanychunk(salt);
	freeanychunk(wire_iv);
	freeanychunk(aad);
	freeanychunk(plaintext);
	freeanychunk(ciphertext);
	freeanychunk(tag);
	freeanychunk(text_and_tag);

	/* Clean up.  */
	free_any_symkey("sym_key", &sym_key);

	DBG(DBG_CRYPT, DBG_log("test_gcm_vector: %s", ok ? "passed" : "failed"));
	return ok;
}

bool test_gcm_vectors(const struct encrypt_desc *encrypt_desc,
		      const struct gcm_test_vector *tests)
{
	bool ok = TRUE;
	const struct gcm_test_vector *test;
	for (test = tests; test->key != NULL; test++) {
		if (!test_gcm_vector(encrypt_desc, test)) {
			ok = FALSE;
		}
	}
	return ok;
}
