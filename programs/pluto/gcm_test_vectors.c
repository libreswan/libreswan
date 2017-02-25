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

static bool test_gcm_vector(const struct encrypt_desc *encrypt_desc,
			    const struct gcm_test_vector *test)
{
	DBG(DBG_CRYPT, DBG_log("test_gcm_vector: enter"));

	const size_t salt_size = encrypt_desc->salt_size;

	bool ok = TRUE;

	PK11SymKey *sym_key = decode_to_key(encrypt_desc, test->key);

	chunk_t salted_iv = decode_to_chunk("salted IV", test->salted_iv);
	passert(salted_iv.len == encrypt_desc->wire_iv_size + salt_size);
	chunk_t salt = { .ptr = salted_iv.ptr, .len = salt_size };
	chunk_t wire_iv = { .ptr = salted_iv.ptr + salt_size, .len = salted_iv.len - salt_size };

	chunk_t aad = decode_to_chunk("AAD", test->aad);
	chunk_t plaintext = decode_to_chunk("plaintext", test->plaintext);
	chunk_t ciphertext = decode_to_chunk("ciphertext", test->ciphertext);
	passert(plaintext.len == ciphertext.len);
	size_t len = plaintext.len;
	chunk_t tag = decode_to_chunk("tag", test->tag);

	chunk_t text_and_tag;
	text_and_tag.len = len + tag.len;
	text_and_tag.ptr = alloc_bytes(text_and_tag.len, "GCM data");

	/* macro to test encryption or decryption
	 *
	 * This would be better as a function but it uses too many locals
	 * from test_gcm_vector to be pleasant:
	 *	text_and_tag, len, tag, aad, salt, wire_iv, sym_key
	 */
#	define try(enc, desc, from, to) {  \
		memcpy(text_and_tag.ptr, from.ptr, from.len);  \
		text_and_tag.len = len + tag.len;  \
		DBG(DBG_CRYPT,  \
		    DBG_log("test_gcm_vector: %s: aad-size=%zd salt-size=%zd wire-IV-size=%zd text-size=%zd tag-size=%zd",  \
			    desc, aad.len, salt.len, wire_iv.len, len, tag.len);  \
		    DBG_dump_chunk("test_gcm_vector: text+tag on call",  \
				   text_and_tag));  \
		if (!encrypt_desc->do_aead_crypt_auth(encrypt_desc,  \
						      salt.ptr, salt.len,  \
						      wire_iv.ptr, wire_iv.len,  \
						      aad.ptr, aad.len,  \
						      text_and_tag.ptr,  \
						      len, tag.len,  \
						      sym_key, enc) ||  \
		    !verify_chunk_data("output ciphertext",  \
				   to, text_and_tag.ptr) ||  \
		    !verify_chunk_data("TAG", tag, text_and_tag.ptr + len))  \
			ok = FALSE;  \
		DBG(DBG_CRYPT, DBG_dump_chunk("test_gcm_vector: text+tag on return",  \
					      text_and_tag));  \
	}

	/* test decryption */
	memcpy(text_and_tag.ptr + len, tag.ptr, tag.len);
	try(FALSE, "decrypt", ciphertext, plaintext);

	/* test encryption */
	memset(text_and_tag.ptr + len, '\0', tag.len);
	try(TRUE, "encrypt", plaintext, ciphertext);

#	undef try

	freeanychunk(salted_iv);
	freeanychunk(aad);
	freeanychunk(plaintext);
	freeanychunk(ciphertext);
	freeanychunk(tag);
	freeanychunk(text_and_tag);

	/* Clean up.  */
	release_symkey(__func__, "sym_key", &sym_key);

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
