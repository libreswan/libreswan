/*
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

struct gcm_test_vector {
	const char *key;
	/*
	 * NIST provides a simple IV, while we require a separate SALT
	 * and wire-IV.  The value gets split before being passed to
	 * the do_crypt_hash method.
	 */
	const char *salted_iv;
	const char *aad;
	const char *plaintext;
	const char *ciphertext;
	const char *tag;
};

const int salt_size = 4;

/*
 * Ref: http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 *
 * some select entries
 */
const struct gcm_test_vector aes_gcm_test_vectors[] = {
	{
		.key ="0xcf063a34d4a9a76c2c86787d3f96db71",
		.salted_iv = "0x113b9785971864c83b01c787",
		.ciphertext = "",
		.aad = "",
		.tag = "0x72ac8493e3a5228b5d130a69d2510e42",
		.plaintext = ""
	},
	{
		.key = "0xe98b72a9881a84ca6b76e0f43e68647a",
		.salted_iv = "0x8b23299fde174053f3d652ba",
		.ciphertext = "0x5a3c1cf1985dbb8bed818036fdd5ab42",
		.aad = "",
		.tag = "0x23c7ab0f952b7091cd324835043b5eb5",
		.plaintext = "0x28286a321293253c3e0aa2704a278032",
	},
	{
		.key = "0xbfd414a6212958a607a0f5d3ab48471d",
		.salted_iv = "0x86d8ea0ab8e40dcc481cd0e2",
		.ciphertext = "0x62171db33193292d930bf6647347652c1ef33316d7feca99d54f1db4fcf513f8",
		.aad = "",
		.tag = "0xc28280aa5c6c7a8bd366f28c1cfd1f6e",
		.plaintext = "0xa6b76a066e63392c9443e60272ceaeb9d25c991b0f2e55e2804e168c05ea591a",
	},
	{
		.key = "0x006c458100fc5f4d62949d2c833b82d1",
		.salted_iv = "0xa4e9c4bc5725a21ff42c82b2",
		.ciphertext = "0xf39b4db3542d8542fb73fd2d66be568f26d7f814b3f87d1eceac3dd09a8d697e",
		.aad = "0x2efb14fb3657cdd6b9a8ff1a5f5a39b9",
		.tag = "0x39f045cb23b698c925db134d56c5",
		.plaintext = "0xf381d3bfbee0a879f7a4e17b623278cedd6978053dd313530a18f1a836100950",
	},
	{
		.key = NULL,
	}
};

static bool test_gcm_vector(CK_MECHANISM_TYPE cipher_mechanism,
			    bool (*do_crypt_hash)(u_int8_t *salt, size_t salt_size,
						  u_int8_t *wire_iv, size_t wire_iv_size,
						  u_int8_t *aad, size_t aad_size,
						  u_int8_t *text_and_tag,
						  size_t text_size, size_t tag_size,
						  PK11SymKey *key, bool enc),
			    const struct gcm_test_vector *test)
{
	DBG(DBG_CRYPT, DBG_log("test_gcm_vector: enter"));

	bool ok = TRUE;

	PK11SymKey *sym_key = decode_to_key(cipher_mechanism, test->key);

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
		if (!do_crypt_hash(salt.ptr, salt.len,
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

static bool test_gcm_vectors(CK_MECHANISM_TYPE cipher_mechanism,
			     bool (*do_crypt_hash)(u_int8_t *salt, size_t salt_size,
						   u_int8_t *wire_iv, size_t wire_iv_size,
						   u_int8_t *aad, size_t aad_size,
						   u_int8_t *text_and_tag,
						   size_t text_size, size_t tag_size,
						   PK11SymKey *key, bool enc),
			     const struct gcm_test_vector *tests)
{
	bool ok = TRUE;
	const struct gcm_test_vector *test;
	for (test = tests; test->key != NULL; test++) {
		if (!test_gcm_vector(cipher_mechanism, do_crypt_hash, test)) {
			ok = FALSE;
		}
	}
	return ok;
}

bool test_aes_gcm(void)
{
	return test_gcm_vectors(CKM_AES_GCM, do_aes_gcm, aes_gcm_test_vectors);
}
