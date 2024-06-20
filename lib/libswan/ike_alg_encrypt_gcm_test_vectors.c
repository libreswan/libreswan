/*
 * Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <stdlib.h>
#include "constants.h"
#include "lswalloc.h"
#include "fips_mode.h"

#include "ike_alg.h"
#include "test_buffer.h"
#include "ike_alg_test_gcm.h"
#include "ike_alg_encrypt_ops.h"	/* XXX: oops */

#include "pk11pub.h"
#include "crypt_symkey.h"

#include "lswlog.h"

/*
 * Ref: http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 *
 * some select entries
 */
static const struct gcm_test_vector aes_gcm_test_vectors[] = {
	{
		.description = "empty string",
		.key ="0xcf063a34d4a9a76c2c86787d3f96db71",
		.salted_iv = "0x113b9785971864c83b01c787",
		.ciphertext = "",
		.aad = "",
		.tag = "0x72ac8493e3a5228b5d130a69d2510e42",
		.plaintext = ""
	},
	{
		.description = "one block",
		.key = "0xe98b72a9881a84ca6b76e0f43e68647a",
		.salted_iv = "0x8b23299fde174053f3d652ba",
		.ciphertext = "0x5a3c1cf1985dbb8bed818036fdd5ab42",
		.aad = "",
		.tag = "0x23c7ab0f952b7091cd324835043b5eb5",
		.plaintext = "0x28286a321293253c3e0aa2704a278032",
	},
	{
		.description = "two blocks",
		.key = "0xbfd414a6212958a607a0f5d3ab48471d",
		.salted_iv = "0x86d8ea0ab8e40dcc481cd0e2",
		.ciphertext = "0x62171db33193292d930bf6647347652c1ef33316d7feca99d54f1db4fcf513f8",
		.aad = "",
		.tag = "0xc28280aa5c6c7a8bd366f28c1cfd1f6e",
		.plaintext = "0xa6b76a066e63392c9443e60272ceaeb9d25c991b0f2e55e2804e168c05ea591a",
	},
	{
		.description = "two blocks with associated data",
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
const struct gcm_test_vector *const aes_gcm_tests = aes_gcm_test_vectors;

static bool test_gcm_vector(const struct encrypt_desc *encrypt_desc,
			    const struct gcm_test_vector *test,
			    struct logger *logger)
{
	const size_t salt_size = encrypt_desc->salt_size;

	bool ok = true;

	PK11SymKey *sym_key = decode_to_key(encrypt_desc, test->key, logger);

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
#	define try(CRYPT, FROM, TO)					\
	{								\
		memcpy(text_and_tag.ptr, FROM.ptr, FROM.len);		\
		text_and_tag.len = len + tag.len;			\
		if (DBGP(DBG_CRYPT)) {					\
			DBG_log("test_gcm_vector: %s: aad-size=%zd salt-size=%zd wire-IV-size=%zd text-size=%zd tag-size=%zd", \
				#CRYPT, aad.len, salt.len, wire_iv.len, len, tag.len); \
			DBG_dump_hunk("test_gcm_vector: text+tag on call", \
				      text_and_tag);			\
		}							\
		if (!encrypt_desc->encrypt_ops				\
		    ->do_aead(encrypt_desc,				\
			      HUNK_AS_SHUNK(salt),			\
			      wire_iv,					\
			      HUNK_AS_SHUNK(aad),			\
			      text_and_tag,				\
			      plaintext.len, tag.len,			\
			      sym_key,					\
			      CRYPT,					\
			      logger) ||				\
		    !verify_bytes("output ciphertext",			\
				  TO.ptr, TO.len,			\
				  text_and_tag.ptr, TO.len) ||		\
		    !verify_bytes("TAG", tag.ptr, tag.len,		\
				  text_and_tag.ptr + len, tag.len))	\
			ok = false;					\
		if (DBGP(DBG_CRYPT)) {					\
			DBG_dump_hunk("test_gcm_vector: text+tag on return", \
				      text_and_tag);			\
		}							\
	}

	/* test decryption */
	memcpy(text_and_tag.ptr + len, tag.ptr, tag.len);
	try(DECRYPT, ciphertext, plaintext);

	/* test encryption */
	memset(text_and_tag.ptr + len, '\0', tag.len);
	try(ENCRYPT, plaintext, ciphertext);

#	undef try

	free_chunk_content(&salted_iv);
	free_chunk_content(&aad);
	free_chunk_content(&plaintext);
	free_chunk_content(&ciphertext);
	free_chunk_content(&tag);
	free_chunk_content(&text_and_tag);

	/* Clean up. */
	release_symkey(__func__, "sym_key", &sym_key);

	ldbgf(DBG_CRYPT, logger, "test_gcm_vector: %s", ok ? "passed" : "failed");
	return ok;
}

bool test_gcm_vectors(const struct encrypt_desc *desc,
		      const struct gcm_test_vector *tests,
		      struct logger *logger)
{
	bool ok = true;
	const struct gcm_test_vector *test;
	for (test = tests; test->key != NULL; test++) {
		llog(RC_LOG, logger, "  %s", test->description);
		if (!test_gcm_vector(desc, test, logger)) {
			ok = false;
		}
	}
	return ok;
}
