/*
 * Copyright (C) 2014,2016 Andrew Cagney <cagney@gnu.org>
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
#include "cbc_test_vectors.h"

#include "nss.h"
#include "pk11pub.h"
#include "crypt_symkey.h"

static bool test_cbc_op(const struct encrypt_desc *encrypt_desc,
			const char *description, int encrypt,
			PK11SymKey *sym_key, const char *encoded_iv,
			const char *input_name, const char *input,
			const char *output_name, const char *output)
{
	const char *op = encrypt ? "encrypt" : "decrypt";
	bool ok = TRUE;
	chunk_t iv = decode_to_chunk("IV: ", encoded_iv);

	/*
	 * If encrypting, the new iv is in the output, if decrypting,
	 * the new iv is the input.  The expected IV is found in the
	 * last few bytes.
	 */
	chunk_t expected_iv =
		decode_to_chunk("new IV: ", encrypt ? output : input);
	chunk_t tmp = decode_to_chunk(input_name, input);
	chunk_t expected = decode_to_chunk(output_name, output);

	/* do_crypt modifies the data and IV in place.  */
	encrypt_desc->do_crypt(encrypt_desc, tmp.ptr, tmp.len,
			       sym_key, iv.ptr, encrypt);

	if (!verify_chunk(op, expected, tmp)) {
		DBG(DBG_CRYPT, DBG_log("test_cbc_op: %s: %s: output does not match", description, op));
		ok = FALSE;
	}
	if (!verify_chunk_data("updated CBC IV", iv,
			   expected_iv.ptr + expected_iv.len - iv.len)) {
		DBG(DBG_CRYPT, DBG_log("test_cbc_op: %s: %s: IV does not match", description, op));
		ok = FALSE;
	}

	freeanychunk(iv);
	freeanychunk(expected_iv);
	freeanychunk(tmp);
	freeanychunk(expected);

	return ok;
}

/*
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/nss_sample_code/NSS_Sample_Code_sample2
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_Tech_Notes/nss_tech_note5
 */

static bool test_cbc_vector(const struct encrypt_desc *encrypt_desc,
			    const struct cbc_test_vector *test)
{
	bool ok = TRUE;
	DBG(DBG_CRYPT, DBG_log("test_cbc_vector: %s", test->description));

	PK11SymKey *sym_key = decode_to_key(encrypt_desc, test->key);
	if (!test_cbc_op(encrypt_desc, test->description, 1,
			 sym_key, test->iv,
			 "plaintext: ", test->plaintext,
			 "ciphertext: ", test->ciphertext)) {
		ok = FALSE;
	}
	if (!test_cbc_op(encrypt_desc, test->description, 0,
			 sym_key, test->iv,
			 "cipertext: ", test->ciphertext,
			 "plaintext: ", test->plaintext)) {
		ok = FALSE;
	}

	/* Clean up.  */
	free_any_symkey("sym_key", &sym_key);

	DBG(DBG_CRYPT, DBG_log("test_ctr_vector: %s %s",
			       test->description, ok ? "passed" : "failed"));
	return ok;
}

bool test_cbc_vectors(const struct encrypt_desc *encrypt_desc,
		      const struct cbc_test_vector *tests)
{
	bool ok = TRUE;
	const struct cbc_test_vector *test;
	for (test = tests; test->description != NULL; test++) {
		if (!test_cbc_vector(encrypt_desc, test)) {
			ok = FALSE;
		}
	}
	return ok;
}
