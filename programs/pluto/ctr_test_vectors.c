/*
 * Copyright (C) 2014-2015 Andrew Cagney <cagney@gnu.org>
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
#include "ctr_test_vectors.h"

#include "nss.h"
#include "pk11pub.h"
#include "crypt_symkey.h"

static bool test_ctr_op(const struct encrypt_desc *encrypt_desc,
			const char *description, int encrypt,
			PK11SymKey *sym_key,
			const char *encoded_cb, const char *output_cb,
			const char *input_name, const char *input,
			const char *output_name, const char *output)
{
	const char *op = encrypt ? "encrypt" : "decrypt";

	bool ok = TRUE;
	chunk_t cb = decode_to_chunk("input counter-block: ", encoded_cb);
	chunk_t tmp = decode_to_chunk(input_name, input);
	chunk_t expected_output = decode_to_chunk(output_name, output);
	chunk_t expected_cb = decode_to_chunk("expected counter-block: ", output_cb);

	/* do_crypt modifies the data and IV in place.  */
	encrypt_desc->do_crypt(encrypt_desc, tmp.ptr, tmp.len,
			       sym_key, cb.ptr, encrypt);
	if (!verify_chunk(op, expected_output, tmp)) {
		DBG(DBG_CRYPT, DBG_log("test_ctr_op: %s: %s: output does not match", description, op));
		ok = FALSE;
	}
	if (!verify_chunk("counter-block", expected_cb, cb)) {
		DBG(DBG_CRYPT, DBG_log("test_ctr_op: %s: %s: counter-block does not match", description, op));
		ok = FALSE;
	}

	freeanychunk(cb);
	freeanychunk(expected_cb);
	freeanychunk(tmp);
	freeanychunk(expected_output);

	return ok;
}

static bool test_ctr_vector(const struct encrypt_desc *encrypt_desc,
			    const struct ctr_test_vector *test)
{
	DBG(DBG_CRYPT, DBG_log("test_ctr_vector: %s", test->description));
	bool ok = TRUE;

	PK11SymKey *sym_key = decode_to_key(encrypt_desc, test->key);
	if (!test_ctr_op(encrypt_desc, test->description, 1, sym_key,
			 test->cb, test->output_cb,
			 "Plaintext", test->plaintext,
			 "Ciphertext", test->ciphertext)) {
		ok = FALSE;
	}
	if (!test_ctr_op(encrypt_desc, test->description, 0, sym_key,
			 test->cb, test->output_cb,
			 "Ciphertext", test->ciphertext,
			 "Plaintext", test->plaintext)) {
		ok = FALSE;
	}

	/* Clean up.  */
	release_symkey(__func__, "sym_key", &sym_key);

	DBG(DBG_CRYPT, DBG_log("test_ctr_vector: %s %s",
			       test->description, ok ? "passed" : "failed"));
	return ok;
}

bool test_ctr_vectors(const struct encrypt_desc *encrypt_desc,
		      const struct ctr_test_vector *tests)
{
	bool ok = TRUE;
	const struct ctr_test_vector *test;
	for (test = tests; test->description != NULL; test++) {
		if (!test_ctr_vector(encrypt_desc, test)) {
			ok = FALSE;
		}
	}
	return ok;
}
