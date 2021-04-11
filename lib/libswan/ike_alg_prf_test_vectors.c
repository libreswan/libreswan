/*
 * Copyright (C) 2014-2019 Andrew Cagney <cagney@gnu.org>
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

#include "ike_alg.h"
#include "ike_alg_prf.h"
#include "test_buffer.h"
#include "ike_alg_test_prf.h"

#include "lswfips.h"
#include "pk11pub.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"

#include "lswlog.h"

/*
 * Ref: https://tools.ietf.org/html/rfc4435: Test Vectors
 */

const struct prf_test_vector aes_xcbc_prf_tests[] = {
	/* from RFC 3566 */
	{
		.description = "RFC 3566 Test Case 1: AES-XCBC-MAC-96 with 0-byte input",
		.key = "0x000102030405060708090a0b0c0d0e0f",
		.key_size = 16,
		.message = "",
		.prf_output = "0x75f0251d528ac01c4573dfd584d79f29",
		/* AES-XCBC-MAC-96: 75f0251d528ac01c4573dfd5 */
	},
	{
		.description = "RFC 3566 Test Case 2: AES-XCBC-MAC-96 with 3-byte input",
		.key = "0x000102030405060708090a0b0c0d0e0f",
		.key_size = 16,
		.message = "0x000102",
		.prf_output = "0x5b376580ae2f19afe7219ceef172756f",
		/* AES-XCBC-MAC-96: 5b376580ae2f19afe7219cee */
	},
	{
		.description = "RFC 3566 Test Case 3: AES-XCBC-MAC-96 with 16-byte input",
		.key = "0x000102030405060708090a0b0c0d0e0f",
		.key_size = 16,
		.message = "0x000102030405060708090a0b0c0d0e0f",
		.prf_output = "0xd2a246fa349b68a79998a4394ff7a263",
		/* AES-XCBC-MAC-96: d2a246fa349b68a79998a439 */
	},
	{
		.description = "RFC 3566 Test Case 4: AES-XCBC-MAC-96 with 20-byte input",
		.key = "0x000102030405060708090a0b0c0d0e0f",
		.key_size = 16,
		.message = "0x000102030405060708090a0b0c0d0e0f10111213",
		.prf_output = "0x47f51b4564966215b8985c63055ed308",
		/* AES-XCBC-MAC-96: 47f51b4564966215b8985c63 */
	},
	{
		.description = "RFC 3566 Test Case 5: AES-XCBC-MAC-96 with 32-byte input",
		.key = "0x000102030405060708090a0b0c0d0e0f",
		.key_size = 16,
		.message = ("0x000102030405060708090a0b0c0d0e0f10111213141516171819"
			    "1a1b1c1d1e1f"),
		.prf_output = "0xf54f0ec8d2b9f3d36807734bd5283fd4",
		/* AES-XCBC-MAC-96: f54f0ec8d2b9f3d36807734b */
	},
	{
		.description = "RFC 3566 Test Case 6: AES-XCBC-MAC-96 with 34-byte input",
		.key = "0x000102030405060708090a0b0c0d0e0f",
		.key_size = 16,
		.message = ("0x000102030405060708090a0b0c0d0e0f10111213141516171819"
			    "1a1b1c1d1e1f2021"),
		.prf_output = "0xbecbb3bccdb518a30677d5481fb6b4d8",
		/* AES-XCBC-MAC-96: becbb3bccdb518a30677d548 */
	},
	{
		.description = "RFC 3566 Test Case 7: AES-XCBC-MAC-96 with 1000-byte input",
		.key = "0x000102030405060708090a0b0c0d0e0f",
		.key_size = 16,
		/* .message = "0x00000000000000000000 ... 00000000000000000000 [1000 bytes]", */
		.message_size = 1000,
		.prf_output = "0xf0dafee895db30253761103b5d84528f",
		/* AES-XCBC-MAC-96: f0dafee895db30253761103b */
	},
	/* from RFC 4434 */
	{
		.description = "RFC 4434 Test Case AES-XCBC-PRF-128 with 20-byte input (key length 16)",
		.key = "0x000102030405060708090a0b0c0d0e0f",
		.key_size = 16,
		.message = "0x000102030405060708090a0b0c0d0e0f10111213",
		.prf_output = "0x47f51b4564966215b8985c63055ed308",
	},
	{
		.description = "RFC 4434 Test Case AES-XCBC-PRF-128 with 20-byte input (key length 10)",
		.key = "0x00010203040506070809",
		.key_size = 10,
		.message = "0x000102030405060708090a0b0c0d0e0f10111213",
		.prf_output = "0x0fa087af7d866e7653434e602fdde835",
	},
	{
		.description = "RFC 4434 Test Case AES-XCBC-PRF-128 with 20-byte input (key length 18)",
		.key = "0x000102030405060708090a0b0c0d0e0fedcb",
		.key_size = 18,
		.message = "0x000102030405060708090a0b0c0d0e0f10111213",
		.prf_output = "0x8cd3c93ae598a9803006ffb67c40e9e4",
	},
	{
		.description = NULL,
	}
};

const struct prf_test_vector hmac_md5_prf_tests[] = {
	{
		.description = "RFC 2104: MD5_HMAC test 1",
		.key = "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		.key_size = 16, /* bytes */
		.message = "Hi There",
		/* data_len =    8  bytes */
		.prf_output = "0x9294727a3638bb1c13f48ef8158bfc9d",
	},
	{
		.description = "RFC 2104: MD5_HMAC test 2",
		.key = "Jefe",
		.key_size = 4,
		.message = "what do ya want for nothing?",
		/* data_len =    28 bytes */
		.prf_output = "0x750c783e6ab0b503eaa86e310a5db738",
	},
	{
		.description = "RFC 2104: MD5_HMAC test 3",
		.key = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		.key_size = 16, /* bytes */
		.message = ("0xDDDDDDDDDDDDDDDDDDDD"
			    "DDDDDDDDDDDDDDDDDDDD"
			    "DDDDDDDDDDDDDDDDDDDD"
			    "DDDDDDDDDDDDDDDDDDDD"
			    "DDDDDDDDDDDDDDDDDDDD"),
		/* data_len =    50 bytes */
		.prf_output = "0x56be34521d144c88dbb8c733f0e8b3f6",
	},
	{
		.description = NULL,
	},
};

static bool test_prf_vector(const struct prf_desc *prf,
			    const struct prf_test_vector *test,
			    struct logger *logger)
{
	chunk_t chunk_key = decode_to_chunk(__func__, test->key);
	passert(chunk_key.len == test->key_size);
	chunk_t chunk_message = (test->message != NULL)
		? decode_to_chunk(__func__, test->message)
		: alloc_chunk(test->message_size, __func__);
	chunk_t prf_output = decode_to_chunk(__func__, test->prf_output);


	/* chunk interface */
	struct crypt_prf *chunk_prf = crypt_prf_init_hunk("PRF chunk interface", prf,
							  "key", chunk_key,
							  logger);
	crypt_prf_update_hunk(chunk_prf, "message", chunk_message);
	struct crypt_mac chunk_output = crypt_prf_final_mac(&chunk_prf, NULL);
	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("chunk output", chunk_output);
	}
	bool ok = verify_hunk(test->description, prf_output, chunk_output);

	/* symkey interface */
	PK11SymKey *symkey_key = symkey_from_hunk("key symkey", chunk_key, logger);
	struct crypt_prf *symkey_prf = crypt_prf_init_symkey("PRF symkey interface", prf,
							     "key symkey", symkey_key,
							     logger);
	PK11SymKey *symkey_message = symkey_from_hunk("message symkey",
						      chunk_message, logger);
	crypt_prf_update_symkey(symkey_prf, "symkey message", symkey_message);
	PK11SymKey *symkey_output = crypt_prf_final_symkey(&symkey_prf);
	if (DBGP(DBG_CRYPT)) {
		DBG_symkey(logger, "output", "symkey", symkey_output);
	}
	ok = verify_symkey(test->description, prf_output, symkey_output, logger);
	DBGF(DBG_CRYPT, "%s: %s %s", __func__, test->description, ok ? "passed" : "failed");
	release_symkey(__func__, "symkey", &symkey_output);

	free_chunk_content(&chunk_message);
	free_chunk_content(&chunk_key);

	release_symkey(__func__, "message", &symkey_message);
	release_symkey(__func__, "key", &symkey_key);
	release_symkey(__func__, "output", &symkey_output);

	free_chunk_content(&prf_output);
	return ok;
}

bool test_prf_vectors(const struct prf_desc *desc,
		      const struct prf_test_vector *tests,
		      struct logger *logger)
{
	bool ok = TRUE;
	for (const struct prf_test_vector *test = tests;
	     test->description != NULL; test++) {
		llog(RC_LOG, logger, "  %s", test->description);
		if (!test_prf_vector(desc, test, logger)) {
			ok = FALSE;
		}
	}
	return ok;
}
