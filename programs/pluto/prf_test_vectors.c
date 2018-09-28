/*
 * Copyright (C) 2014,2016-2017 Andrew Cagney
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
#include "lswlog.h"

#include "ike_alg.h"
#include "ike_alg_prf.h"
#include "test_buffer.h"
#include "ike_alg_test_prf.h"

#include "lswfips.h"
#include "nss.h"
#include "pk11pub.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"

/*
 * Ref: https://tools.ietf.org/html/rfc4435: Test Vectors
 */

const struct prf_test_vectors aes_xcbc_prf_tests = {
	.prf = &ike_alg_prf_aes_xcbc,
	.tests = {
		/* from RFC 3566 */
		{
			.description = "Test Case #1   : AES-XCBC-MAC-96 with 0-byte input",
			.key = "0x000102030405060708090a0b0c0d0e0f",
			.key_size = 16,
			.message = "",
			.prf_output = "0x75f0251d528ac01c4573dfd584d79f29",
			/* AES-XCBC-MAC-96: 75f0251d528ac01c4573dfd5 */
		},
		{
			.description = " Test Case #2   : AES-XCBC-MAC-96 with 3-byte input",
			.key = "0x000102030405060708090a0b0c0d0e0f",
			.key_size = 16,
			.message = "0x000102",
			.prf_output = "0x5b376580ae2f19afe7219ceef172756f",
			/* AES-XCBC-MAC-96: 5b376580ae2f19afe7219cee */
		},
		{
			.description = " Test Case #3   : AES-XCBC-MAC-96 with 16-byte input",
			.key = "0x000102030405060708090a0b0c0d0e0f",
			.key_size = 16,
			.message = "0x000102030405060708090a0b0c0d0e0f",
			.prf_output = "0xd2a246fa349b68a79998a4394ff7a263",
			/* AES-XCBC-MAC-96: d2a246fa349b68a79998a439 */
		},
		{
			.description = " Test Case #4   : AES-XCBC-MAC-96 with 20-byte input",
			.key = "0x000102030405060708090a0b0c0d0e0f",
			.key_size = 16,
			.message = "0x000102030405060708090a0b0c0d0e0f10111213",
			.prf_output = "0x47f51b4564966215b8985c63055ed308",
			/* AES-XCBC-MAC-96: 47f51b4564966215b8985c63 */
		},
		{
			.description = " Test Case #5   : AES-XCBC-MAC-96 with 32-byte input",
			.key = "0x000102030405060708090a0b0c0d0e0f",
			.key_size = 16,
			.message = ("0x000102030405060708090a0b0c0d0e0f10111213141516171819"
				    "1a1b1c1d1e1f"),
			.prf_output = "0xf54f0ec8d2b9f3d36807734bd5283fd4",
			/* AES-XCBC-MAC-96: f54f0ec8d2b9f3d36807734b */
		},
		{
			.description = " Test Case #6   : AES-XCBC-MAC-96 with 34-byte input",
			.key = "0x000102030405060708090a0b0c0d0e0f",
			.key_size = 16,
			.message = ("0x000102030405060708090a0b0c0d0e0f10111213141516171819"
				    "1a1b1c1d1e1f2021"),
			.prf_output = "0xbecbb3bccdb518a30677d5481fb6b4d8",
			/* AES-XCBC-MAC-96: becbb3bccdb518a30677d548 */
		},
		{
			.description = " Test Case #7   : AES-XCBC-MAC-96 with 1000-byte input",
			.key = "0x000102030405060708090a0b0c0d0e0f",
			.key_size = 16,
			/* .message = "0x00000000000000000000 ... 00000000000000000000 [1000 bytes]", */
			.message_size = 1000,
			.prf_output = "0xf0dafee895db30253761103b5d84528f",
			/* AES-XCBC-MAC-96: f0dafee895db30253761103b */
		},
		/* from RFC 4434 */
		{
			.description = "Test Case AES-XCBC-PRF-128 with 20-byte input (key length 16)",
			.key = "0x000102030405060708090a0b0c0d0e0f",
			.key_size = 16,
			.message = "0x000102030405060708090a0b0c0d0e0f10111213",
			.prf_output = "0x47f51b4564966215b8985c63055ed308",
		},
		{
			.description = "Test Case AES-XCBC-PRF-128 with 20-byte input (key length 10)",
			.key = "0x00010203040506070809",
			.key_size = 10,
			.message = "0x000102030405060708090a0b0c0d0e0f10111213",
			.prf_output = "0x0fa087af7d866e7653434e602fdde835",
		},
		{
			.description = "Test Case AES-XCBC-PRF-128 with 20-byte input (key length 18)",
			.key = "0x000102030405060708090a0b0c0d0e0fedcb",
			.key_size = 18,
			.message = "0x000102030405060708090a0b0c0d0e0f10111213",
			.prf_output = "0x8cd3c93ae598a9803006ffb67c40e9e4",
		},
		{
			.description = NULL,
		}
	},
};

static bool test_prf_vector(const struct prf_desc *prf,
			    const struct prf_test_vector *test,
			    lset_t debug)
{
	DBG(debug, DBG_log("%s: %s", __func__, test->description));

	chunk_t chunk_key = decode_to_chunk(__func__, test->key);
	passert(chunk_key.len == test->key_size);
	chunk_t chunk_message = (test->message != NULL)
		? decode_to_chunk(__func__, test->message)
		: alloc_chunk(test->message_size, __func__);
	chunk_t prf_output = decode_to_chunk(__func__, test->prf_output);


	/* chunk interface */
	struct crypt_prf *chunk_prf = crypt_prf_init_chunk(__func__, debug,
							   prf, "key", chunk_key);
	crypt_prf_update_chunk(__func__, chunk_prf, chunk_message);
	chunk_t chunk_output = crypt_prf_final_chunk(&chunk_prf);
	DBG(debug, DBG_dump_chunk("chunk output", chunk_output));
	bool ok = verify_chunk(test->description, prf_output, chunk_output);
	freeanychunk(chunk_output);

	/* symkey interface */
	PK11SymKey *symkey_key = symkey_from_chunk("key symkey", chunk_key);
	struct crypt_prf *symkey_prf = crypt_prf_init_symkey(__func__, debug,
							    prf, "key symkey", symkey_key);
	PK11SymKey *symkey_message = symkey_from_chunk("message symkey",
						       chunk_message);
	crypt_prf_update_symkey(__func__, symkey_prf, symkey_message);
	PK11SymKey *symkey_output = crypt_prf_final_symkey(&symkey_prf);
	DBG(debug, DBG_symkey("output", "symkey", symkey_output));
	ok = verify_symkey(test->description, prf_output, symkey_output);
	DBG(debug, DBG_log("%s: %s %s", __func__,
			   test->description, ok ? "passed" : "failed"));
	release_symkey(__func__, "symkey", &symkey_output);

	freeanychunk(chunk_message);
	freeanychunk(chunk_key);
	freeanychunk(chunk_output);

	release_symkey(__func__, "message", &symkey_message);
	release_symkey(__func__, "key", &symkey_key);
	release_symkey(__func__, "output", &symkey_output);

	freeanychunk(prf_output);
	return ok;
}

bool test_prf_vectors(const struct prf_test_vectors *tests)
{
	if (libreswan_fipsmode() && !tests->prf->common.fips) {
		return true;
	}
	bool ok = TRUE;
	for (const struct prf_test_vector *test = tests->tests;
	     test->description != NULL; test++) {
		if (!test_prf_vector(tests->prf, test, DBG_CRYPT)) {
			ok = FALSE;
		}
	}
	return ok;
}
