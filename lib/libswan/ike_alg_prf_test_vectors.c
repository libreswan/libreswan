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

#include "fips_mode.h"
#include "pk11pub.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "ikev2_prf.h"

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
	chunk_t chunk_key = decode_to_chunk(__func__, test->key, logger, HERE);
	passert(chunk_key.len == test->key_size);
	chunk_t chunk_message =
		(test->message != NULL ? decode_to_chunk(__func__, test->message, logger, HERE) :
		 alloc_chunk(test->message_size, __func__));
	chunk_t prf_output = decode_to_chunk(__func__, test->prf_output, logger, HERE);
	bool ok = true;

	/* chunk interface */
	struct crypt_prf *chunk_prf = crypt_prf_init_hunk("PRF chunk interface", prf,
							  "key", chunk_key,
							  logger);
	crypt_prf_update_hunk(chunk_prf, "message", chunk_message);
	struct crypt_mac chunk_output = crypt_prf_final_mac(&chunk_prf, NULL);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "chunk output");
		LDBG_hunk(logger, chunk_output);
	}
	if (!verify_hunk(test->description, "prf OUT",
			 prf_output, chunk_output,
			 logger, HERE)) {
		ok = false;
	}

	/* symkey interface */
	PK11SymKey *symkey_key = symkey_from_hunk("key symkey", chunk_key, logger);
	struct crypt_prf *symkey_prf = crypt_prf_init_symkey("PRF symkey interface", prf,
							     "key symkey", symkey_key,
							     logger);
	PK11SymKey *symkey_message = symkey_from_hunk("message symkey",
						      chunk_message, logger);
	crypt_prf_update_symkey(symkey_prf, "symkey message", symkey_message);
	PK11SymKey *symkey_output = crypt_prf_final_symkey(&symkey_prf);
	if (LDBGP(DBG_CRYPT, logger)) {
		DBG_symkey(logger, "output", "symkey", symkey_output);
	}
	if (!verify_symkey(test->description, "symkey",
			   prf_output, symkey_output,
			   logger, HERE)) {
		ok = false;
	}
	ldbg(logger, "%s: %s %s", __func__, test->description, (ok ? "passed" : "failed"));

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
	bool ok = true;
	for (const struct prf_test_vector *test = tests;
	     test->description != NULL; test++) {
		llog(RC_LOG, logger, "  %s", test->description);
		if (!test_prf_vector(desc, test, logger)) {
			ok = false;
		}
	}
	return ok;
}

const struct kdf_test_vector hmac_sha1_kdf_tests[] = {
	{
		.description = "CAVP: IKEv2 key derivation with HMAC-SHA1",
		.ni = "0x32b50d5f4a3763f3",
		.ni_size = 8,
		.nr = "0x9206a04b26564cb1",
		.nr_size = 8,
		.gir = ("0x4b2c1f971981a8ad8d0abeafabf38cf7"
			"5fc8349c148142465ed9c8b516b8be52"),
		.gir_new = ("0x863f3c9d06efd39d2b907b97f8699e5d"
			    "d5251ef64a2a176f36ee40c87d4f9330"),
		.gir_size = 32,
		.spii = "0x34c9e7c188868785",
		.spir = "0x3ff77d760d2b2199",
		.skeyseed = "0xa9a7b222b59f8f48645f28a1db5b5f5d7479cba7",
		.skeyseed_rekey = "0x63e81194946ebd05df7df5ebf5d8750056bf1f1d",
		.dkm = ("0xa14293677cc80ff8f9cc0eee30d895da"
			"9d8f405666e30ef0dfcb63c634a46002"
			"a2a63080e514a062768b76606f9fa5e9"
			"92204fc5a670bde3f10d6b027113936a"
			"5c55b648a194ae587b0088d52204b702"
			"c979fa280870d2ed41efa9c549fd1119"
			"8af1670b143d384bd275c5f594cf266b"
			"05ebadca855e4249520a441a81157435"
			"a7a56cc4"),
		.dkm_size = 132,
	},
	{
		.description = NULL,
	}
};

static bool test_kdf_vector(const struct prf_desc *prf,
			    const struct kdf_test_vector *test,
			    struct logger *logger)
{
	chunk_t chunk_ni = decode_to_chunk(__func__, test->ni, logger, HERE);
	passert(chunk_ni.len == test->ni_size);
	chunk_t chunk_nr = decode_to_chunk(__func__, test->nr, logger, HERE);
	passert(chunk_nr.len == test->nr_size);
	chunk_t chunk_spii = decode_to_chunk(__func__, test->spii, logger, HERE);
	chunk_t chunk_spir = decode_to_chunk(__func__, test->spir, logger, HERE);
	chunk_t chunk_gir = decode_to_chunk(__func__, test->gir, logger, HERE);
	passert(chunk_gir.len == test->gir_size);
	chunk_t chunk_gir_new = decode_to_chunk(__func__, test->gir_new, logger, HERE);
	passert(chunk_gir_new.len == test->gir_size);
	chunk_t chunk_skeyseed = decode_to_chunk(__func__, test->skeyseed, logger, HERE);
	chunk_t chunk_skeyseed_rekey = decode_to_chunk(__func__, test->skeyseed_rekey, logger, HERE);
	chunk_t chunk_dkm = decode_to_chunk(__func__, test->dkm, logger, HERE);
	passert(chunk_dkm.len == test->dkm_size);
	bool ok = true;


	/* SKEYSEED = prf(Ni | Nr, g^ir) */
	PK11SymKey *gir = symkey_from_hunk("gir symkey", chunk_gir, logger);
	PK11SymKey *skeyseed = ikev2_ike_sa_skeyseed(prf, chunk_ni, chunk_nr,
						     gir, logger);
	if (!verify_symkey(test->description, "skeyseed",
			   chunk_skeyseed, skeyseed,
			   logger, HERE)) {
		ok = false;
	}

	/* prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr) */
	ike_spis_t spi_ir;
	passert(sizeof(spi_ir.initiator.bytes) == chunk_spii.len);
	memcpy(spi_ir.initiator.bytes, chunk_spii.ptr, chunk_spii.len);
	passert(sizeof(spi_ir.responder.bytes) == chunk_spir.len);
	memcpy(spi_ir.responder.bytes, chunk_spir.ptr, chunk_spir.len);
	PK11SymKey *dkm = ikev2_ike_sa_keymat(prf, skeyseed,
					      chunk_ni, chunk_nr,
					      &spi_ir,
					      test->dkm_size,
					      logger);

	if (!verify_symkey(test->description, "DKM",
			   chunk_dkm, dkm,
			   logger, HERE)) {
		ok = false;
	}

	/* SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr) */
	PK11SymKey *skd = key_from_symkey_bytes("SK_d", dkm,
                                                 0, prf->prf_key_size,
                                                 HERE, logger);
	PK11SymKey *gir_new = symkey_from_hunk("gir_new symkey", chunk_gir_new,
					       logger);
	PK11SymKey *skeyseed_rekey =
		ikev2_ike_sa_rekey_skeyseed(prf, skd, gir_new,
					    chunk_ni, chunk_nr,
					    logger);
	if (!verify_symkey(test->description, "skeyseed_rekey",
			   chunk_skeyseed_rekey, skeyseed_rekey,
			   logger, HERE)) {
		ok = false;
	}

	release_symkey(__func__, "gir", &gir);
	release_symkey(__func__, "gir_new", &gir_new);
	release_symkey(__func__, "skeyseed", &skeyseed);
	release_symkey(__func__, "dkm", &dkm);
	release_symkey(__func__, "skd", &skd);
	release_symkey(__func__, "skeyseed_rekey", &skeyseed_rekey);

	free_chunk_content(&chunk_ni);
	free_chunk_content(&chunk_nr);
	free_chunk_content(&chunk_gir);
	free_chunk_content(&chunk_gir_new);
	free_chunk_content(&chunk_spii);
	free_chunk_content(&chunk_spir);
	free_chunk_content(&chunk_skeyseed);
	free_chunk_content(&chunk_skeyseed_rekey);
	free_chunk_content(&chunk_dkm);

	ldbg(logger, "%s() %s: %s", __func__, test->description, (ok ? "passed" : "failed"));
	return ok;
}

bool test_kdf_vectors(const struct prf_desc *desc,
		      const struct kdf_test_vector *tests,
		      struct logger *logger)
{
	bool ok = true;
	for (const struct kdf_test_vector *test = tests;
	     test->description != NULL; test++) {
		llog(RC_LOG, logger, "  %s", test->description);
		if (!test_kdf_vector(desc, test, logger)) {
			ok = false;
		}
	}
	return ok;
}
