/*
 * Copyright (C) 2014-2015 Andrew Cagney <cagney@gnu.org>
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
#include "test_buffer.h"
#include "ike_alg_test_ctr.h"
#include "ike_alg_encrypt_ops.h"	/* XXX: oops */

#include "fips_mode.h"
#include "pk11pub.h"
#include "crypt_symkey.h"

#include "lswlog.h"

/*
 * Ref: https://tools.ietf.org/html/rfc3686 Test Vectors
 */
static const struct ctr_test_vector aes_ctr_test_vectors[] = {
	{
		.description = "Encrypting 16 octets using AES-CTR with 128-bit key",
		.key = "0x AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E",
		.plaintext = "0x 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67",
		.cb = "0x 00 00 00 30  00 00 00 00 00 00 00 00  00 00 00 01",
		.ciphertext = "0x E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8",
		.output_cb = "0x 00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 02",
	},
	{
		.description = "Encrypting 32 octets using AES-CTR with 128-bit key",
		.key = "0x 7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63",
		.plaintext = "0x"
		"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
		"10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F",
		.cb = "0x 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01",
		.ciphertext = "0x"
		"51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88"
		"EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28",
		.output_cb = "0x 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 03",
	},
	{
		.description = "Encrypting 36 octets using AES-CTR with 128-bit key",
		.key = "0x 76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC",
		.plaintext = "0x"
		"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
		"10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
		"20 21 22 23",
		.cb = "0x 00 E0 01 7B  27 77 7F 3F 4A 17 86 F0  00 00 00 01",
		.ciphertext = "0x"
		"C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7"
		"45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53"
		"25 B2 07 2F",
		.output_cb = "0x 00 E0 01 7B  27 77 7F 3F 4A 17 86 F0  00 00 00 04",
	},
	{
		.description = "Encrypting 16 octets using AES-CTR with 192-bit key",
		.key = "0x"
		"16 AF 5B 14 5F C9 F5 79 C1 75 F9 3E 3B FB 0E ED"
		"86 3D 06 CC FD B7 85 15",
		.plaintext = "0x 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67",
		.cb = "0x 00 00 00 48  36 73 3C 14 7D 6D 93 CB  00 00 00 01",
		.ciphertext = "0x 4B 55 38 4F E2 59 C9 C8 4E 79 35 A0 03 CB E9 28",
		.output_cb = "0x 00 00 00 48  36 73 3C 14 7D 6D 93 CB  00 00 00 02",
	},
	{
		.description = "Encrypting 32 octets using AES-CTR with 192-bit key",
		.key = "0x"
		"7C 5C B2 40 1B 3D C3 3C 19 E7 34 08 19 E0 F6 9C"
		"67 8C 3D B8 E6 F6 A9 1A",
		.plaintext = "0x"
		"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
		"10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F",
		.cb = "0x 00 96 B0 3B  02 0C 6E AD C2 CB 50 0D  00 00 00 01",
		.ciphertext = "0x"
		"45 32 43 FC 60 9B 23 32 7E DF AA FA 71 31 CD 9F"
		"84 90 70 1C 5A D4 A7 9C FC 1F E0 FF 42 F4 FB 00",
		.output_cb = "0x 00 96 B0 3B  02 0C 6E AD C2 CB 50 0D  00 00 00 03",
	},
	{
		.description = "Encrypting 36 octets using AES-CTR with 192-bit key",
		.key = "0x"
		"02 BF 39 1E E8 EC B1 59 B9 59 61 7B 09 65 27 9B"
		"F5 9B 60 A7 86 D3 E0 FE",
		.plaintext = "0x"
		"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
		"10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
		"20 21 22 23",
		.cb = "0x 00 07 BD FD  5C BD 60 27 8D CC 09 12  00 00 00 01",
		.ciphertext = "0x"
		"96 89 3F C5 5E 5C 72 2F 54 0B 7D D1 DD F7 E7 58"
		"D2 88 BC 95 C6 91 65 88 45 36 C8 11 66 2F 21 88"
		"AB EE 09 35",
		.output_cb = "0x 00 07 BD FD  5C BD 60 27 8D CC 09 12  00 00 00 04",
	},
	{
		.description = "Encrypting 16 octets using AES-CTR with 256-bit key",
		.key = "0x"
		"77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C"
		"6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04",
		.plaintext = "0x 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67",
		.cb = "0x 00 00 00 60  DB 56 72 C9 7A A8 F0 B2  00 00 00 01",
		.ciphertext = "0x 14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0",
		.output_cb = "0x 00 00 00 60  DB 56 72 C9 7A A8 F0 B2  00 00 00 02",
	},
	{
		.description = "Encrypting 32 octets using AES-CTR with 256-bit key",
		.key = "0x"
		"F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86"
		"C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84",
		.plaintext = "0x"
		"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
		"10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F",
		.cb = "0x 00 FA AC 24  C1 58 5E F1 5A 43 D8 75  00 00 00 01",
		.ciphertext = "0x"
		"F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9"
		"B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C",
		.output_cb = "0x 00 FA AC 24  C1 58 5E F1 5A 43 D8 75  00 00 00 03",
	},
	{
		.description = "Encrypting 36 octets using AES-CTR with 256-bit key",
		.key = "0x"
		"FF 7A 61 7C E6 91 48 E4 F1 72 6E 2F 43 58 1D E2"
		"AA 62 D9 F8 05 53 2E DF F1 EE D6 87 FB 54 15 3D",
		.plaintext = "0x"
		"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
		"10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
		"20 21 22 23",
		.cb = "0x 00 1C C5 B7  51 A5 1D 70 A1 C1 11 48  00 00 00 01",
		.ciphertext = "0x"
		"EB 6C 52 82 1D 0B BB F7 CE 75 94 46 2A CA 4F AA"
		"B4 07 DF 86 65 69 FD 07 F4 8C C0 B5 83 D6 07 1F"
		"1E C0 E6 B8",
		.output_cb = "0x 00 1C C5 B7  51 A5 1D 70 A1 C1 11 48  00 00 00 04",
	},
	{
		.description = NULL,
	}
};
const struct ctr_test_vector *const aes_ctr_tests = aes_ctr_test_vectors;

static bool test_ctr_op(const struct encrypt_desc *encrypt_desc,
			const char *description, int encrypt,
			PK11SymKey *sym_key,
			const char *encoded_cb, const char *output_cb,
			const char *input_name, const char *input,
			const char *output_name, const char *output,
			struct logger *logger)
{
	const char *op = encrypt ? "encrypt" : "decrypt";

	bool ok = true;
	chunk_t cb = decode_to_chunk("input counter-block: ", encoded_cb);
	chunk_t tmp = decode_to_chunk(input_name, input);
	chunk_t expected_output = decode_to_chunk(output_name, output);
	chunk_t expected_cb = decode_to_chunk("expected counter-block: ", output_cb);

	/* do_crypt modifies the data and IV in place. */
	encrypt_desc->encrypt_ops->do_crypt(encrypt_desc, tmp.ptr, tmp.len,
					    sym_key, cb.ptr, encrypt, logger);
	if (!verify_hunk(op, expected_output, tmp)) {
		ldbgf(DBG_CRYPT, logger,
		      "test_ctr_op: %s: %s: output does not match",
		      description, op);
		ok = false;
	}
	if (!verify_hunk("counter-block", expected_cb, cb)) {
		ldbgf(DBG_CRYPT, logger,
		      "test_ctr_op: %s: %s: counter-block does not match",
		      description, op);
		ok = false;
	}

	free_chunk_content(&cb);
	free_chunk_content(&expected_cb);
	free_chunk_content(&tmp);
	free_chunk_content(&expected_output);

	return ok;
}

static bool test_ctr_vector(const struct encrypt_desc *encrypt_desc,
			    const struct ctr_test_vector *test,
			    struct logger *logger)
{
	bool ok = true;

	PK11SymKey *sym_key = decode_to_key(encrypt_desc, test->key, logger);
	if (!test_ctr_op(encrypt_desc, test->description, 1, sym_key,
			 test->cb, test->output_cb,
			 "Plaintext", test->plaintext,
			 "Ciphertext", test->ciphertext,
			 logger)) {
		ok = false;
	}
	if (!test_ctr_op(encrypt_desc, test->description, 0, sym_key,
			 test->cb, test->output_cb,
			 "Ciphertext", test->ciphertext,
			 "Plaintext", test->plaintext,
			 logger)) {
		ok = false;
	}

	/* Clean up. */
	release_symkey(__func__, "sym_key", &sym_key);

	ldbgf(DBG_CRYPT, logger, "test_ctr_vector: %s %s",
	      test->description, ok ? "passed" : "failed");
	return ok;
}

bool test_ctr_vectors(const struct encrypt_desc *desc,
		      const struct ctr_test_vector *tests,
		      struct logger *logger)
{
	bool ok = true;
	const struct ctr_test_vector *test;
	for (test = tests; test->description != NULL; test++) {
		llog(RC_LOG, logger, "  %s", test->description);
		if (!test_ctr_vector(desc, test, logger)) {
			ok = false;
		}
	}
	return ok;
}
