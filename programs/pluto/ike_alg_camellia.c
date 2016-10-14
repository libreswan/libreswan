/*
 * Copyright (C) 2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Paul Wouters <paul@libreswan.org>
 *
 * Based on ike_alg_camellia.c
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
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <libreswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "crypto.h"
#include "alg_info.h"
#include "ike_alg.h"

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include "lswfips.h"
#include "lswlog.h"

#include "ike_alg_nss_cbc.h"
#include "cbc_test_vectors.h"
#include "ike_alg_camellia.h"

/*
 * https://tools.ietf.org/html/rfc4312
 * https://info.isl.ntt.co.jp/crypt/index.html
 * https://info.isl.ntt.co.jp/crypt/eng/camellia/dl/cryptrec/t_camellia.txt
 */
static const struct cbc_test_vector camellia_cbc_test_vectors[] = {
	{
		.description = "Camellia: 16 bytes with 128-bit key",
		.key = "0x" "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		.iv = "0x" "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		.plaintext = "0x" "80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		.ciphertext = "0x" "07 92 3A 39 EB 0A 81 7D 1C 4D 87 BD B8 2D 1F 1C"
	},
	{
		.description = "Camellia: 16 bytes with 128-bit key",
		.key = "0x" "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF",
		.iv = "0x" "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		.plaintext = "0x" "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 ",
		.ciphertext = "0x" "14 4D 2B 0F 50 0C 27 B7 EC 2C D1 2D 91 59 6F 37"
	},
	{
		.description = "Camellia: 16 bytes with 256-bit key",
		.key = "0x" "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		.iv = "0x" "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		.plaintext = "0x" "80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		.ciphertext = "0x" "B0 C6 B8 8A EA 51 8A B0 9E 84 72 48 E9 1B 1B 9D"
	},
	{
		.description = "Camellia: 16 bytes with 256-bit key",
		.key = "0x" "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00",
		.iv = "0x" "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		.plaintext = "0x" "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01",
		.ciphertext = "0x" "CC 39 FF EE 18 56 D3 EB 61 02 5E 93 21 9B 65 23 "
	},
	{
		.description = NULL,
	}
};

static void do_camellia_cbc(u_int8_t *buf, size_t buf_len, PK11SymKey *symkey,
			    u_int8_t *iv, bool enc)
{
	ike_alg_nss_cbc(CKM_CAMELLIA_CBC, &ike_alg_encrypt_camellia_cbc,
			buf, buf_len, symkey, iv, enc);
}

static bool test_camellia_cbc(const struct ike_alg *alg)
{
	return test_cbc_vectors((const struct encrypt_desc*)alg,
				camellia_cbc_test_vectors);
}

struct encrypt_desc ike_alg_encrypt_camellia_cbc =
{
	.common = {
		.name = "camellia",
		.officname = "camellia",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_CAMELLIA_CBC,
		.algo_v2id =   IKEv2_ENCR_CAMELLIA_CBC,
		.do_test =     test_camellia_cbc,
	},
	.enc_ctxsize =   sizeof(camellia_context),
	.enc_blocksize = CAMELLIA_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =       CAMELLIA_BLOCK_SIZE,
	.keyminlen =    CAMELLIA_KEY_MIN_LEN,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.keymaxlen =    CAMELLIA_KEY_MAX_LEN,
	.do_crypt =     do_camellia_cbc,
};

static void do_camellia_ctr(u_int8_t *buf UNUSED, size_t buf_len UNUSED, PK11SymKey *symkey UNUSED,
			    u_int8_t *nonce_iv UNUSED, bool enc UNUSED)
{
	DBG(DBG_CRYPT, DBG_log("NSS do_camellia_ctr: stubb only"));
}

struct encrypt_desc ike_alg_encrypt_camellia_ctr =
{
	.common = {
		.name = "camellia_ctr",
		.officname = "camellia_ctr",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_CAMELLIA_CTR,
		.algo_v2id =   IKEv2_ENCR_CAMELLIA_CTR,
	},
	.enc_ctxsize =   sizeof(camellia_context),
	.enc_blocksize = CAMELLIA_BLOCK_SIZE,
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	CAMELLIA_BLOCK_SIZE,
	.keyminlen =    CAMELLIA_KEY_MIN_LEN,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.keymaxlen =    CAMELLIA_KEY_MAX_LEN,
	.do_crypt =     do_camellia_ctr,
};
