/*
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2016 Andrew Cagney <andrew.cagney@gmail.com>
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
#include "klips-crypto/aes_cbc.h"
#include "lswlog.h"
#include "ike_alg.h"

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>

#include "ike_alg_nss_cbc.h"
#include "ctr_test_vectors.h"
#include "cbc_test_vectors.h"
#include "gcm_test_vectors.h"
#include "ike_alg_aes.h"

#ifdef NOT_YET
static void aes_xcbc_init_thunk(union hash_ctx *ctx)
{
	aes_xcbc_init(&ctx->ctx_aes_xcbc);
}

static void aes_xcbc_write_thunk(union hash_ctx *ctx, const unsigned char *datap, size_t length)
{
	aes_xcbc_write(&ctx->ctx_aes_xcbc, datap, length);
}

static void aes_xcbc_final_thunk(u_char *hash, union hash_ctx *ctx)
{
	aes_xcbc_final(hash, &ctx->ctx_aes_xcbc);
}
#endif

/*
 * Ref: http://tools.ietf.org/html/rfc3602: Test Vectors
 */
static const struct cbc_test_vector aes_cbc_test_vectors[] = {
	{
		.description = "Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key",
		.key = "0x06a9214036b8a15b512e03d534120006",
		.iv = "0x3dafba429d9eb430b422da802c9fac41",
		.plaintext = "Single block msg",
		.ciphertext = "0xe353779c1079aeb82708942dbe77181a"
	},
	{
		.description = "Encrypting 32 bytes (2 blocks) using AES-CBC with 128-bit key",
		.key = "0xc286696d887c9aa0611bbb3e2025a45a",
		.iv = "0x562e17996d093d28ddb3ba695a2e6f58",
		.plaintext =
		"0x000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f",
		.ciphertext =
		"0xd296cd94c2cccf8a3a863028b5e1dc0a"
		"7586602d253cfff91b8266bea6d61ab1"
	},
	{
		.description = "Encrypting 48 bytes (3 blocks) using AES-CBC with 128-bit key",
		.key = "0x6c3ea0477630ce21a2ce334aa746c2cd",
		.iv = "0xc782dc4c098c66cbd9cd27d825682c81",
		.plaintext = "This is a 48-byte message (exactly 3 AES blocks)",
		.ciphertext =
		"0xd0a02b3836451753d493665d33f0e886"
		"2dea54cdb293abc7506939276772f8d5"
		"021c19216bad525c8579695d83ba2684"
	},
	{
		.description = "Encrypting 64 bytes (4 blocks) using AES-CBC with 128-bit key",
		.key = "0x56e47a38c5598974bc46903dba290349",
		.iv = "0x8ce82eefbea0da3c44699ed7db51b7d9",
		.plaintext =
		"0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
		"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
		.ciphertext =
		"0xc30e32ffedc0774e6aff6af0869f71aa"
		"0f3af07a9a31a9c684db207eb0ef8e4e"
		"35907aa632c3ffdf868bb7b29d3d46ad"
		"83ce9f9a102ee99d49a53e87f4c3da55"
	},
	{
		.description = NULL,
	}
};

static bool test_aes_cbc(const struct ike_alg *alg)
{
	return test_cbc_vectors((const struct encrypt_desc*)alg,
				 aes_cbc_test_vectors);
}

struct encrypt_desc ike_alg_encrypt_aes_cbc = {
	.common = {
		.name = "aes",
		.officname = "aes",
		.algo_type =   IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_AES_CBC,
		.ikev2_id = IKEv2_ENCR_AES_CBC,
		.fips =        TRUE,
		.do_ike_test = test_aes_cbc,
	},
	.enc_ctxsize =   sizeof(aes_context),
	.enc_blocksize = AES_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =       AES_CBC_BLOCK_SIZE,
	.keyminlen =    AES_KEY_MIN_LEN,
	.keydeflen =    AES_KEY_DEF_LEN,
	.keymaxlen =    AES_KEY_MAX_LEN,
	.nss_mechanism = CKM_AES_CBC,
	.do_crypt = ike_alg_nss_cbc,
};

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

static bool test_aes_ctr(const struct ike_alg *alg)
{
	return test_ctr_vectors((const struct encrypt_desc*)alg,
				aes_ctr_test_vectors);
}

static void do_aes_ctr(const struct encrypt_desc *alg UNUSED,
		       u_int8_t *buf, size_t buf_len, PK11SymKey *sym_key,
		       u_int8_t *counter_block, bool encrypt)
{
	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: enter"));

	passert(sym_key);
	if (sym_key == NULL) {
		loglog(RC_LOG_SERIOUS, "do_aes_ctr: NSS derived enc key in NULL");
		impossible();
	}

	CK_AES_CTR_PARAMS counter_param;
	counter_param.ulCounterBits = sizeof(u_int32_t) * 8;/* Per RFC 3686 */
	memcpy(counter_param.cb, counter_block, sizeof(counter_param.cb));
	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&counter_param;
	param.len = sizeof(counter_param);

	/* Output buffer for transformed data.  */
	u_int8_t *out_buf = PR_Malloc((PRUint32)buf_len);
	unsigned int out_len = 0;

	if (encrypt) {
		SECStatus rv = PK11_Encrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf_len,
					    buf, buf_len);
		if (rv != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_ctr: PK11_Encrypt failure (err %d)", PR_GetError());
			impossible();
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf_len,
					    buf, buf_len);
		if (rv != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_ctr: PK11_Decrypt failure (err %d)", PR_GetError());
			impossible();
		}
	}

	memcpy(buf, out_buf, buf_len);
	PR_Free(out_buf);

	/*
	 * Finally update the counter located at the end of the
	 * counter_block. It is incremented by 1 for every full or
	 * partial block encoded/decoded.
	 *
	 * There's a portability assumption here that the IV buffer is
	 * at least sizeof(u_int32_t) (4-byte) aligned.
	 */
	u_int32_t *counter = (u_int32_t*)(counter_block + AES_BLOCK_SIZE
					  - sizeof(u_int32_t));
	u_int32_t old_counter = ntohl(*counter);
	size_t increment = (buf_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	u_int32_t new_counter = old_counter + increment;
	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: counter-block updated from 0x%lx to 0x%lx for %zd bytes",
			       (unsigned long)old_counter, (unsigned long)new_counter, buf_len));
	if (new_counter < old_counter) {
		/* Wrap ... */
		loglog(RC_LOG_SERIOUS,
		       "do_aes_ctr: counter wrapped");
		/* what next??? */
	}
	*counter = htonl(new_counter);

	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: exit"));
}

struct encrypt_desc ike_alg_encrypt_aes_ctr =
{
	.common = {
		.name = "aes_ctr",
		.officname = "aes_ctr",
		.algo_type =   IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_AES_CTR,
		.ikev2_id = IKEv2_ENCR_AES_CTR,
		.fips =        TRUE,
		.do_ike_test = test_aes_ctr,
	},
	.enc_ctxsize =   sizeof(aes_context),
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	8,
	.salt_size = 4,
	.keyminlen =    AES_KEY_MIN_LEN,
	.keydeflen =    AES_KEY_DEF_LEN,
	.keymaxlen =    AES_KEY_MAX_LEN,
	.nss_mechanism = CKM_AES_CTR,
	.do_crypt =     do_aes_ctr,
};

static bool do_aes_gcm(const struct encrypt_desc *alg UNUSED,
		       u_int8_t *salt, size_t salt_size,
		       u_int8_t *wire_iv, size_t wire_iv_size,
		       u_int8_t *aad, size_t aad_size,
		       u_int8_t *text_and_tag,
		       size_t text_size, size_t tag_size,
		       PK11SymKey *sym_key, bool enc)
{
	/* See pk11gcmtest.c */
	bool ok = TRUE;

	u_int8_t iv[AES_BLOCK_SIZE];
	passert(sizeof iv >= wire_iv_size + salt_size);
	memcpy(iv, salt, salt_size);
	memcpy(iv + salt_size, wire_iv, wire_iv_size);

	CK_GCM_PARAMS gcm_params;
	gcm_params.pIv = iv;
	gcm_params.ulIvLen = salt_size + wire_iv_size;
	gcm_params.pAAD = aad;
	gcm_params.ulAADLen = aad_size;
	gcm_params.ulTagBits = tag_size * 8;

	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&gcm_params;
	param.len = sizeof gcm_params;

	/* Output buffer for transformed data.  */
	size_t text_and_tag_size = text_size + tag_size;
	u_int8_t *out_buf = PR_Malloc(text_and_tag_size);
	unsigned int out_len = 0;

	if (enc) {
		SECStatus rv = PK11_Encrypt(sym_key, CKM_AES_GCM, &param,
					    out_buf, &out_len, text_and_tag_size,
					    text_and_tag, text_size);
		if (rv != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_gcm: PK11_Encrypt failure (err %d)", PR_GetError());
			ok = FALSE;
		} else if (out_len != text_and_tag_size) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_gcm: PK11_Encrypt output length of %u not the expected %zd",
			       out_len, text_and_tag_size);
			ok = FALSE;
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_GCM, &param,
					    out_buf, &out_len, text_and_tag_size,
					    text_and_tag, text_and_tag_size);
		if (rv != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_gcm: PK11_Decrypt failure (err %d)", PR_GetError());
			ok = FALSE;
		} else if (out_len != text_size) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_gcm: PK11_Decrypt output length of %u not the expected %zd",
			       out_len, text_size);
			ok = FALSE;
		}
	}

	memcpy(text_and_tag, out_buf, out_len);
	PR_Free(out_buf);

	return ok;
}

/*
 * Ref: http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 *
 * some select entries
 */
static const struct gcm_test_vector aes_gcm_test_vectors[] = {
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

static bool test_aes_gcm(const struct ike_alg *alg)
{
	return test_gcm_vectors((const struct encrypt_desc*)alg,
				aes_gcm_test_vectors);
}

struct encrypt_desc ike_alg_encrypt_aes_gcm_8 =
{
	.common = {
		.name = "aes_gcm",
		.officname = "aes_gcm",
		.algo_type =   IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_AES_GCM_8,
		.ikev2_id = IKEv2_ENCR_AES_GCM_8,
		.fips =        TRUE,
	},
	.enc_ctxsize =   sizeof(aes_context),
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	8,
	.salt_size = AES_GCM_SALT_BYTES,
	.keyminlen =    AES_GCM_KEY_MIN_LEN,
	.keydeflen =    AES_GCM_KEY_DEF_LEN,
	.keymaxlen =    AES_GCM_KEY_MAX_LEN,
	.aead_tag_size = 8,
	.nss_mechanism = CKM_AES_GCM,
	.do_aead_crypt_auth =     do_aes_gcm,
};

struct encrypt_desc ike_alg_encrypt_aes_gcm_12 =
{
	.common = {
		.name = "aes_gcm_12",
		.officname = "aes_gcm_12",
		.algo_type =   IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_AES_GCM_12,
		.ikev2_id = IKEv2_ENCR_AES_GCM_12,
		.fips =        TRUE,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	.salt_size = AES_GCM_SALT_BYTES,
	.keyminlen =     AEAD_AES_KEY_MIN_LEN,
	.keydeflen =     AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =     AEAD_AES_KEY_MAX_LEN,
	.aead_tag_size = 12,
	.nss_mechanism = CKM_AES_GCM,
	.do_aead_crypt_auth =     do_aes_gcm,
};

struct encrypt_desc ike_alg_encrypt_aes_gcm_16 =
{
	.common = {
		.name = "aes_gcm_16",
		.officname = "aes_gcm_16",
		.algo_type =  IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_AES_GCM_16,
		.ikev2_id = IKEv2_ENCR_AES_GCM_16,
		.fips =        TRUE,
		.do_ike_test = test_aes_gcm,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	.salt_size = AES_GCM_SALT_BYTES,
	.keyminlen =    AEAD_AES_KEY_MIN_LEN,
	.keydeflen =    AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =    AEAD_AES_KEY_MAX_LEN,
	.aead_tag_size = 16,
	.nss_mechanism = CKM_AES_GCM,
	.do_aead_crypt_auth =     do_aes_gcm,
};

struct encrypt_desc ike_alg_encrypt_aes_ccm_8 =
{
	.common = {
		.name = "aes_ccm_8",
		.officname = "aes_ccm_8",
		.algo_type =    IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_AES_CCM_8,
		.ikev2_id = IKEv2_ENCR_AES_CCM_8,
		.fips =         TRUE,
		.do_ike_test = NULL,
	},
	.enc_blocksize =  AES_BLOCK_SIZE,
	.wire_iv_size =  8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keyminlen =      AEAD_AES_KEY_MIN_LEN,
	.keydeflen =      AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =      AEAD_AES_KEY_MAX_LEN,
#ifdef NOT_YET
	.nss_mechanism = CKM_AES_CCM,
#endif
};

struct encrypt_desc ike_alg_encrypt_aes_ccm_12 =
{
	.common = {
		.name = "aes_ccm_12",
		.officname = "aes_ccm_12",
		.algo_type =    IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_AES_CCM_12,
		.ikev2_id = IKEv2_ENCR_AES_CCM_12,
		.fips =         TRUE,
		.do_ike_test = NULL,
	},
	.enc_blocksize =  AES_BLOCK_SIZE,
	.wire_iv_size =  8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keyminlen =      AEAD_AES_KEY_MIN_LEN,
	.keydeflen =      AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =      AEAD_AES_KEY_MAX_LEN,
#ifdef NOT_YET
	.nss_mechanism = CKM_AES_CCM,
#endif
};

struct encrypt_desc ike_alg_encrypt_aes_ccm_16 =
{
	.common = {
		.name = "aes_ccm_16",
		.officname = "aes_ccm_16",
		.algo_type =   IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_AES_CCM_16,
		.ikev2_id = IKEv2_ENCR_AES_CCM_16,
		.fips =         TRUE,
		.do_ike_test = NULL,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keyminlen =     AEAD_AES_KEY_MIN_LEN,
	.keydeflen =     AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =     AEAD_AES_KEY_MAX_LEN,
#ifdef NOT_YET
	.nss_mechanism = CKM_AES_CCM,
#endif
};

struct integ_desc ike_alg_integ_aes_xcbc = {
	.common = {
		.name = "aes_xcbc",
		.officname =  "aes_xcbc",
		.algo_type = IKE_ALG_INTEG,
		.ikev1_oakley_id = OAKLEY_AES_XCBC, /* stolen from IKEv2 */
		.ikev1_esp_id = AUTH_ALGORITHM_AES_XCBC,
		.ikev2_id = IKEv2_AUTH_AES_XCBC_96,
		.fips = TRUE,
		.do_ike_test = NULL, /* No NSS support */
	},
#ifdef NOT_IMPLMENTED
	.hash_ctx_size = sizeof(aes_xcbc_context),
	.hash_key_size = AES_XCBC_DIGEST_SIZE,
	.hash_digest_len = AES_XCBC_DIGEST_SIZE,
	.hash_block_size = AES_CBC_BLOCK_SIZE,
	.hash_init = aes_xcbc_init_thunk,
	.hash_update = aes_xcbc_write_thunk,
	.hash_final = aes_xcbc_final_thunk,
#endif
	.integ_key_size = AES_XCBC_DIGEST_SIZE,
	.integ_output_size = AES_XCBC_DIGEST_SIZE_TRUNC, /* XXX 96 */
};

struct integ_desc ike_alg_integ_aes_cmac = {
	.common = {
		.name = "aes_cmac",
		.officname =  "aes_cmac",
		.algo_type = IKE_ALG_INTEG,
#ifdef NOT_IMPLMENTED
		/* not supported */
		.ikev1_oakley_id = AUTH_ALGORITHM_AES_CMAC_96,
#endif
		.ikev1_esp_id = AUTH_ALGORITHM_AES_CMAC_96,
		.ikev2_id = IKEv2_AUTH_AES_CMAC_96,
		.fips = TRUE,
		.do_ike_test = NULL, /* No NSS support */
	},
#if 0
	.hash_key_size = BYTES_FOR_BITS(128),
	.hash_digest_len = BYTES_FOR_BITS(128),
	.hash_block_size = BYTES_FOR_BITS(128),
	/* not implemented */
	.hash_ctx_size = sizeof(aes_cmac_context),
	.hash_init = aes_cmac_init_thunk,
	.hash_update = aes_cmac_write_thunk,
	.hash_final = aes_cmac_final_thunk,
#endif
	.integ_key_size = BYTES_FOR_BITS(128),
	.integ_output_size = BYTES_FOR_BITS(96), /* truncated */
};
