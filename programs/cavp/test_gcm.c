/*
 * CAVP GCM test functions, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include <pk11pub.h>
#include <blapit.h>

#include "lswalloc.h"
#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "crypt_cipher.h"
#include "crypt_symkey.h"
#include "ike_alg_encrypt_ops.h"

#include "cavp.h"
#include "cavp_entry.h"
#include "cavp_print.h"
#include "test_gcm.h"


static unsigned long keylen;
static unsigned long ivlen;
static unsigned long ptlen;
static unsigned long aadlen;
static unsigned long taglen;

static struct cavp_entry config[] = {
	{ .key = "Keylen", .op = op_unsigned_long, .unsigned_long = &keylen, },
	{ .key = "IVlen", .op = op_unsigned_long, .unsigned_long = &ivlen, },
	{ .key = "PTlen", .op = op_unsigned_long, .unsigned_long = &ptlen, },
	{ .key = "AADlen", .op = op_unsigned_long, .unsigned_long = &aadlen, },
	{ .key = "Taglen", .op = op_unsigned_long, .unsigned_long = &taglen, },
	{ .key = NULL, },
};

static void gcm_print_config(void)
{
	config_number("Keylen", keylen);
	config_number("IVlen", ivlen);
	config_number("PTlen", ptlen);
	config_number("AADlen", aadlen);
	config_number("Taglen", taglen);
}

static unsigned long count;
static PK11SymKey *key;
static chunk_t iv;
static chunk_t ct;
static chunk_t aad;
static chunk_t tag;

static struct cavp_entry data[] = {
	{ .key = "Count", .op = op_unsigned_long, .unsigned_long = &count, },
	{ .key = "Key", .op = op_symkey, .symkey = &key, },
	{ .key = "IV", .op = op_chunk, .chunk = &iv, },
	{ .key = "CT", .op = op_chunk, .chunk = &ct, },
	{ .key = "AAD", .op = op_chunk, .chunk = &aad, },
	{ .key = "Tag", .op = op_chunk, .chunk = &tag, },
	{ .key = "PT", .op = op_ignore, },
	{ .key = "FAIL", .op = op_ignore, },
	{ .key = NULL, },
};

static struct encrypt_desc ike_alg_encrypt_aes_gcm_4 = {
	.common = {
		.fqn = "AES_GCM",
		.type =   IKE_ALG_ENCRYPT,
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_AES_GCM,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = false,
	.wire_iv_size =	8,
	.salt_size = AES_GCM_SALT_BYTES,
	.keydeflen = AES_GCM_KEY_DEF_LEN,
	.aead_tag_size = 4,
	.encrypt_ops = &ike_alg_encrypt_nss_aead_ops,
};

static struct encrypt_desc ike_alg_encrypt_aes_gcm_13 = {
	.common = {
		.fqn = "AES_GCM",
		.type =   IKE_ALG_ENCRYPT,
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_AES_GCM,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = false,
	.wire_iv_size =	8,
	.salt_size = AES_GCM_SALT_BYTES,
	.keydeflen = AES_GCM_KEY_DEF_LEN,
	.aead_tag_size = 13,
	.encrypt_ops = &ike_alg_encrypt_nss_aead_ops,
};

static struct encrypt_desc ike_alg_encrypt_aes_gcm_14 = {
	.common = {
		.fqn = "AES_GCM",
		.type =   IKE_ALG_ENCRYPT,
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_AES_GCM,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = false,
	.wire_iv_size =	8,
	.salt_size = AES_GCM_SALT_BYTES,
	.keydeflen = AES_GCM_KEY_DEF_LEN,
	.aead_tag_size = 14,
	.encrypt_ops = &ike_alg_encrypt_nss_aead_ops,
};

static struct encrypt_desc ike_alg_encrypt_aes_gcm_15 = {
	.common = {
		.fqn = "AES_GCM",
		.type =   IKE_ALG_ENCRYPT,
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_AES_GCM,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = false,
	.wire_iv_size =	8,
	.salt_size = AES_GCM_SALT_BYTES,
	.keydeflen = AES_GCM_KEY_DEF_LEN,
	.aead_tag_size = 15,
	.encrypt_ops = &ike_alg_encrypt_nss_aead_ops,
};

static const struct encrypt_desc *encrypts[] = {
	&ike_alg_encrypt_aes_gcm_4,
	&ike_alg_encrypt_aes_gcm_8,
	&ike_alg_encrypt_aes_gcm_12,
	&ike_alg_encrypt_aes_gcm_13,
	&ike_alg_encrypt_aes_gcm_14,
	&ike_alg_encrypt_aes_gcm_15,
	&ike_alg_encrypt_aes_gcm_16,
	NULL,
};

static const struct encrypt_desc *lookup_by_taglen(void) {
	for (const struct encrypt_desc **ep = encrypts; *ep != NULL; ep++) {
		if ((*ep)->aead_tag_size * BITS_IN_BYTE == taglen) {
			return *ep;
		}
	}
	return NULL;
}

static uint8_t a_byte;
static chunk_t salt = {
	.ptr = &a_byte,
	.len = 0,
};

static void gcm_run_test(struct logger *logger)
{
	print_number("Count", NULL, count);
	print_symkey("Key", NULL, key, 0, logger);
	print_chunk("IV", NULL, iv, 0);
	print_chunk("CT", NULL, ct, 0);
	print_chunk("AAD", NULL, aad, 0);
	print_chunk("Tag", NULL, tag, 0);
	const struct encrypt_desc *gcm_alg = lookup_by_taglen();
	if (gcm_alg == NULL) {
		fprintf(stderr, "taglen %lu not supported\n",
			taglen);
		return;
	}
	PK11SymKey *gcm_key = encrypt_key_from_symkey_bytes("GCM key", gcm_alg,
							    0, sizeof_symkey(key),
							    key,
							    HERE, logger);

	chunk_t text_and_tag = clone_hunk_hunk(ct, tag, "text-and-tag");

	bool result = cipher_aead(gcm_alg, DECRYPT, USE_WIRE_IV,
				  HUNK_AS_SHUNK(salt), iv,
				  HUNK_AS_SHUNK(aad),
				  text_and_tag,
				  ct.len, tag.len,
				  gcm_key,
				  logger);
	if (result) {
		/* plain text */
		chunk_t pt = {
			.ptr = text_and_tag.ptr,
			.len = ct.len,
		};
		print_chunk("PT", NULL, pt, 0);
	} else {
		print_line("FAIL");
	}
	symkey_delref(logger, "GCM-key", &gcm_key);
	free_chunk_content(&text_and_tag);
}

const struct cavp test_gcm = {
	.alias = "gcm",
	.description = "GCM",
	.print_config = gcm_print_config,
	.run_test = gcm_run_test,
	.config = config,
	.data = data,
	.match = {
		"GCM Decrypt",
		NULL,
	},
};
