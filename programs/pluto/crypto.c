/* crypto interfaces
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <libreswan.h>

#include <errno.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "log.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "alg_info.h"
#include "ike_alg.h"
#include "test_buffer.h"

#include "pem.h"

#include "lswfips.h"

#ifdef USE_3DES
static void do_3des(u_int8_t *buf, size_t buf_len, PK11SymKey *key,
		    u_int8_t *iv, bool enc);
static struct encrypt_desc crypto_encrypter_3des =
{
	.common = { .name = "oakley_3des_cbc",
		    .officname =     "3des",
		    .algo_type =     IKE_ALG_ENCRYPT,
		    .algo_id =       OAKLEY_3DES_CBC,
		    .algo_v2id =     IKEv2_ENCR_3DES,
		    .algo_next =     NULL, },
	.enc_ctxsize =      8 * 16 * 3, /* sizeof(des_key_schedule) * 3 */
	.enc_blocksize =    DES_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =           DES_CBC_BLOCK_SIZE,
	.keydeflen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.keyminlen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.keymaxlen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.do_crypt =         do_3des,
};
#endif

#ifdef USE_MD5

static void lsMD5Init_thunk(union hash_ctx *context)
{
	lsMD5Init(&context->ctx_md5);
}

static void lsMD5Update_thunk(union hash_ctx *context, const unsigned char *input, size_t inputLen)
{
	lsMD5Update(&context->ctx_md5, input, inputLen);
}

static void lsMD5Final_thunk(unsigned char digest[MD5_DIGEST_SIZE], union hash_ctx *context)
{
	lsMD5Final(digest, &context->ctx_md5);
}

static struct hash_desc crypto_hasher_md5 =
{
	.common = { .name = "oakley_md5",
		    .officname = "md5",
		    .algo_type = IKE_ALG_HASH,
		    .algo_id =   OAKLEY_MD5,
		    .algo_v2id = IKEv2_PRF_HMAC_MD5,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(lsMD5_CTX),
	.hash_key_size = MD5_DIGEST_SIZE,
	.hash_digest_len = MD5_DIGEST_SIZE,
	.hash_integ_len = 0,    /* Not applicable */
	.hash_block_size = 64,	/* B from RFC 2104 */
	.hash_init = lsMD5Init_thunk,
	.hash_update = lsMD5Update_thunk,
	.hash_final = lsMD5Final_thunk,
};

static struct hash_desc crypto_integ_md5 =
{
	.common = { .name = "oakley_md5",
		    .officname = "md5",
		    .algo_type = IKE_ALG_INTEG,
		    .algo_id =   OAKLEY_MD5,
		    .algo_v2id = IKEv2_AUTH_HMAC_MD5_96,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(lsMD5_CTX),
	.hash_key_size =   MD5_DIGEST_SIZE,
	.hash_digest_len = MD5_DIGEST_SIZE,
	.hash_integ_len = MD5_DIGEST_SIZE_96,
	.hash_block_size = 64,	/* B from RFC 2104 */
	.hash_init = lsMD5Init_thunk,
	.hash_update = lsMD5Update_thunk,
	.hash_final = lsMD5Final_thunk,
};
#endif

#ifdef USE_SHA1

static void SHA1Init_thunk(union hash_ctx *context)
{
	SHA1Init(&context->ctx_sha1);
}

static void SHA1Update_thunk(union hash_ctx *context, const unsigned char *input, size_t inputLen)
{
	SHA1Update(&context->ctx_sha1, input, inputLen);
}

static void SHA1Final_thunk(unsigned char digest[MD5_DIGEST_SIZE], union hash_ctx *context)
{
	SHA1Final(digest, &context->ctx_sha1);
}


/* Also used in nat_traversal.c.  I don't know how to call SHA1 by name.
 * RFC 5996 2.23 only allows "SHA-1 digest of the SPIs (in the order they appear
 * in the header), IP address, and port from which this packet was sent. "
 */
struct hash_desc crypto_hasher_sha1 =
{
	.common = { .name = "oakley_sha",
		    .officname = "sha1",
		    .algo_type = IKE_ALG_HASH,
		    .algo_id =   OAKLEY_SHA1,
		    .algo_v2id = IKEv2_PRF_HMAC_SHA1,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(SHA1_CTX),
	.hash_key_size =   SHA1_DIGEST_SIZE,
	.hash_digest_len = SHA1_DIGEST_SIZE,
	.hash_integ_len = 0,	/* Not applicable */
	.hash_block_size = 64,	/* B from RFC 2104 */
	.hash_init = SHA1Init_thunk,
	.hash_update = SHA1Update_thunk,
	.hash_final = SHA1Final_thunk,
};

static struct hash_desc crypto_integ_sha1 =
{
	.common = { .name = "oakley_sha",
		    .officname = "sha1",
		    .algo_type = IKE_ALG_INTEG,
		    .algo_id =   OAKLEY_SHA1,
		    .algo_v2id = IKEv2_AUTH_HMAC_SHA1_96,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(SHA1_CTX),
	.hash_key_size =   SHA1_DIGEST_SIZE,
	.hash_digest_len = SHA1_DIGEST_SIZE,
	.hash_integ_len = SHA1_DIGEST_SIZE_96,
	.hash_block_size = 64,	/* B from RFC 2104 */
	.hash_init = SHA1Init_thunk,
	.hash_update = SHA1Update_thunk,
	.hash_final = SHA1Final_thunk,
};

#endif

void init_crypto(void)
{
#ifdef FIPS_CHECK
	bool fips = libreswan_fipsmode();
#else
	bool fips = FALSE;
#endif

#ifdef USE_TWOFISH
	if (!fips)
		ike_alg_twofish_init();
#endif

#ifdef USE_SERPENT
	if (!fips)
		ike_alg_serpent_init();
#endif

#ifdef USE_AES
	ike_alg_aes_init();
#endif

#ifdef USE_CAMELLIA
	if (!fips)
		ike_alg_camellia_init();
#endif

#ifdef USE_3DES
	ike_alg_add(&crypto_encrypter_3des.common);
#endif

#ifdef USE_SHA2
	ike_alg_sha2_init();
#endif

#ifdef USE_SHA1
	ike_alg_add(&crypto_hasher_sha1.common);
	ike_alg_add(&crypto_integ_sha1.common);
#endif

#ifdef USE_MD5
	if (!fips) {
		ike_alg_add(&crypto_hasher_md5.common);
		ike_alg_add(&crypto_integ_md5.common);
	}
#endif
}

/* Oakley group description
 *
 * See:
 * RFC-2409 "The Internet key exchange (IKE)" Section 6
 * RFC-3526 "More Modular Exponential (MODP) Diffie-Hellman groups"
 */

/* magic signifier */
const struct oakley_group_desc unset_group = {
	.group = OAKLEY_GROUP_invalid,
};

static struct oakley_group_desc oakley_group[] = {
	/* modp768_modulus no longer supported - too weak */
	{
		.group = OAKLEY_GROUP_MODP1024,
		.gen = MODP_GENERATOR,
		.modp = MODP1024_MODULUS,
		.bytes = BYTES_FOR_BITS(1024),
	},
	{
		.group = OAKLEY_GROUP_MODP1536,
		.gen = MODP_GENERATOR,
		.modp = MODP1536_MODULUS,
		.bytes = BYTES_FOR_BITS(1536),
	},
	{
		.group = OAKLEY_GROUP_MODP2048,
		.gen = MODP_GENERATOR,
		.modp = MODP2048_MODULUS,
		.bytes = BYTES_FOR_BITS(2048),
	},
	{
		.group = OAKLEY_GROUP_MODP3072,
		.gen = MODP_GENERATOR,
		.modp = MODP3072_MODULUS,
		.bytes = BYTES_FOR_BITS(3072),
	},
	{
		.group = OAKLEY_GROUP_MODP4096,
		.gen = MODP_GENERATOR,
		.modp = MODP4096_MODULUS,
		.bytes = BYTES_FOR_BITS(4096),
	},
	{
		.group = OAKLEY_GROUP_MODP6144,
		.gen = MODP_GENERATOR,
		.modp = MODP6144_MODULUS,
		.bytes = BYTES_FOR_BITS(6144),
	},
	{
		.group = OAKLEY_GROUP_MODP8192,
		.gen = MODP_GENERATOR,
		.modp = MODP8192_MODULUS,
		.bytes = BYTES_FOR_BITS(8192),
	},
	{
		.group = OAKLEY_GROUP_DH22,
		.gen = MODP_GENERATOR_DH22,
		.modp = MODP1024_MODULUS_DH22,
		.bytes = BYTES_FOR_BITS(1024),
	},
	{
		.group = OAKLEY_GROUP_DH23,
		.gen = MODP_GENERATOR_DH23,
		.modp = MODP2048_MODULUS_DH23,
		.bytes = BYTES_FOR_BITS(2048),
	},
	{
		.group = OAKLEY_GROUP_DH24,
		.gen = MODP_GENERATOR_DH24,
		.modp = MODP2048_MODULUS_DH24,
		.bytes = BYTES_FOR_BITS(2048),
	},
};

const struct oakley_group_desc *lookup_group(u_int16_t group)
{
	int i;

	for (i = 0; i != elemsof(oakley_group); i++)
		if (group == oakley_group[i].group)
			return &oakley_group[i];

	return NULL;
}

const struct oakley_group_desc *next_oakley_group(const struct oakley_group_desc *group)
{
	if (group == NULL) {
		return &oakley_group[0];
	} else if (group < &oakley_group[elemsof(oakley_group) - 1]) {
		return group + 1;
	} else {
		return NULL;
	}
}

void get_oakley_group_param(const struct oakley_group_desc *group,
			    chunk_t *base, chunk_t *prime)
{
	*base = decode_hex_to_chunk(group->gen, group->gen);
	*prime = decode_hex_to_chunk(group->modp, group->modp);
}

/* Encryption Routines
 *
 * Each uses and updates the state object's st_new_iv.
 * This must already be initialized.
 * 1DES support removed - it is simply too weak
 * BLOWFISH support removed - author suggests TWOFISH instead
 */

/* encrypt or decrypt part of an IKE message using 3DES
 * See RFC 2409 "IKE" Appendix B
 */
static void do_3des(u_int8_t *buf, size_t buf_len,
		    PK11SymKey *key, u_int8_t *iv, bool enc)
{
	passert(key != NULL);

	do_3des_nss(buf, buf_len, key, iv, enc);
}

/* hash and prf routines */
/*==========================================================
 *
 *  ike_alg linked list
 *
 *==========================================================
 */
const struct hash_desc *crypto_get_hasher(oakley_hash_t alg)
{
	return (const struct hash_desc *) ikev1_alg_find(IKE_ALG_HASH, alg);
}

const struct encrypt_desc *crypto_get_encrypter(int alg)
{
	return (const struct encrypt_desc *) ikev1_alg_find(IKE_ALG_ENCRYPT, alg);
}

void crypto_cbc_encrypt(const struct encrypt_desc *e, bool enc,
			u_int8_t *buf, size_t size, struct state *st)
{
	passert(st->st_new_iv_len >= e->enc_blocksize);
	st->st_new_iv_len = e->enc_blocksize;   /* truncate */

#if 0
	DBG(DBG_CRYPT,
	    DBG_log("encrypting buf=%p size=%d NSS keyptr: %p, iv: %p enc: %d",
		    buf, size, st->st_enc_key_nss,
		    st->st_new_iv, enc));
#endif

	e->do_crypt(buf, size, st->st_enc_key_nss, st->st_new_iv, enc);
}

/*
 * Return a required oakley or ipsec keysize or 0 if not required.
 * The first parameter uses 0 for ESP, and anything above that for
 * IKE major version
 */
int crypto_req_keysize(enum crk_proto ksproto, int algo)
{
	switch (ksproto) {
	case CRK_IKEv2:
		switch (algo) {
		case IKEv2_ENCR_CAST:
			return CAST_KEY_DEF_LEN;
		case IKEv2_ENCR_AES_CBC:
		case IKEv2_ENCR_AES_CTR:
		case IKEv2_ENCR_AES_CCM_8:
		case IKEv2_ENCR_AES_CCM_12:
		case IKEv2_ENCR_AES_CCM_16:
		case IKEv2_ENCR_AES_GCM_8:
		case IKEv2_ENCR_AES_GCM_12:
		case IKEv2_ENCR_AES_GCM_16:
		case IKEv2_ENCR_CAMELLIA_CBC_ikev1: /* IANA ikev1/ipsec-v3 fixup */
		case IKEv2_ENCR_CAMELLIA_CBC:
		case IKEv2_ENCR_NULL_AUTH_AES_GMAC:
			return AES_KEY_DEF_LEN;
		case IKEv2_ENCR_CAMELLIA_CTR:
		case IKEv2_ENCR_CAMELLIA_CCM_A:
		case IKEv2_ENCR_CAMELLIA_CCM_B:
		case IKEv2_ENCR_CAMELLIA_CCM_C:
			return CAMELLIA_KEY_DEF_LEN;
		/* private use */
		case IKEv2_ENCR_SERPENT_CBC:
			return SERPENT_KEY_DEF_LEN;
		case IKEv2_ENCR_TWOFISH_CBC:
		case IKEv2_ENCR_TWOFISH_CBC_SSH: /* ?? */
			return TWOFISH_KEY_DEF_LEN;
		default:
			return 0;
		}

	case CRK_IKEv1:
		switch (algo) {
		case OAKLEY_CAST_CBC:
			return CAST_KEY_DEF_LEN;
		case OAKLEY_AES_CBC:
			return AES_KEY_DEF_LEN;
		case OAKLEY_CAMELLIA_CBC:
			return CAMELLIA_KEY_DEF_LEN;
		/* private use */
		case OAKLEY_SERPENT_CBC:
			return SERPENT_KEY_DEF_LEN;
		case OAKLEY_TWOFISH_CBC:
		case OAKLEY_TWOFISH_CBC_SSH: /* ?? */
			return TWOFISH_KEY_DEF_LEN;
		default:
			return 0;
		}

	case CRK_ESPorAH:
		switch (algo) {
		case ESP_CAST:
			return CAST_KEY_DEF_LEN;
		case ESP_AES:
			return AES_KEY_DEF_LEN;
		case ESP_AES_CTR:
			return AES_CTR_KEY_DEF_LEN;
		case ESP_AES_CCM_8:
		case ESP_AES_CCM_12:
		case ESP_AES_CCM_16:
			return AES_CCM_KEY_DEF_LEN;
		case ESP_AES_GCM_8:
		case ESP_AES_GCM_12:
		case ESP_AES_GCM_16:
			return AES_GCM_KEY_DEF_LEN;
		case ESP_CAMELLIA:
		case ESP_CAMELLIAv1:
			return CAMELLIA_KEY_DEF_LEN;
		case ESP_NULL_AUTH_AES_GMAC:
			return AES_GMAC_KEY_DEF_LEN;
		/* private use */
		case ESP_SERPENT:
			return SERPENT_KEY_DEF_LEN;
		case ESP_TWOFISH:
			return TWOFISH_KEY_DEF_LEN;
		default:
			return 0;
		}

	default:
		bad_case(ksproto);
	}
}
