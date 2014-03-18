/* crypto interfaces
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
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
#define HEADER_DES_LOCL_H   /* stupid trick to force prototype decl in <des.h> */
#include <klips-crypto/des.h>

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

#include "lswcrypto.h"

#include "pem.h"

/* moduli and generator. */

static MP_INT
	/* modp768_modulus no longer supported - it is too weak */
	modp1024_modulus, /* migrate away from this if you are still using it */
	modp1536_modulus,
	modp2048_modulus,
	modp3072_modulus,
	modp4096_modulus,
	modp6144_modulus,
	modp8192_modulus;

static MP_INT
	dh22_modulus,
	dh23_modulus,
	dh24_modulus;

static MP_INT groupgenerator;  /* MODP group generator (2) */

static MP_INT generator_dh22,
       generator_dh23,
       generator_dh24;

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
	.enc_ctxsize =      sizeof(des_key_schedule) * 3,
	.enc_blocksize =    DES_CBC_BLOCK_SIZE,
	.keydeflen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.keyminlen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.keymaxlen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.do_crypt =         do_3des,
};
#endif

#ifdef USE_MD5
static struct hash_desc crypto_hasher_md5 =
{
	.common = { .name = "oakley_md5",
		    .officname = "md5",
		    .algo_type = IKE_ALG_HASH,
		    .algo_id =   OAKLEY_MD5,
		    .algo_v2id = IKEv2_PRF_HMAC_MD5,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(MD5_CTX),
	.hash_key_size =   MD5_DIGEST_SIZE,
	.hash_digest_len = MD5_DIGEST_SIZE,
	.hash_integ_len = 0,    /*Not applicable*/
	.hash_block_size = HMAC_BUFSIZE,
	.hash_init = (void (*)(void *))osMD5Init,
	.hash_update = (void (*)(void *, const u_int8_t *, size_t))osMD5Update,
	.hash_final = (void (*)(u_char *, void *))osMD5Final,
};

static struct hash_desc crypto_integ_md5 =
{
	.common = { .name = "oakley_md5",
		    .officname = "md5",
		    .algo_type = IKE_ALG_INTEG,
		    .algo_id =   OAKLEY_MD5,
		    .algo_v2id = IKEv2_AUTH_HMAC_MD5_96,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(MD5_CTX),
	.hash_key_size =   MD5_DIGEST_SIZE,
	.hash_digest_len = MD5_DIGEST_SIZE,
	.hash_integ_len = MD5_DIGEST_SIZE_96,
	.hash_block_size = HMAC_BUFSIZE,
	.hash_init = (void (*)(void *))osMD5Init,
	.hash_update = (void (*)(void *, const u_int8_t *, size_t))osMD5Update,
	.hash_final = (void (*)(u_char *, void *))osMD5Final,
};
#endif

#ifdef USE_SHA1
static struct hash_desc crypto_hasher_sha1 =
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
	.hash_integ_len = 0,    /*Not applicable*/
	.hash_block_size = HMAC_BUFSIZE,
	.hash_init = (void (*)(void *))SHA1Init,
	.hash_update = (void (*)(void *, const u_int8_t *, size_t))SHA1Update,
	.hash_final = (void (*)(u_char *, void *))SHA1Final,
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
	.hash_block_size = HMAC_BUFSIZE,
	.hash_init = (void (*)(void *))SHA1Init,
	.hash_update = (void (*)(void *, const u_int8_t *, size_t))SHA1Update,
	.hash_final = (void (*)(u_char *, void *))SHA1Final,
};
#endif

void init_crypto(void)
{
	if (mpz_init_set_str(&groupgenerator, MODP_GENERATOR, 10) != 0
	    ||  mpz_init_set_str(&generator_dh22, MODP_GENERATOR_DH22,
				 16) != 0 ||
	    mpz_init_set_str(&generator_dh23, MODP_GENERATOR_DH23, 16) != 0 ||
	    mpz_init_set_str(&generator_dh24, MODP_GENERATOR_DH24, 16) != 0
	    /* modp768_modulus no longer supported */
	    || mpz_init_set_str(&modp1024_modulus, MODP1024_MODULUS,
				16) != 0 ||
	    mpz_init_set_str(&modp1536_modulus, MODP1536_MODULUS, 16) != 0 ||
	    mpz_init_set_str(&modp2048_modulus, MODP2048_MODULUS, 16) != 0 ||
	    mpz_init_set_str(&modp3072_modulus, MODP3072_MODULUS, 16) != 0 ||
	    mpz_init_set_str(&modp4096_modulus, MODP4096_MODULUS, 16) != 0 ||
	    mpz_init_set_str(&modp6144_modulus, MODP6144_MODULUS, 16) != 0 ||
	    mpz_init_set_str(&modp8192_modulus, MODP8192_MODULUS, 16) != 0
	    || mpz_init_set_str(&dh22_modulus, MODP1024_MODULUS_DH22,
				16) != 0 ||
	    mpz_init_set_str(&dh23_modulus, MODP2048_MODULUS_DH23, 16) != 0 ||
	    mpz_init_set_str(&dh24_modulus, MODP2048_MODULUS_DH24, 16) != 0
	    )
		exit_log("mpz_init_set_str() failed in init_crypto()");

#ifdef USE_TWOFISH
	ike_alg_twofish_init();
#endif

#ifdef USE_SERPENT
	ike_alg_serpent_init();
#endif

#ifdef USE_AES
	ike_alg_aes_init();
#endif

#ifdef USE_3DES
	ike_alg_add((struct ike_alg *) &crypto_encrypter_3des);
#endif

#ifdef USE_SHA2
	ike_alg_sha2_init();
#endif

#ifdef USE_SHA1
	ike_alg_add((struct ike_alg *) &crypto_hasher_sha1);
	ike_alg_add((struct ike_alg *) &crypto_integ_sha1);
#endif

#ifdef USE_MD5
	ike_alg_add((struct ike_alg *) &crypto_hasher_md5);
	ike_alg_add((struct ike_alg *) &crypto_integ_md5);
#endif
}

/* Oakley group description
 *
 * See:
 * RFC-2409 "The Internet key exchange (IKE)" Section 6
 * RFC-3526 "More Modular Exponential (MODP) Diffie-Hellman groups"
 */

const struct oakley_group_desc unset_group = { 0, NULL, NULL, 0 };      /* magic signifier */

const struct oakley_group_desc oakley_group[] = {
	/* modp768_modulus no longer supported - too weak */
	{ OAKLEY_GROUP_MODP1024, &groupgenerator, &modp1024_modulus,
	  BYTES_FOR_BITS(1024) },
	{ OAKLEY_GROUP_MODP1536, &groupgenerator, &modp1536_modulus,
	  BYTES_FOR_BITS(1536) },
	{ OAKLEY_GROUP_MODP2048, &groupgenerator, &modp2048_modulus,
	  BYTES_FOR_BITS(2048) },
	{ OAKLEY_GROUP_MODP3072, &groupgenerator, &modp3072_modulus,
	  BYTES_FOR_BITS(3072) },
	{ OAKLEY_GROUP_MODP4096, &groupgenerator, &modp4096_modulus,
	  BYTES_FOR_BITS(4096) },
	{ OAKLEY_GROUP_MODP6144, &groupgenerator, &modp6144_modulus,
	  BYTES_FOR_BITS(6144) },
	{ OAKLEY_GROUP_MODP8192, &groupgenerator, &modp8192_modulus,
	  BYTES_FOR_BITS(8192) },
	{ OAKLEY_GROUP_DH22, &generator_dh22, &dh22_modulus, BYTES_FOR_BITS(
		  1024) },
	{ OAKLEY_GROUP_DH23, &generator_dh23, &dh23_modulus, BYTES_FOR_BITS(
		  2048) },
	{ OAKLEY_GROUP_DH24, &generator_dh24, &dh24_modulus, BYTES_FOR_BITS(
		  2048) },

};

const unsigned int oakley_group_size = elemsof(oakley_group);

const struct oakley_group_desc *lookup_group(u_int16_t group)
{
	int i;

	for (i = 0; i != elemsof(oakley_group); i++)
		if (group == oakley_group[i].group)
			return &oakley_group[i];

	return NULL;
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
struct hash_desc *crypto_get_hasher(oakley_hash_t alg)
{
	return (struct hash_desc *) ikev1_alg_find(IKE_ALG_HASH, alg);
}

struct encrypt_desc *crypto_get_encrypter(int alg)
{
	return (struct encrypt_desc *) ikev1_alg_find(IKE_ALG_ENCRYPT, alg);
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

	/*
	   e->set_key(&ctx, st->st_enc_key_nss);
	   e->cbc_crypt(&ctx, buf, size, st->st_new_iv, enc);
	 */
}
