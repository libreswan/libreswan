/* crypto interfaces
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: crypto.c,v 1.41 2005/10/06 19:41:27 mcr Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <openswan.h>
#define HEADER_DES_LOCL_H   /* stupid trick to force prototype decl in <des.h> */
#include <crypto/des.h>

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

#include "tpm/tpm.h"


/* moduli and generator. */


static MP_INT
#if defined(USE_VERYWEAK_DH1) 	/* modp768 not sufficiently strong */
    modp768_modulus,
#endif
    modp1024_modulus,
    modp1536_modulus,
    modp2048_modulus,
    modp3072_modulus,
    modp4096_modulus,
    modp6144_modulus,
    modp8192_modulus;

MP_INT groupgenerator;	/* MODP group generator (2) */

#ifdef IKE_ALG

#ifdef USE_1DES
static void do_des(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc);

static struct encrypt_desc crypto_encrypter_des =
{
    common: {name: "oakley_des_cbc",
             algo_type:         IKE_ALG_ENCRYPT,
             algo_id:           OAKLEY_DES_CBC,
             algo_next:         NULL, },
    enc_ctxsize:        sizeof(des_key_schedule),
    enc_blocksize:      DES_CBC_BLOCK_SIZE,
    keydeflen:  DES_CBC_BLOCK_SIZE * BITS_PER_BYTE,
    keyminlen:  DES_CBC_BLOCK_SIZE * BITS_PER_BYTE,
    keymaxlen:  DES_CBC_BLOCK_SIZE * BITS_PER_BYTE,
    do_crypt:   do_des,
};
#endif

#ifdef USE_3DES
static void do_3des(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc);
static struct encrypt_desc crypto_encrypter_3des =
{ 	
    common: {name: "oakley_3des_cbc",
	     algo_type: 	IKE_ALG_ENCRYPT,
	     algo_id:   	OAKLEY_3DES_CBC, 
	     algo_next: 	NULL, },
    enc_ctxsize: 	sizeof(des_key_schedule) * 3,
    enc_blocksize: 	DES_CBC_BLOCK_SIZE, 
    keydeflen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
    keyminlen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
    keymaxlen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
    do_crypt: 	do_3des,
};
#endif

static struct hash_desc crypto_hasher_md5 =
{ 	
    common: {name: "oakley_md5",
	     algo_type: IKE_ALG_HASH,
	     algo_id:   OAKLEY_MD5,
	     algo_next: NULL, },
    hash_ctx_size: sizeof(MD5_CTX),
    hash_digest_len: MD5_DIGEST_SIZE,
    hash_init: (void (*)(void *)) osMD5Init,
    hash_update: (void (*)(void *, const u_int8_t *, size_t)) osMD5Update,
    hash_final: (void (*)(u_char *, void *)) osMD5Final,
};
static struct hash_desc crypto_hasher_sha1 =
{ 	
    common: {name: "oakley_sha",
	     algo_type: IKE_ALG_HASH,
	     algo_id:   OAKLEY_SHA,
	     algo_next: NULL, },
    hash_ctx_size: sizeof(SHA1_CTX),
    hash_digest_len: SHA1_DIGEST_SIZE,
    hash_init: (void (*)(void *)) SHA1Init,
    hash_update: (void (*)(void *, const u_int8_t *, size_t)) SHA1Update,
    hash_final: (void (*)(u_char *, void *)) SHA1Final,
};
#endif
void
init_crypto(void)
{
    if (mpz_init_set_str(&groupgenerator, MODP_GENERATOR, 10) != 0
#if defined(USE_VERYWEAK_DH1)	                        /* modp768 not sufficiently strong */
    || mpz_init_set_str(&modp768_modulus, MODP768_MODULUS, 16) != 0
#endif
    || mpz_init_set_str(&modp1024_modulus, MODP1024_MODULUS, 16) != 0
    || mpz_init_set_str(&modp1536_modulus, MODP1536_MODULUS, 16) != 0
    || mpz_init_set_str(&modp2048_modulus, MODP2048_MODULUS, 16) != 0
    || mpz_init_set_str(&modp3072_modulus, MODP3072_MODULUS, 16) != 0
    || mpz_init_set_str(&modp4096_modulus, MODP4096_MODULUS, 16) != 0
    || mpz_init_set_str(&modp6144_modulus, MODP6144_MODULUS, 16) != 0
    || mpz_init_set_str(&modp8192_modulus, MODP8192_MODULUS, 16) != 0)
	exit_log("mpz_init_set_str() failed in init_crypto()");
#ifdef IKE_ALG
	{
#ifdef USE_TWOFISH
	    {
		extern int ike_alg_twofish_init(void);
		ike_alg_twofish_init();
	    }
#endif

#ifdef USE_SERPENT
	    {
		extern int ike_alg_serpent_init(void);
		ike_alg_serpent_init();
	    }
#endif

#ifdef USE_AES
	    {
		extern int ike_alg_aes_init(void);
		ike_alg_aes_init();
	    }
#endif

#ifdef USE_3DES
	    {
		ike_alg_add((struct ike_alg *) &crypto_encrypter_3des);
	    }
#endif
	    
#ifdef USE_BLOWFISH
	    {
		extern int ike_alg_blowfish_init(void);
		ike_alg_blowfish_init();
	    }
#endif

#ifdef USE_1DES
/*#warning YOUR PLUTO IS INSECURE, IT HAS 1DES. DO NOT USE IT. */
	    {
		ike_alg_add((struct ike_alg *) &crypto_encrypter_des);
	    }
#endif

#ifdef USE_SHA2
	    {
		extern int ike_alg_sha2_init(void);
		ike_alg_sha2_init();
	    }
#endif
	    
	    ike_alg_add((struct ike_alg *) &crypto_hasher_sha1);
	    ike_alg_add((struct ike_alg *) &crypto_hasher_md5);
	}
#endif
}

/* Oakley group description
 *
 * See RFC2409 "The Internet key exchange (IKE)" 6.
 */

const struct oakley_group_desc unset_group = {0, NULL, 0};	/* magic signifier */

const struct oakley_group_desc oakley_group[] = {
#if defined(USE_VERYWEAK_DH1)    	/* modp768 not sufficiently strong */
    { OAKLEY_GROUP_MODP768, &modp768_modulus, BYTES_FOR_BITS(768) },
#endif
    { OAKLEY_GROUP_MODP1024, &modp1024_modulus, BYTES_FOR_BITS(1024) },
    { OAKLEY_GROUP_MODP1536, &modp1536_modulus, BYTES_FOR_BITS(1536) },
    { OAKLEY_GROUP_MODP2048, &modp2048_modulus, BYTES_FOR_BITS(2048) },
    { OAKLEY_GROUP_MODP3072, &modp3072_modulus, BYTES_FOR_BITS(3072) },
    { OAKLEY_GROUP_MODP4096, &modp4096_modulus, BYTES_FOR_BITS(4096) },
    { OAKLEY_GROUP_MODP6144, &modp6144_modulus, BYTES_FOR_BITS(6144) },
    { OAKLEY_GROUP_MODP8192, &modp8192_modulus, BYTES_FOR_BITS(8192) },
};

const unsigned int oakley_group_size = elemsof(oakley_group);

const struct oakley_group_desc *
lookup_group(u_int16_t group)
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
 */

#ifdef USE_1DES
/* encrypt or decrypt part of an IKE message using DES
 * See RFC 2409 "IKE" Appendix B
 */
static void
do_des(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    des_key_schedule ks;

    (void) des_set_key((des_cblock *)key, ks);

    passert(key_size >= DES_CBC_BLOCK_SIZE);
    key_size = DES_CBC_BLOCK_SIZE;     /* truncate */

    des_ncbc_encrypt((des_cblock *)buf, (des_cblock *)buf, buf_len,
	ks,
	(des_cblock *)iv, enc);
}
#endif

/* encrypt or decrypt part of an IKE message using 3DES
 * See RFC 2409 "IKE" Appendix B
 */
static void
do_3des(u_int8_t *buf, size_t buf_len
	, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    des_key_schedule ks[3];

    passert(key != NULL);
    passert(key_size==(DES_CBC_BLOCK_SIZE * 3));
    (void) des_set_key((des_cblock *)key + 0, ks[0]);
    (void) des_set_key((des_cblock *)key + 1, ks[1]);
    (void) des_set_key((des_cblock *)key + 2, ks[2]);

    des_ede3_cbc_encrypt((des_cblock *)buf, (des_cblock *)buf, buf_len,
			 ks[0], ks[1], ks[2],
			 (des_cblock *)iv, enc);
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
	return (struct hash_desc *) ike_alg_find(IKE_ALG_HASH, alg, 0);
}
struct encrypt_desc *crypto_get_encrypter(int alg)
{
	return (struct encrypt_desc *) ike_alg_find(IKE_ALG_ENCRYPT, alg, 0);
}

void 
crypto_cbc_encrypt(const struct encrypt_desc *e, bool enc
		   , u_int8_t *buf, size_t size, struct state *st)
{
    passert(st->st_new_iv_len >= e->enc_blocksize);
    st->st_new_iv_len = e->enc_blocksize;	/* truncate */

#if 0
    DBG(DBG_CRYPT
	, DBG_log("encrypting buf=%p size=%d keyptr: %p keysize: %d, iv: %p enc: %d"
		  , buf, size, st->st_enc_key.ptr
		  , st->st_enc_key.len, st->st_new_iv, enc));
#endif

    e->do_crypt(buf, size, st->st_enc_key.ptr
		, st->st_enc_key.len, st->st_new_iv, enc);

    /*
      e->set_key(&ctx, st->st_enc_key.ptr, st->st_enc_key.len);
      e->cbc_crypt(&ctx, buf, size, st->st_new_iv, enc);
    */
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

