/* crypto interfaces
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <gmp.h>    /* GNU MP library */

#ifdef USE_MD5
#include "md5.h"
#endif
#ifdef USE_SHA1
#include "sha1.h"
#endif
#ifdef USE_SHA2
#include "sha2.h"
#endif
#include "aes_xcbc.h"

#include <nss.h>
#include <pk11pub.h>

#include "mpzfuncs.h"

extern void init_crypto(void);

/* Oakley group descriptions */

struct oakley_group_desc {
	u_int16_t group;
/* RFC 5114 defines new modp groups each having different generator */
	MP_INT *generator;
	MP_INT *modulus;
	size_t bytes;
};

extern const struct oakley_group_desc unset_group;      /* magic signifier */
extern const struct oakley_group_desc *lookup_group(u_int16_t group);
extern const struct oakley_group_desc oakley_group[];
extern const unsigned int oakley_group_size;

/* unification of cryptographic encoding/decoding algorithms
 *
 * The IV is taken from and returned to st->st_new_iv.
 * This allows the old IV to be retained.
 * Use update_iv to commit to the new IV (for example, once a packet has
 * been validated).
 */

#define MAX_OAKLEY_KEY_LEN_OLD  (3 * DES_CBC_BLOCK_SIZE)
#define MAX_OAKLEY_KEY_LEN  (256 / BITS_PER_BYTE)

struct state;   /* forward declaration, dammit */

struct encrypt_desc;	/* forward */
struct hash_desc;	/* forward */
struct encrypt_desc *crypto_get_encrypter(int alg);
struct hash_desc *crypto_get_hasher(oakley_hash_t alg);

void crypto_cbc_encrypt(const struct encrypt_desc *e, bool enc, u_int8_t *buf,
			size_t size, struct state *st);

/* macros to manipulate IVs in state */

#define update_iv(st)	{ \
	passert(st->st_new_iv_len <= sizeof(st->st_iv)); \
	(st)->st_iv_len = (st)->st_new_iv_len; \
	memcpy((st)->st_iv, (st)->st_new_iv, (st)->st_new_iv_len); \
    }

#define set_ph1_iv_from_new(st)	{ \
	passert((st)->st_new_iv_len <= sizeof((st)->st_ph1_iv)); \
	(st)->st_ph1_iv_len = (st)->st_new_iv_len; \
	memcpy((st)->st_ph1_iv, (st)->st_new_iv, (st)->st_ph1_iv_len); \
 }

#define save_iv(st, tmp, tmp_len) { \
	passert((st)->st_iv_len <= sizeof((tmp))); \
	(tmp_len) = (st)->st_iv_len; \
	memcpy((tmp), (st)->st_iv, (tmp_len)); \
    }

#define restore_iv(st, tmp, tmp_len) { \
	passert((tmp_len) <= sizeof((st)->st_iv)); \
	(st)->st_iv_len = (tmp_len); \
	memcpy((st)->st_iv, (tmp), (tmp_len)); \
    }

#define save_new_iv(st, tmp, tmp_len)	{ \
	passert((st)->st_new_iv_len <= sizeof((tmp))); \
	(tmp_len) = (st)->st_new_iv_len; \
	memcpy((tmp), (st)->st_new_iv, (tmp_len)); \
    }

#define restore_new_iv(st, tmp, tmp_len)	{ \
	passert((tmp_len) <= sizeof((st)->st_new_iv)); \
	(st)->st_new_iv_len = (tmp_len); \
	memcpy((st)->st_new_iv, (tmp), (tmp_len)); \
    }

/* unification of cryptographic hashing mechanisms */

union hash_ctx {
	lsMD5_CTX ctx_md5;
	SHA1_CTX ctx_sha1;
#ifdef USE_SHA2
	sha256_context ctx_sha256;
	sha384_context ctx_sha384;
	sha512_context ctx_sha512;
#endif
	aes_xcbc_context ctx_aes_xcbc;
};

/* HMAC package
 * Note that hmac_ctx can be (and is) copied since there are
 * no persistent pointers into it.
 */

struct hmac_ctx {
	const struct hash_desc *h;      /* underlying hash function */
	size_t hmac_digest_len;         /* copy of h->hash_digest_len */
	union hash_ctx hash_ctx;        /* ctx for hash function */
	u_char buf1[HMAC_BUFSIZE], buf2[HMAC_BUFSIZE];
#ifdef USE_SHA2
	sha256_context ctx_sha256;
	sha512_context ctx_sha512;
#endif
	aes_xcbc_context ctx_aes_xcbc;

	PK11SymKey *ikey, *okey;
	PK11Context *ctx_nss;
};

extern void hmac_init(struct hmac_ctx *ctx,
		      const struct hash_desc *h,
		      /*const*/ PK11SymKey *symkey);

extern void hmac_update(struct hmac_ctx *ctx,
			const u_char *data,
			size_t data_len);

#define hmac_update_chunk(ctx, ch) hmac_update((ctx), (ch).ptr, (ch).len)

extern void hmac_final(u_char *output, struct hmac_ctx *ctx);

#define hmac_final_chunk(ch, name, ctx) { \
		pfreeany((ch).ptr); \
		(ch).len = (ctx)->hmac_digest_len; \
		(ch).ptr = alloc_bytes((ch).len, name); \
		hmac_final((ch).ptr, (ctx)); \
}

extern CK_MECHANISM_TYPE nss_key_derivation_mech(const struct hash_desc *hasher);
extern void nss_symkey_log(PK11SymKey *key, const char *msg);
extern chunk_t hmac_pads(u_char val, unsigned int len);
extern PK11SymKey *pk11_derive_wrapper_lsw(PK11SymKey *base,
					   CK_MECHANISM_TYPE mechanism,
					   chunk_t data,
					   CK_MECHANISM_TYPE target,
					   CK_ATTRIBUTE_TYPE operation,
					   int keySize);
extern PK11SymKey *PK11_Derive_lsw(PK11SymKey *base,
				   CK_MECHANISM_TYPE mechanism,
				   SECItem *param, CK_MECHANISM_TYPE target,
				   CK_ATTRIBUTE_TYPE operation, int keySize);

enum crk_proto {
	CRK_ESPorAH,
	CRK_IKEv1,
	CRK_IKEv2
};

extern int crypto_req_keysize(enum crk_proto ksproto, int algo);

extern struct hash_desc crypto_hasher_sha1;	/* used by nat_traversal.c */

#endif /* _CRYPTO_H */
