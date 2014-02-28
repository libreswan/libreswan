/*
 * Copyright (C) 2010-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2013 Paul Wouters <paul@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "libsha2/sha2.h"
#include "alg_info.h"
#include "ike_alg.h"

#include <pk11pub.h>
#include "lswlog.h"

static void sha256_hash_final(u_char *hash, sha256_context *ctx)
{
	unsigned int len;
	SECStatus s;

	s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, SHA2_256_DIGEST_SIZE);
	passert(s == SECSuccess);
	passert(len == SHA2_256_DIGEST_SIZE);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS SHA 256 hash final : end"));
}

static void sha384_hash_final(u_char *hash, sha512_context *ctx)
{
	unsigned int len;
	SECStatus s;

	s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, SHA2_384_DIGEST_SIZE);
	passert(s == SECSuccess);
	passert(len == SHA2_384_DIGEST_SIZE);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS SHA 384 hash final : end"));
}

static void sha512_hash_final(u_char *hash, sha512_context *ctx)
{
	unsigned int len;
	SECStatus s;

	s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, SHA2_512_DIGEST_SIZE);
	passert(s == SECSuccess);
	passert(len == SHA2_512_DIGEST_SIZE);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS SHA 512 hash final : end"));
}

static struct hash_desc hash_desc_sha2_256 = {
	.common = { .officname =  "sha256",
		    .algo_type = IKE_ALG_HASH,
		    .algo_id =   OAKLEY_SHA2_256,
		    .algo_v2id = IKEv2_PRF_HMAC_SHA2_256,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(sha256_context),
	.hash_key_size = SHA2_256_DIGEST_SIZE,
	.hash_digest_len = SHA2_256_DIGEST_SIZE,
	.hash_integ_len = 0,    /*Not applicable*/
	.hash_block_size = HMAC_BUFSIZE,
	.hash_init = (void (*)(void *))sha256_init,
	.hash_update = (void (*)(void *, const u_char *, size_t ))sha256_write,
	.hash_final = (void (*)(u_char *, void *))sha256_hash_final,
};

static struct hash_desc integ_desc_sha2_256 = {
	.common = { .officname =  "sha256",
		    .algo_type = IKE_ALG_INTEG,
		    .algo_id =   OAKLEY_SHA2_256,
		    .algo_v2id = IKEv2_AUTH_HMAC_SHA2_256_128,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(sha256_context),
	.hash_key_size = SHA2_256_DIGEST_SIZE,
	.hash_digest_len = SHA2_256_DIGEST_SIZE,
	.hash_integ_len = SHA2_256_DIGEST_SIZE / 2,
	.hash_block_size = HMAC_BUFSIZE,
	.hash_init = (void (*)(void *))sha256_init,
	.hash_update = (void (*)(void *, const u_char *, size_t ))sha256_write,
	.hash_final = (void (*)(u_char *, void *))sha256_hash_final,
};

static struct hash_desc hash_desc_sha2_384 = {
	.common = { .officname =  "sha384",
		    .algo_type = IKE_ALG_HASH,
		    .algo_id =   OAKLEY_SHA2_384,
		    .algo_v2id = IKEv2_PRF_HMAC_SHA2_384,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(sha512_context),
	.hash_key_size = SHA2_384_DIGEST_SIZE,
	.hash_digest_len = SHA2_384_DIGEST_SIZE,
	.hash_integ_len = 0,    /*Not applicable*/
	.hash_block_size = HMAC_BUFSIZE * 2,
	.hash_init = (void (*)(void *))sha384_init,
	.hash_update = (void (*)(void *, const u_char *, size_t ))sha512_write,
	.hash_final = (void (*)(u_char *, void *))sha384_hash_final,
};

static struct hash_desc integ_desc_sha2_384 = {
	.common = { .officname =  "sha384",
		    .algo_type = IKE_ALG_INTEG,
		    .algo_id =   OAKLEY_SHA2_384,
		    .algo_v2id = IKEv2_AUTH_HMAC_SHA2_384_192,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(sha512_context),
	.hash_key_size = SHA2_384_DIGEST_SIZE,
	.hash_digest_len = SHA2_384_DIGEST_SIZE,
	.hash_integ_len = SHA2_384_DIGEST_SIZE / 2,
	.hash_block_size = HMAC_BUFSIZE * 2,
	.hash_init = (void (*)(void *))sha384_init,
	.hash_update = (void (*)(void *, const u_char *, size_t ))sha512_write,
	.hash_final = (void (*)(u_char *, void *))sha384_hash_final,
};

static struct hash_desc hash_desc_sha2_512 = {
	.common = { .officname = "sha512",
		    .algo_type = IKE_ALG_HASH,
		    .algo_id =   OAKLEY_SHA2_512,
		    .algo_v2id = IKEv2_PRF_HMAC_SHA2_512,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(sha512_context),
	.hash_key_size = SHA2_512_DIGEST_SIZE,
	.hash_digest_len = SHA2_512_DIGEST_SIZE,
	.hash_integ_len = 0,      /*Not applicable*/
	.hash_block_size = HMAC_BUFSIZE * 2,
	.hash_init = (void (*)(void *))sha512_init,
	.hash_update = (void (*)(void *, const u_char *, size_t ))sha512_write,
	.hash_final = (void (*)(u_char *, void *))sha512_hash_final,
};

static struct hash_desc integ_desc_sha2_512 = {
	.common = { .officname =  "sha512",
		    .algo_type = IKE_ALG_INTEG,
		    .algo_id =   OAKLEY_SHA2_512,
		    .algo_v2id = IKEv2_AUTH_HMAC_SHA2_512_256,
		    .algo_next = NULL, },
	.hash_ctx_size = sizeof(sha512_context),
	.hash_key_size = SHA2_512_DIGEST_SIZE,
	.hash_digest_len = SHA2_512_DIGEST_SIZE,
	.hash_integ_len = SHA2_512_DIGEST_SIZE / 2,
	.hash_block_size = HMAC_BUFSIZE * 2,
	.hash_init = (void (*)(void *))sha512_init,
	.hash_update = (void (*)(void *, const u_char *, size_t ))sha512_write,
	.hash_final = (void (*)(u_char *, void *))sha512_hash_final,
};

int ike_alg_sha2_init(void)
{
	int ret;

	ret = ike_alg_register_hash(&hash_desc_sha2_512);
	if (ret == 0) {
		ret = ike_alg_register_hash(&hash_desc_sha2_384);
		if (ret == 0) {
			ret = ike_alg_register_hash(&hash_desc_sha2_256);

			ike_alg_add((struct ike_alg *) &integ_desc_sha2_256);
			ike_alg_add((struct ike_alg *) &integ_desc_sha2_384);
			ike_alg_add((struct ike_alg *) &integ_desc_sha2_512);
		}
	}
	return ret;
}

/*
   IKE_ALG_INIT_NAME: ike_alg_sha2_init
 */
