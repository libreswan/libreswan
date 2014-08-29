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
#include "crypto.h"
#include "alg_info.h"
#include "ike_alg.h"

#include <pk11pub.h>

/* these thunks accept void * and pass as a shaN_context * */

/* sha256 thunks */

static void sha256_init_thunk(void *ctx)
{
	sha256_init(ctx);
}

static void sha256_write_thunk(void *ctx, const unsigned char *datap, size_t length)
{
	sha256_write(ctx, datap, length);
}

static void sha256_final_thunk(u_char *hash, void *ctx)
{
	sha256_final(hash, ctx);
}

/* sha384 thunks */

static void sha384_init_thunk(void *ctx)
{
	sha384_init(ctx);
}

static void sha384_write_thunk(void *ctx, const unsigned char *datap, size_t length)
{
	sha384_write(ctx, datap, length);
}

static void sha384_final_thunk(u_char *hash, void *ctx)
{
	sha384_final(hash, ctx);
}

/* sha512 thunks */

static void sha512_init_thunk(void *ctx)
{
	sha512_init(ctx);
}

static void sha512_write_thunk(void *ctx, const unsigned char *datap, size_t length)
{
	sha512_write(ctx, datap, length);
}

static void sha512_final_thunk(u_char *hash, void *ctx)
{
	sha512_final(hash, ctx);
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
	.hash_integ_len = 0,    /* Not applicable */
	.hash_block_size = HMAC_BUFSIZE,
	.hash_init = sha256_init_thunk,
	.hash_update = sha256_write_thunk,
	.hash_final = sha256_final_thunk,
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
	.hash_init = sha256_init_thunk,
	.hash_update = sha256_write_thunk,
	.hash_final = sha256_final_thunk,
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
	.hash_integ_len = 0,    /* Not applicable */
	.hash_block_size = HMAC_BUFSIZE * 2,
	.hash_init = sha384_init_thunk,
	.hash_update = sha384_write_thunk,
	.hash_final = sha384_final_thunk,
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
	.hash_init = sha384_init_thunk,
	.hash_update = sha384_write_thunk,
	.hash_final = sha384_final_thunk,
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
	.hash_integ_len = 0,      /* Not applicable */
	.hash_block_size = HMAC_BUFSIZE * 2,
	.hash_init = sha512_init_thunk,
	.hash_update = sha512_write_thunk,
	.hash_final = sha512_final_thunk,
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
	.hash_init = sha512_init_thunk,
	.hash_update = sha512_write_thunk,
	.hash_final = sha512_final_thunk,
};

/*
 * IKE_ALG_INIT_NAME: ike_alg_sha2_init
 */
void ike_alg_sha2_init(void)
{
	if (ike_alg_register_hash(&hash_desc_sha2_512))
		ike_alg_add(&integ_desc_sha2_256.common);

	if (ike_alg_register_hash(&hash_desc_sha2_384))
		ike_alg_add(&integ_desc_sha2_384.common);

	if (ike_alg_register_hash(&hash_desc_sha2_256))
		ike_alg_add(&integ_desc_sha2_512.common);
}
