/* MD5, for libreswan.
 *
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
#include "ike_alg_md5.h"

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

struct hash_desc ike_alg_prf_md5 = {
	.common = {
		.name = "oakley_md5",
		.officname = "md5",
		.algo_type = IKE_ALG_HASH,
		.algo_id = OAKLEY_MD5,
		.algo_v2id = IKEv2_PRF_HMAC_MD5,
	},
	.hash_ctx_size = sizeof(lsMD5_CTX),
	.hash_key_size = MD5_DIGEST_SIZE,
	.hash_digest_len = MD5_DIGEST_SIZE,
	.hash_integ_len = 0,    /* Not applicable */
	.hash_block_size = 64,	/* B from RFC 2104 */
	.hash_init = lsMD5Init_thunk,
	.hash_update = lsMD5Update_thunk,
	.hash_final = lsMD5Final_thunk,
};

struct hash_desc ike_alg_integ_md5 =
{
	.common = {
		.name = "oakley_md5",
		.officname = "md5",
		.algo_type = IKE_ALG_INTEG,
		.algo_id = OAKLEY_MD5,
		.algo_v2id = IKEv2_AUTH_HMAC_MD5_96,
	},
	.hash_ctx_size = sizeof(lsMD5_CTX),
	.hash_key_size =   MD5_DIGEST_SIZE,
	.hash_digest_len = MD5_DIGEST_SIZE,
	.hash_integ_len = MD5_DIGEST_SIZE_96,
	.hash_block_size = 64,	/* B from RFC 2104 */
	.hash_init = lsMD5Init_thunk,
	.hash_update = lsMD5Update_thunk,
	.hash_final = lsMD5Final_thunk,
};
