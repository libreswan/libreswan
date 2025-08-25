/*
 * Parse DRBG CAVP test functions, for libreswan
 *
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
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

#include "lswalloc.h"
#include "ike_alg.h"
#include "ike_alg_prf.h"
#include "ike_alg_hash_ops.h"
#include "ike_alg_prf_mac_ops.h"
#include "ike_alg_prf_ikev1_ops.h"
#include "ike_alg_prf_ikev2_ops.h"

#include "crypt_symkey.h"
#include "crypt_prf.h"

#include "cavp.h"
#include "cavp_entry.h"
#include "cavp_print.h"
#include "test_hmac.h"
#include "test_sha.h"

static long unsigned l;

static struct cavp_entry config[] = {
	{ .key = "L", .op = op_unsigned_long, .unsigned_long = &l, },
	{ .key = NULL, },
};

#ifdef USE_SHA2
static struct prf_desc ike_alg_prf_sha2_224 = {
	.common = {
		.fqn = "SHA2_224",
		.type = &ike_alg_prf,
		.fips.approved = true,
	},
	.prf_key_size = 64, /* 224/8 */
	.prf_output_size = 28,  /* 224/8 */
	.hasher = &ike_alg_hash_sha2_224,
	.prf_mac_ops = &ike_alg_prf_mac_hmac_ops,
	.prf_ikev1_ops = &ike_alg_prf_ikev1_mac_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_mac_ops,
};
#endif

static const struct prf_desc *prfs[] = {
#ifdef USE_SHA1
	&ike_alg_prf_sha1,
#endif
#ifdef USE_SHA2
	&ike_alg_prf_sha2_224,
	&ike_alg_prf_sha2_256,
	&ike_alg_prf_sha2_384,
	&ike_alg_prf_sha2_512,
#endif
	NULL,
};

static const struct prf_desc *prf_alg;

static void hmac_print_config(void)
{
	for (int i = 0; prfs[i]; i++) {
		if (prfs[i]->prf_output_size == l) {
			prf_alg = prfs[i];
			break;
		}
	}
	config_number("L", l);
	if (prf_alg == NULL) {
		fprintf(stderr, "HMAC length %lu not recognised\n", l);
	} else {
		fprintf(stderr, "HMAC %s with length %lu\n",
			prf_alg->common.fqn, l);
	}
}

static chunk_t key;
static chunk_t msg;
static long int count;
static long int tlen;

static struct cavp_entry data[] = {
	{ .key = "Count", .op = op_signed_long, .signed_long = &count, },
	{ .key = "Klen", .op = op_ignore, },
	{ .key = "Tlen", .op = op_signed_long, .signed_long = &tlen},
	{ .key = "Key", .op = op_chunk, .chunk = &key, },
	{ .key = "Msg", .op = op_chunk, .chunk = &msg, },
	{ .key = "Mac", .op = op_ignore, },
	{ .key = NULL, },
};

static void hmac_run_test(struct logger *logger)
{
	print_number("Count", NULL, count);
	print_number("Klen", NULL, key.len);
	print_number("Tlen", NULL, tlen);
	print_chunk("Key", NULL, key, 0);
	print_chunk("Msg", NULL, msg, 0);
	if (prf_alg == NULL) {
		return;
	}
	struct crypt_prf *prf = crypt_prf_init_hunk("run", prf_alg,
						    "key", key,
						    logger);
	crypt_prf_update_hunk(prf, "msg", msg);
	chunk_t bytes = alloc_chunk(prf_alg->prf_output_size, "bytes");
	crypt_prf_final_bytes(&prf, bytes.ptr, bytes.len);
	print_chunk("Mac", NULL, bytes, tlen);
	free_chunk_content(&bytes);
}

const struct cavp test_hmac = {
	.alias = "hmac",
	.description = "HMAC PRF",
	.print_config = hmac_print_config,
	.run_test = hmac_run_test,
	.config = config,
	.data = data,
	.match = {
		"HMAC information",
		NULL,
	},
};
