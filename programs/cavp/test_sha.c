/*
 * Parse DRBG CAVP test functions, for libreswan
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

#include "lswalloc.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "ike_alg_hash_ops.h"
#include "passert.h"

#include "crypt_symkey.h"
#include "ikev2_prf.h"

#include "cavp.h"
#include "cavp_entry.h"
#include "cavp_print.h"
#include "test_sha.h"

static unsigned long l;

static struct cavp_entry config[] = {
	{ .key = "L", .op = op_unsigned_long, .unsigned_long = &l, },
	{ .key = NULL, },
};

struct hash_desc ike_alg_hash_sha2_224 = {
	.common = {
		.fqn = "SHA2_224",
		.type = IKE_ALG_HASH,
		.fips.approved = true,
	},
	.hash_digest_size = 28, /* 224/8 */
	.hash_block_size = 64, /* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,
};

static const struct hash_desc *hashes[] = {
#ifdef USE_SHA1
	&ike_alg_hash_sha1,
#endif
#ifdef USE_SHA2
	&ike_alg_hash_sha2_224,
	&ike_alg_hash_sha2_256,
	&ike_alg_hash_sha2_384,
	&ike_alg_hash_sha2_512,
#endif
	NULL,
};

static const struct hash_desc *hash_alg;

static void print_config(void)
{
	for (int i = 0; hashes[i]; i++) {
		if (hashes[i]->hash_digest_size == l) {
			hash_alg = hashes[i];
			break;
		}
	}
	config_number("L", l);
	if (hash_alg == NULL) {
		fprintf(stderr, "SHA length %lu not recognised\n", l);
	} else {
		fprintf(stderr, "SHA %s with length %lu\n",
			hash_alg->common.fqn, l);
	}
}

static unsigned long len;
static chunk_t msg;

static struct cavp_entry msg_data[] = {
	{ .key = "Len", .op = op_unsigned_long, .unsigned_long = &len, },
	{ .key = "Msg", .op = op_chunk, .chunk = &msg, },
	{ .key = "MD", .op = op_ignore, },
	{ .key = NULL, },
};

static void msg_run_test(struct logger *logger_unused UNUSED)
{
	print_number("Len", NULL, len);
	/* byte aligned */
	passert(len == (len & -4));
	/* when len==0, msg may contain one byte :-/ */
	passert((len == 0 && msg.len <= 1) || len == msg.len * BITS_IN_BYTE);
	print_chunk("Msg", NULL, msg, 0);
	struct hash_context *hash = hash_alg->hash_ops->init(hash_alg, "sha");
	/* See above, use LEN, not MSG.LEN */
	hash_alg->hash_ops->digest_bytes(hash, "msg", msg.ptr, len / BITS_IN_BYTE);
	chunk_t bytes = alloc_chunk(l, "bytes");
	hash_alg->hash_ops->final_bytes(&hash, bytes.ptr, bytes.len);
	print_chunk("MD", NULL, bytes, 0);
	free_chunk_content(&bytes);
}

const struct cavp test_sha_msg = {
	.alias = "sha",
	.description = "SHA Algorithms (message digest)",
	.config = config,
	.print_config = print_config,
	.run_test = msg_run_test,
	.data = msg_data,
	.match = {
		"SHA.*Msg",
		NULL,
	}
};

static chunk_t seed;
static unsigned long count;

static struct cavp_entry monte_data[] = {
	{ .key = "Seed", .op = op_chunk, .chunk = &seed, },
	{ .key = "COUNT", .op = op_unsigned_long, .unsigned_long = &count},
	{ .key = "MD", .op = op_ignore, },
	{ .key = NULL, },
};

static void monte_run_test(struct logger *logger_unused UNUSED)
{
	print_chunk("Seed", NULL, seed, 0);
	chunk_t MDi_3 = alloc_chunk(seed.len, "MDi_3");
	chunk_t MDi_2 = alloc_chunk(seed.len, "MDi_2");
	chunk_t MDi_1 = alloc_chunk(seed.len, "MDi_1");
	chunk_t Mi = alloc_chunk(3 * seed.len, "Mi");
	for (int j = 0; j < 100; j++) {
		//MD[0] = MD[1] = MD[2] = Seed
		memcpy(MDi_3.ptr, seed.ptr, seed.len);
		memcpy(MDi_2.ptr, seed.ptr, seed.len);
		memcpy(MDi_1.ptr, seed.ptr, seed.len);
		for (int i = 3; i < 1003; i++) {
			// shuffle
			chunk_t tmp = MDi_3;
			MDi_3 = MDi_2;
			MDi_2 = MDi_1;
			MDi_1 = seed;
			seed = tmp;
			// M[i] = MD[i-3] || MD[i-2] || MD[i-1];
			memcpy(Mi.ptr + seed.len * 0, MDi_3.ptr, seed.len);
			memcpy(Mi.ptr + seed.len * 1, MDi_2.ptr, seed.len);
			memcpy(Mi.ptr + seed.len * 2, MDi_1.ptr, seed.len);
			// MDi = SHA(Mi);
			struct hash_context *hash = hash_alg->hash_ops->init(hash_alg,
									     "sha");
			hash_alg->hash_ops->digest_bytes(hash, "msg", Mi.ptr, Mi.len);
			hash_alg->hash_ops->final_bytes(&hash, seed.ptr, seed.len);
			// printf("%d ", i);
			// print_chunk("MDi", seed, 0);
		}
		print_line("");
		print_number("COUNT", NULL, j);
		// MDj = Seed = MD1002;
		// OUTPUT: MDj; (aka seed)
		print_chunk("MD", NULL, seed, 0);
	}
	free_chunk_content(&MDi_3);
	free_chunk_content(&MDi_2);
	free_chunk_content(&MDi_1);
	free_chunk_content(&Mi);
	print_line("");
	exit(0);
}

const struct cavp test_sha_monte = {
	.alias = "sha",
	.description = "SHA Algorithms (monte carlo)",
	.config = config,
	.print_config = print_config,
	.run_test = monte_run_test,
	.data = monte_data,
	.match = {
		"SHA.*Monte",
		NULL,
	}
};
