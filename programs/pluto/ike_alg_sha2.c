/*
 * Copyright (C) 2010-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2013 Paul Wouters <paul@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include "constants.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_sha2.h"
#include "ike_alg_nss_hash_ops.h"
#include "ike_alg_hmac_prf_ops.h"

struct hash_desc ike_alg_hash_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.officname = "sha256",
		.algo_type = IKE_ALG_HASH,
		.ikev1_oakley_id = OAKLEY_SHA2_256,
		.ikev2_id = IKEv2_PRF_HMAC_SHA2_256,
		.fips = TRUE,
		.nss_mechanism = CKM_SHA256,
	},
	.hash_digest_len = SHA2_256_DIGEST_SIZE,
	.hash_block_size = 64,	/* from RFC 4868 */
	.hash_ops = &ike_alg_nss_hash_ops,
};

struct prf_desc ike_alg_prf_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.officname = "sha256",
		.algo_type = IKE_ALG_PRF,
		.ikev1_oakley_id = OAKLEY_SHA2_256,
		.ikev2_id = IKEv2_PRF_HMAC_SHA2_256,
		.fips = TRUE,
	},
	.prf_key_size = SHA2_256_DIGEST_SIZE,
	.prf_output_size = SHA2_256_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_256,
	.prf_ops = &ike_alg_hmac_prf_ops,
};

struct integ_desc ike_alg_integ_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.officname = "sha256",
		.algo_type = IKE_ALG_INTEG,
		.ikev1_oakley_id = OAKLEY_SHA2_256,
		.ikev1_esp_id = AUTH_ALGORITHM_HMAC_SHA2_256,
		.ikev2_id = IKEv2_AUTH_HMAC_SHA2_256_128,
		.fips = TRUE,
	},
	.integ_key_size = SHA2_256_DIGEST_SIZE,
	.integ_output_size = SHA2_256_DIGEST_SIZE / 2,
	.prf = &ike_alg_prf_sha2_256,
};

struct hash_desc ike_alg_hash_sha2_384 = {
	.common = {
		.name = "sha2_384",
		.officname = "sha384",
		.algo_type = IKE_ALG_HASH,
		.ikev1_oakley_id = OAKLEY_SHA2_384,
		.ikev2_id = IKEv2_PRF_HMAC_SHA2_384,
		.fips = TRUE,
		.nss_mechanism = CKM_SHA384,
	},
	.hash_digest_len = SHA2_384_DIGEST_SIZE,
	.hash_block_size = 128,	/* from RFC 4868 */
	.hash_ops = &ike_alg_nss_hash_ops,
};

struct prf_desc ike_alg_prf_sha2_384 = {

	.common = {
		.name = "sha2_384",
		.officname = "sha384",
		.algo_type = IKE_ALG_PRF,
		.ikev1_oakley_id = OAKLEY_SHA2_384,
		.ikev2_id = IKEv2_PRF_HMAC_SHA2_384,
		.fips = TRUE,
	},
	.prf_key_size = SHA2_384_DIGEST_SIZE,
	.prf_output_size = SHA2_384_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_384,
	.prf_ops = &ike_alg_hmac_prf_ops,
};

struct integ_desc ike_alg_integ_sha2_384 = {
	.common = {
		.name = "sha2_384",
		.officname =  "sha384",
		.algo_type = IKE_ALG_INTEG,
		.ikev1_oakley_id = OAKLEY_SHA2_384,
		.ikev1_esp_id = AUTH_ALGORITHM_HMAC_SHA2_384,
		.ikev2_id = IKEv2_AUTH_HMAC_SHA2_384_192,
		.fips = TRUE,
	},
	.integ_key_size = SHA2_384_DIGEST_SIZE,
	.integ_output_size = SHA2_384_DIGEST_SIZE / 2,
	.prf = &ike_alg_prf_sha2_384,
};

struct hash_desc ike_alg_hash_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.officname = "sha512",
		.algo_type = IKE_ALG_HASH,
		.ikev1_oakley_id = OAKLEY_SHA2_512,
		.ikev2_id = IKEv2_PRF_HMAC_SHA2_512,
		.fips = TRUE,
		.nss_mechanism = CKM_SHA512,
	},
	.hash_digest_len = SHA2_512_DIGEST_SIZE,
	.hash_block_size = 128,	/* from RFC 4868 */
	.hash_ops = &ike_alg_nss_hash_ops,
};

struct prf_desc ike_alg_prf_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.officname = "sha512",
		.algo_type = IKE_ALG_PRF,
		.ikev1_oakley_id = OAKLEY_SHA2_512,
		.ikev2_id = IKEv2_PRF_HMAC_SHA2_512,
		.fips = TRUE,
	},
	.prf_key_size = SHA2_512_DIGEST_SIZE,
	.prf_output_size = SHA2_512_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_512,
	.prf_ops = &ike_alg_hmac_prf_ops,
};

struct integ_desc ike_alg_integ_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.officname =  "sha512",
		.algo_type = IKE_ALG_INTEG,
		.ikev1_oakley_id = OAKLEY_SHA2_512,
		.ikev1_esp_id = AUTH_ALGORITHM_HMAC_SHA2_512,
		.ikev2_id = IKEv2_AUTH_HMAC_SHA2_512_256,
		.fips = TRUE,
	},
	.integ_key_size = SHA2_512_DIGEST_SIZE,
	.integ_output_size = SHA2_512_DIGEST_SIZE / 2,
	.prf = &ike_alg_prf_sha2_512,
};
