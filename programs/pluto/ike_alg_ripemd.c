/* RIPEMD, for libreswan.
 *
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
#include "lswlog.h"
#include "lswalloc.h"
#include "ike_alg.h"
#include "ike_alg_ripemd.h"

/*
 * See: https://tools.ietf.org/html/rfc2857
 *
 * While NSS seemingly supports RIPEMD160, lets not go there.
 */

#ifdef NOT_YET
struct hash_desc ike_alg_hash_ripemd_160 = {
	.common = {
		.name = "ripemd",
		.names = { "ripemd", "ripemd160", },
		.officname = "ripemd",
		.algo_type = IKE_ALG_HASH,
		.ikev1_esp_id = AUTH_ALGORITHM_HMAC_RIPEMD,
		.nss_mechanism = CKM_RIPEMD160,
	},
	.hash_digest_len = BYTES_FOR_BITS(160),
	.hash_block_size = 64,
	.hash_ops = &ike_alg_nss_hash_ops,
};

struct prf_desc ike_alg_prf_hmac_ripemd_160 = {
	.common = {
		.name = "ripemd",
		.names = { "ripemd", "hmac_ripemd", "ripemd160", "hmac_ripemd160", },
		.officname = "ripemd",
		.algo_type = IKE_ALG_PRF,
		.ikev1_esp_id = AUTH_ALGORITHM_HMAC_RIPEMD,
		.nss_mechanism = CKM_RIPEMD160_HMAC,
	},
	.prf_key_size = RIPEMD_DIGEST_SIZE,
	.prf_output_size = RIPEMD_DIGEST_SIZE,
	.hasher = &ike_alg_hash_ripemd_160,
	.prf_ops = &ike_alg_hmac_prf_ops,
};
#endif

struct integ_desc ike_alg_integ_hmac_ripemd_160_96 = {
	.common = {
		.name = "ripemd",
		.names = { "ripemd", "hmac_ripemd", "hmac_ripemd_160_96", },
		.officname = "ripemd",
		.algo_type = IKE_ALG_INTEG,
		.ikev1_esp_id = AUTH_ALGORITHM_HMAC_RIPEMD,
	},
	.integ_key_size = BYTES_FOR_BITS(160),
	.integ_output_size = BYTES_FOR_BITS(96),
#ifdef NOT_YET
	.prf = &ike_alg_prf_ripemd_160,
#endif
};
