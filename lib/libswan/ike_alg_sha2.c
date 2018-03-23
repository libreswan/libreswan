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
#include "ike_alg_hash_nss_ops.h"
#include "ike_alg_prf_nss_ops.h"

const struct hash_desc ike_alg_hash_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.fqn = "SHA2_256",
		.names = { "sha2", "sha256", "sha2_256", },
		.officname = "sha256",
		.algo_type = IKE_ALG_HASH,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = -1,
		},
		.fips = TRUE,
	},
	.nss = {
		.oid_tag = SEC_OID_SHA256,
		.derivation_mechanism = CKM_SHA256_KEY_DERIVATION,
	},
	.hash_digest_len = SHA2_256_DIGEST_SIZE,
	.hash_block_size = 64,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,
};

const struct prf_desc ike_alg_prf_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.fqn = "HMAC_SHA2_256",
		.names = { "sha2", "sha256", "sha2_256", "hmac_sha2_256", },
		.officname = "sha256",
		.algo_type = IKE_ALG_PRF,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_256,
		},
		.fips = TRUE,
	},
	.nss = {
		.mechanism = CKM_SHA256_HMAC,
	},
	.prf_key_size = SHA2_256_DIGEST_SIZE,
	.prf_output_size = SHA2_256_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_256,
	.prf_ops = &ike_alg_prf_nss_ops,
};

const struct integ_desc ike_alg_integ_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.fqn = "HMAC_SHA2_256_128",
		.names = { "sha2", "sha256", "sha2_256", "hmac_sha2_256", "hmac_sha2_256_128", },
		.officname = "sha256",
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA2_256,
			[IKEv2_ALG_ID] = IKEv2_AUTH_HMAC_SHA2_256_128,
		},
		.fips = TRUE,
	},
	.integ_keymat_size = SHA2_256_DIGEST_SIZE,
	.integ_output_size = SHA2_256_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = AH_SHA2_256,
	.prf = &ike_alg_prf_sha2_256,
};

const struct integ_desc ike_alg_integ_hmac_sha2_256_truncbug = {
	.common = {
		.name = "hmac_sha2_256_truncbug",
		.fqn = "HMAC_SHA2_256_truncbug",
		.names = { "hmac_sha2_256_truncbug", },
		.officname = "hmac_sha2_256_truncbug",
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG,
			[IKEv2_ALG_ID] = -1,
		},
		.fips = FALSE,
	},
	.integ_keymat_size = SHA2_256_DIGEST_SIZE,
	.integ_output_size = BYTES_FOR_BITS(96),
	.integ_ikev1_ah_transform = AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG, /* YES, not AH_... */
};

const struct hash_desc ike_alg_hash_sha2_384 = {
	.common = {
		.name = "sha2_384",
		.fqn = "SHA2_384",
		.names = { "sha384", "sha2_384", },
		.officname = "sha384",
		.algo_type = IKE_ALG_HASH,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = -1,
		},
		.fips = TRUE,
	},
	.nss = {
		.oid_tag = SEC_OID_SHA384,
		.derivation_mechanism = CKM_SHA384_KEY_DERIVATION,
	},
	.hash_digest_len = SHA2_384_DIGEST_SIZE,
	.hash_block_size = 128,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,
};

const struct prf_desc ike_alg_prf_sha2_384 = {
	.common = {
		.name = "sha2_384",
		.fqn = "HMAC_SHA2_384",
		.names = { "sha384", "sha2_384", "hmac_sha2_384", },
		.officname = "sha384",
		.algo_type = IKE_ALG_PRF,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_384,
		},
		.fips = TRUE,
	},
	.nss = {
		.mechanism = CKM_SHA384_HMAC,
	},
	.prf_key_size = SHA2_384_DIGEST_SIZE,
	.prf_output_size = SHA2_384_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_384,
	.prf_ops = &ike_alg_prf_nss_ops,
};

const struct integ_desc ike_alg_integ_sha2_384 = {
	.common = {
		.name = "sha2_384",
		.fqn = "HMAC_SHA2_384_192",
		.names = { "sha384", "sha2_384", "hmac_sha2_384", "hmac_sha2_384_192", },
		.officname =  "sha384",
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA2_384,
			[IKEv2_ALG_ID] = IKEv2_AUTH_HMAC_SHA2_384_192,
		},
		.fips = TRUE,
	},
	.integ_keymat_size = SHA2_384_DIGEST_SIZE,
	.integ_output_size = SHA2_384_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = AH_SHA2_384,
	.prf = &ike_alg_prf_sha2_384,
};

const struct hash_desc ike_alg_hash_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.fqn = "SHA2_512",
		.names = { "sha512", "sha2_512", },
		.officname = "sha512",
		.algo_type = IKE_ALG_HASH,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = -1,
		},
		.fips = TRUE,
	},
	.nss = {
		.oid_tag = SEC_OID_SHA512,
		.derivation_mechanism = CKM_SHA512_KEY_DERIVATION,
	},
	.hash_digest_len = SHA2_512_DIGEST_SIZE,
	.hash_block_size = 128,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,
};

const struct prf_desc ike_alg_prf_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.fqn = "HMAC_SHA2_512",
		.names = { "sha512", "sha2_512", "hmac_sha2_512", },
		.officname = "sha512",
		.algo_type = IKE_ALG_PRF,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_512,
		},
		.fips = TRUE,
	},
	.nss = {
		.mechanism = CKM_SHA512_HMAC,
	},
	.prf_key_size = SHA2_512_DIGEST_SIZE,
	.prf_output_size = SHA2_512_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_512,
	.prf_ops = &ike_alg_prf_nss_ops,
};

const struct integ_desc ike_alg_integ_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.fqn = "HMAC_SHA2_512_256",
		.names = { "sha512", "sha2_512", "hmac_sha2_512", "hmac_sha2_512_256", },
		.officname =  "sha512",
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA2_512,
			[IKEv2_ALG_ID] = IKEv2_AUTH_HMAC_SHA2_512_256,
		},
		.fips = TRUE,
	},
	.integ_keymat_size = SHA2_512_DIGEST_SIZE,
	.integ_output_size = SHA2_512_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = AH_SHA2_512,
	.prf = &ike_alg_prf_sha2_512,
};
