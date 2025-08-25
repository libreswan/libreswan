/*
 * Copyright (C) 2010-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2013 Paul Wouters <paul@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2016-2018 Sahana Prasad <sahana.prasad07@gmail.com>
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
 *
 */

#include "constants.h"		/* for BYTES_FOR_BITS() */
#include "ietf_constants.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "ike_alg_hash_ops.h"

/* SHA-2 256 */

static const uint8_t asn1_pkcs1_1_5_rsa_sha2_256_blob[1+ASN1_PKCS1_1_5_RSA_SIZE] = {
	ASN1_PKCS1_1_5_RSA_SIZE,
	ASN1_PKCS1_1_5_RSA_SHA2_256_BLOB
};
static const uint8_t asn1_ecdsa_sha2_256_blob[1+ASN1_ECDSA_SHA2_SIZE] = {
	ASN1_ECDSA_SHA2_SIZE,
	ASN1_ECDSA_SHA2_256_BLOB
};
static const uint8_t asn1_rsassa_pss_sha2_256_blob[1+ASN1_RSASSA_PSS_SHA2_SIZE] = {
	ASN1_RSASSA_PSS_SHA2_SIZE,
	ASN1_RSASSA_PSS_SHA2_256_BLOB
};

static const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_256 = {
	.hashAlg = CKM_SHA256,
	.mgf = CKG_MGF1_SHA256,
	.sLen = SHA2_256_DIGEST_SIZE,
};

const struct hash_desc ike_alg_hash_sha2_256 = {
	.common = {
		.fqn = "SHA2_256",
		.names = "sha2,sha256,sha2_256",
		.type = IKE_ALG_HASH,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_HASH_ALGORITHM_SHA2_256,
		},
		.fips = { .approved = true, },
	},
	.nss = {
		.oid_tag = SEC_OID_SHA256,
		.derivation_mechanism = CKM_SHA256_KEY_DERIVATION,
		.rsa_pkcs_pss_params = &rsa_pss_sha2_256,
		.pkcs1_1_5_rsa_oid_tag = SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
	},
	.hash_digest_size = SHA2_256_DIGEST_SIZE,
	.hash_block_size = 64,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,

	.digital_signature_blob = {
		[DIGITAL_SIGNATURE_PKCS1_1_5_RSA_BLOB] = THING_AS_HUNK(asn1_pkcs1_1_5_rsa_sha2_256_blob),
		[DIGITAL_SIGNATURE_ECDSA_BLOB] = THING_AS_HUNK(asn1_ecdsa_sha2_256_blob),
		[DIGITAL_SIGNATURE_RSASSA_PSS_BLOB] = THING_AS_HUNK(asn1_rsassa_pss_sha2_256_blob),
	},
};
