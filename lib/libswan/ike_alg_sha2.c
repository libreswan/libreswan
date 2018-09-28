/*
 * Copyright (C) 2010-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2013 Paul Wouters <paul@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
#include "ike_alg_prf.h"
#include "ike_alg_integ.h"
#include "ike_alg_hash_nss_ops.h"
#include "ike_alg_prf_nss_ops.h"
#include "sadb.h"
#include <pkcs11t.h>


const struct hash_desc ike_alg_hash_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.fqn = "SHA2_256",
		.names = { "sha2", "sha256", "sha2_256", },
		.algo_type = IKE_ALG_HASH,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = -1,
		},
		.fips = true,
	},
	.nss = {
		.oid_tag = SEC_OID_SHA256,
		.derivation_mechanism = CKM_SHA256_KEY_DERIVATION,
	},
	.hash_digest_size = SHA2_256_DIGEST_SIZE,
	.hash_block_size = 64,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,
};

const struct prf_desc ike_alg_prf_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.fqn = "HMAC_SHA2_256",
		.names = { "sha2", "sha256", "sha2_256", "hmac_sha2_256", },
		.algo_type = IKE_ALG_PRF,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_256,
		},
		.fips = true,
	},
	.nss = {
		.mechanism = CKM_SHA256_HMAC,
	},
	.prf_key_size = SHA2_256_DIGEST_SIZE,
	.prf_output_size = SHA2_256_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_256,
	.prf_ops = &ike_alg_prf_nss_ops,
	.prf_ike_audit_name = "sha256",
};

const struct integ_desc ike_alg_integ_sha2_256 = {
	.common = {
		.name = "sha2_256",
		.fqn = "HMAC_SHA2_256_128",
		.names = { "sha2", "sha256", "sha2_256", "hmac_sha2_256", "hmac_sha2_256_128", },
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA2_256,
			[IKEv2_ALG_ID] = IKEv2_AUTH_HMAC_SHA2_256_128,
		},
		.fips = true,
	},
	.integ_keymat_size = SHA2_256_DIGEST_SIZE,
	.integ_output_size = SHA2_256_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = AH_SHA2_256,
	.prf = &ike_alg_prf_sha2_256,
#ifdef SADB_X_AALG_SHA2_256HMAC
	.integ_sadb_aalg_id = SADB_X_AALG_SHA2_256HMAC,
#endif
#ifdef SADB_X_AALG_SHA2_256
	.integ_sadb_aalg_id = SADB_X_AALG_SHA2_256,
#endif
	.integ_netlink_xfrm_name = "hmac(sha256)",
	.integ_tcpdump_name = "sha256",
	.integ_ike_audit_name = "sha256",
	.integ_kernel_audit_name = "HMAC_SHA2_256",
};

const struct integ_desc ike_alg_integ_hmac_sha2_256_truncbug = {
	.common = {
		.name = "hmac_sha2_256_truncbug",
		.fqn = "HMAC_SHA2_256_TRUNCBUG",
		.names = { "hmac_sha2_256_truncbug", },
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG,
			[IKEv2_ALG_ID] = -1,
		},
		.fips = false,
	},
	.integ_keymat_size = SHA2_256_DIGEST_SIZE,
	.integ_output_size = BYTES_FOR_BITS(96),
	.integ_ikev1_ah_transform = AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG, /* YES, not AH_... */
#ifdef SADB_X_AALG_SHA2_256HMAC_TRUNCBUG
	.integ_sadb_aalg_id = SADB_X_AALG_SHA2_256HMAC_TRUNCBUG,
#endif
	.integ_netlink_xfrm_name = "hmac(sha256)",
	.integ_tcpdump_name = "hmac_sha2_256_truncbug",
	.integ_ike_audit_name = "hmac_sha2_256_truncbug",
	.integ_kernel_audit_name = "HMAC_SHA2_256_TRUNCBUG",
};

const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_256 = {
	.hashAlg = CKM_SHA256,
	.mgf = CKG_MGF1_SHA256,
	.sLen = SHA2_256_DIGEST_SIZE,
};

static const uint8_t size_blob_256[ASN1_LEN_ALGO_IDENTIFIER] = LEN_RSA_PSS_SHA2_BLOB;
static const uint8_t asn1_blob_256[ASN1_SHA2_RSA_PSS_SIZE] = RSA_PSS_SHA256_BLOB;

const struct asn1_hash_blob asn1_rsa_pss_sha2_256 = {
	.hash_algo = IKEv2_AUTH_HASH_SHA2_256,
	.size = ASN1_LEN_ALGO_IDENTIFIER,
	.size_blob = size_blob_256,
	.asn1_blob_len = ASN1_SHA2_RSA_PSS_SIZE,
	.asn1_blob = asn1_blob_256,
};

static const uint8_t size_blob_ecdsa_256[ASN1_LEN_ALGO_IDENTIFIER] = LEN_ECDSA_SHA2_BLOB;
static const uint8_t asn1_blob_ecdsa_256[ASN1_SHA2_ECDSA_SIZE] = ECDSA_SHA256_BLOB;

const struct asn1_hash_blob asn1_ecdsa_sha2_256 = {
	.hash_algo = IKEv2_AUTH_HASH_SHA2_256,
	.size = ASN1_LEN_ALGO_IDENTIFIER,
	.size_blob = size_blob_ecdsa_256,
	.asn1_blob_len = ASN1_SHA2_ECDSA_SIZE,
	.asn1_blob = asn1_blob_ecdsa_256,
};

const struct hash_desc ike_alg_hash_sha2_384 = {
	.common = {
		.name = "sha2_384",
		.fqn = "SHA2_384",
		.names = { "sha384", "sha2_384", },
		.algo_type = IKE_ALG_HASH,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = -1,
		},
		.fips = true,
	},
	.nss = {
		.oid_tag = SEC_OID_SHA384,
		.derivation_mechanism = CKM_SHA384_KEY_DERIVATION,
	},
	.hash_digest_size = SHA2_384_DIGEST_SIZE,
	.hash_block_size = 128,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,
};

const struct prf_desc ike_alg_prf_sha2_384 = {
	.common = {
		.name = "sha2_384",
		.fqn = "HMAC_SHA2_384",
		.names = { "sha384", "sha2_384", "hmac_sha2_384", },
		.algo_type = IKE_ALG_PRF,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_384,
		},
		.fips = true,
	},
	.nss = {
		.mechanism = CKM_SHA384_HMAC,
	},
	.prf_key_size = SHA2_384_DIGEST_SIZE,
	.prf_output_size = SHA2_384_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_384,
	.prf_ops = &ike_alg_prf_nss_ops,
	.prf_ike_audit_name = "sha384",
};

const struct integ_desc ike_alg_integ_sha2_384 = {
	.common = {
		.name = "sha2_384",
		.fqn = "HMAC_SHA2_384_192",
		.names = { "sha384", "sha2_384", "hmac_sha2_384", "hmac_sha2_384_192", },
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA2_384,
			[IKEv2_ALG_ID] = IKEv2_AUTH_HMAC_SHA2_384_192,
		},
		.fips = true,
	},
	.integ_keymat_size = SHA2_384_DIGEST_SIZE,
	.integ_output_size = SHA2_384_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = AH_SHA2_384,
	.prf = &ike_alg_prf_sha2_384,
#ifdef SADB_X_AALG_SHA2_384HMAC
	.integ_sadb_aalg_id = SADB_X_AALG_SHA2_384HMAC,
#endif
#ifdef SADB_X_AALG_SHA2_384
	.integ_sadb_aalg_id = SADB_X_AALG_SHA2_384,
#endif
	.integ_netlink_xfrm_name = "hmac(sha384)",
	.integ_tcpdump_name = "sha384",
	.integ_ike_audit_name = "sha384",
	.integ_kernel_audit_name = "HMAC_SHA2_384",
};

const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_384 = {
	.hashAlg = CKM_SHA384,
	.mgf = CKG_MGF1_SHA384,
	.sLen = SHA2_384_DIGEST_SIZE,
};

static const uint8_t size_blob_384[ASN1_LEN_ALGO_IDENTIFIER] = LEN_RSA_PSS_SHA2_BLOB;
static const uint8_t asn1_blob_384[ASN1_SHA2_RSA_PSS_SIZE] = RSA_PSS_SHA384_BLOB;

const struct asn1_hash_blob asn1_rsa_pss_sha2_384 = {
	.hash_algo = IKEv2_AUTH_HASH_SHA2_384,
	.size = ASN1_LEN_ALGO_IDENTIFIER,
	.size_blob = size_blob_384,
	.asn1_blob_len = ASN1_SHA2_RSA_PSS_SIZE,
	.asn1_blob = asn1_blob_384,
};

static const uint8_t size_blob_ecdsa_384[ASN1_LEN_ALGO_IDENTIFIER] = LEN_ECDSA_SHA2_BLOB;
static const uint8_t asn1_blob_ecdsa_384[ASN1_SHA2_ECDSA_SIZE] = ECDSA_SHA384_BLOB;

const struct asn1_hash_blob asn1_ecdsa_sha2_384 = {
	.hash_algo = IKEv2_AUTH_HASH_SHA2_384,
	.size = ASN1_LEN_ALGO_IDENTIFIER,
	.size_blob = size_blob_ecdsa_384,
	.asn1_blob_len = ASN1_SHA2_ECDSA_SIZE,
	.asn1_blob = asn1_blob_ecdsa_384,
};

const struct hash_desc ike_alg_hash_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.fqn = "SHA2_512",
		.names = { "sha512", "sha2_512", },
		.algo_type = IKE_ALG_HASH,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = -1,
		},
		.fips = true,
	},
	.nss = {
		.oid_tag = SEC_OID_SHA512,
		.derivation_mechanism = CKM_SHA512_KEY_DERIVATION,
	},
	.hash_digest_size = SHA2_512_DIGEST_SIZE,
	.hash_block_size = 128,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,
};

const struct prf_desc ike_alg_prf_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.fqn = "HMAC_SHA2_512",
		.names = { "sha512", "sha2_512", "hmac_sha2_512", },
		.algo_type = IKE_ALG_PRF,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_512,
		},
		.fips = true,
	},
	.nss = {
		.mechanism = CKM_SHA512_HMAC,
	},
	.prf_key_size = SHA2_512_DIGEST_SIZE,
	.prf_output_size = SHA2_512_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_512,
	.prf_ops = &ike_alg_prf_nss_ops,
	.prf_ike_audit_name = "sha512",
};

const struct integ_desc ike_alg_integ_sha2_512 = {
	.common = {
		.name = "sha2_512",
		.fqn = "HMAC_SHA2_512_256",
		.names = { "sha512", "sha2_512", "hmac_sha2_512", "hmac_sha2_512_256", },
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA2_512,
			[IKEv2_ALG_ID] = IKEv2_AUTH_HMAC_SHA2_512_256,
		},
		.fips = true,
	},
	.integ_keymat_size = SHA2_512_DIGEST_SIZE,
	.integ_output_size = SHA2_512_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = AH_SHA2_512,
	.prf = &ike_alg_prf_sha2_512,
#ifdef SADB_X_AALG_SHA2_512HMAC
	.integ_sadb_aalg_id = SADB_X_AALG_SHA2_512HMAC,
#endif
#ifdef SADB_X_AALG_SHA2_512
	.integ_sadb_aalg_id = SADB_X_AALG_SHA2_512,
#endif
	.integ_netlink_xfrm_name = "hmac(sha512)",
	.integ_tcpdump_name = "sha512",
	.integ_ike_audit_name = "sha512",
	.integ_kernel_audit_name = "HMAC_SHA2_512",
};

const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_512 = {
	.hashAlg = CKM_SHA512,
	.mgf = CKG_MGF1_SHA512,
	.sLen = SHA2_512_DIGEST_SIZE,
};

static const uint8_t size_blob_512[ASN1_LEN_ALGO_IDENTIFIER] = LEN_RSA_PSS_SHA2_BLOB;
static const uint8_t asn1_blob_512[ASN1_SHA2_RSA_PSS_SIZE] = RSA_PSS_SHA512_BLOB;

const struct asn1_hash_blob asn1_rsa_pss_sha2_512 = {
	.hash_algo = IKEv2_AUTH_HASH_SHA2_512,
	.size = ASN1_LEN_ALGO_IDENTIFIER,
	.size_blob = size_blob_512,
	.asn1_blob_len = ASN1_SHA2_RSA_PSS_SIZE,
	.asn1_blob = asn1_blob_512,
};

static const uint8_t size_blob_ecdsa_512[ASN1_LEN_ALGO_IDENTIFIER] = LEN_ECDSA_SHA2_BLOB;
static const uint8_t asn1_blob_ecdsa_512[ASN1_SHA2_ECDSA_SIZE] = ECDSA_SHA512_BLOB;

const struct asn1_hash_blob asn1_ecdsa_sha2_512 = {
	.hash_algo = IKEv2_AUTH_HASH_SHA2_512,
	.size = ASN1_LEN_ALGO_IDENTIFIER,
	.size_blob = size_blob_ecdsa_512,
	.asn1_blob_len = ASN1_SHA2_ECDSA_SIZE,
	.asn1_blob = asn1_blob_ecdsa_512,
};
