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

#include <pkcs11t.h>

#include "constants.h"		/* for BYTES_FOR_BITS() */
#include "ietf_constants.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "ike_alg_prf.h"
#include "ike_alg_integ.h"
#include "ike_alg_hash_ops.h"
#include "ike_alg_prf_mac_ops.h"
#include "ike_alg_prf_ikev1_ops.h"
#include "ike_alg_prf_ikev2_ops.h"
#include "lsw-pfkeyv2.h"	/* for SADB_*ALG_* */

/* SHA-2 256 */

const struct prf_desc ike_alg_prf_sha2_256 = {
	.common = {
		.fqn = "HMAC_SHA2_256",
		.names = "sha2,sha256,sha2_256,hmac_sha2_256",
		.type = &ike_alg_prf,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_256,
		},
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_SHA256_HMAC,
	},
	.prf_key_size = SHA2_256_DIGEST_SIZE,
	.prf_output_size = SHA2_256_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_256,
	.prf_mac_ops = &ike_alg_prf_mac_nss_ops,
#ifdef USE_NSS_KDF
	.prf_ikev1_ops = &ike_alg_prf_ikev1_nss_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_nss_ops,
#else
	.prf_ikev1_ops = &ike_alg_prf_ikev1_mac_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_mac_ops,
#endif
	.prf_ike_audit_name = "sha256",
};

const struct integ_desc ike_alg_integ_sha2_256 = {
	.common = {
		.fqn = "HMAC_SHA2_256_128",
		.names = "sha2,sha256,sha2_256,sha2_256_128,hmac_sha2_256,hmac_sha2_256_128",
		.type = &ike_alg_integ,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_256,
			[IKEv1_IPSEC_ID] = AUTH_ALGORITHM_HMAC_SHA2_256,
			[IKEv2_ALG_ID] = IKEv2_INTEG_HMAC_SHA2_256_128,
#ifdef SADB_X_AALG_SHA2_256HMAC
			[SADB_ALG_ID] = SADB_X_AALG_SHA2_256HMAC,
#endif
#ifdef SADB_X_AALG_SHA2_256
			[SADB_ALG_ID] = SADB_X_AALG_SHA2_256,
#endif
		},
		.fips.approved = true,
	},
	.integ_keymat_size = SHA2_256_DIGEST_SIZE,
	.integ_output_size = SHA2_256_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = IKEv1_AH_SHA2_256,
	.prf = &ike_alg_prf_sha2_256,
	.integ_netlink_xfrm_name = "hmac(sha256)",
	.integ_tcpdump_name = "sha256",
	.integ_ike_audit_name = "sha256",
	.integ_kernel_audit_name = "HMAC_SHA2_256",
};

const struct integ_desc ike_alg_integ_hmac_sha2_256_truncbug = {
	.common = {
		.fqn = "HMAC_SHA2_256_TRUNCBUG",
		.names = "hmac_sha2_256_truncbug",
		.type = &ike_alg_integ,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG,
			[IKEv2_ALG_ID] = -1,
#ifdef SADB_X_AALG_SHA2_256HMAC_TRUNCBUG
			[SADB_ALG_ID] = SADB_X_AALG_SHA2_256HMAC_TRUNCBUG,
#endif
		},
		.fips.approved = false,
	},
	.integ_keymat_size = SHA2_256_DIGEST_SIZE,
	.integ_output_size = BYTES_FOR_BITS(96),
	.integ_ikev1_ah_transform = IKEv1_AH_SHA2_256_TRUNCBUG,
	.integ_netlink_xfrm_name = "hmac(sha256)",
	.integ_tcpdump_name = "hmac_sha2_256_truncbug",
	.integ_ike_audit_name = "hmac_sha2_256_truncbug",
	.integ_kernel_audit_name = "HMAC_SHA2_256_TRUNCBUG",
};

/* SHA-2 384 */

static const uint8_t asn1_pkcs1_1_5_rsa_sha2_384_blob[1+ASN1_PKCS1_1_5_RSA_SIZE] = {
	ASN1_PKCS1_1_5_RSA_SIZE,
	ASN1_PKCS1_1_5_RSA_SHA2_384_BLOB
};
static const uint8_t asn1_ecdsa_sha2_384_blob[1+ASN1_ECDSA_SHA2_SIZE] = {
	ASN1_ECDSA_SHA2_SIZE,
	ASN1_ECDSA_SHA2_384_BLOB
};
static const uint8_t asn1_rsassa_pss_sha2_384_blob[1+ASN1_RSASSA_PSS_SHA2_SIZE] = {
	ASN1_RSASSA_PSS_SHA2_SIZE,
	ASN1_RSASSA_PSS_SHA2_384_BLOB
};

const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_384 = {
	.hashAlg = CKM_SHA384,
	.mgf = CKG_MGF1_SHA384,
	.sLen = SHA2_384_DIGEST_SIZE,
};

const struct hash_desc ike_alg_hash_sha2_384 = {
	.common = {
		.fqn = "SHA2_384",
		.names = "sha384,sha2_384",
		.type = &ike_alg_hash,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] =  IKEv2_HASH_ALGORITHM_SHA2_384,
		},
		.fips.approved = true,
	},
	.nss = {
		.oid_tag = SEC_OID_SHA384,
		.derivation_mechanism = CKM_SHA384_KEY_DERIVATION,
		.rsa_pkcs_pss_params = &rsa_pss_sha2_384,
		.pkcs1_1_5_rsa_oid_tag = SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION,
	},
	.hash_digest_size = SHA2_384_DIGEST_SIZE,
	.hash_block_size = 128,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,

	.digital_signature_blob = {
		[DIGITAL_SIGNATURE_PKCS1_1_5_RSA_BLOB] = THING_AS_HUNK(asn1_pkcs1_1_5_rsa_sha2_384_blob),
		[DIGITAL_SIGNATURE_ECDSA_BLOB] = THING_AS_HUNK(asn1_ecdsa_sha2_384_blob),
		[DIGITAL_SIGNATURE_RSASSA_PSS_BLOB] = THING_AS_HUNK(asn1_rsassa_pss_sha2_384_blob),
	},
};

const struct prf_desc ike_alg_prf_sha2_384 = {
	.common = {
		.fqn = "HMAC_SHA2_384",
		.names = "sha384,sha2_384,hmac_sha2_384",
		.type = &ike_alg_prf,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_384,
		},
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_SHA384_HMAC,
	},
	.prf_key_size = SHA2_384_DIGEST_SIZE,
	.prf_output_size = SHA2_384_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_384,
	.prf_mac_ops = &ike_alg_prf_mac_nss_ops,
#ifdef USE_NSS_KDF
	.prf_ikev1_ops = &ike_alg_prf_ikev1_nss_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_nss_ops,
#else
	.prf_ikev1_ops = &ike_alg_prf_ikev1_mac_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_mac_ops,
#endif
	.prf_ike_audit_name = "sha384",
};

const struct integ_desc ike_alg_integ_sha2_384 = {
	.common = {
		.fqn = "HMAC_SHA2_384_192",
		.names = "sha384,sha2_384,sha2_384_192,hmac_sha2_384,hmac_sha2_384_192",
		.type = &ike_alg_integ,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_384,
			[IKEv1_IPSEC_ID] = AUTH_ALGORITHM_HMAC_SHA2_384,
			[IKEv2_ALG_ID] = IKEv2_INTEG_HMAC_SHA2_384_192,
#ifdef SADB_X_AALG_SHA2_384HMAC
			[SADB_ALG_ID] = SADB_X_AALG_SHA2_384HMAC,
#endif
#ifdef SADB_X_AALG_SHA2_384
			[SADB_ALG_ID] = SADB_X_AALG_SHA2_384,
#endif
		},
		.fips.approved = true,
	},
	.integ_keymat_size = SHA2_384_DIGEST_SIZE,
	.integ_output_size = SHA2_384_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = IKEv1_AH_SHA2_384,
	.prf = &ike_alg_prf_sha2_384,
	.integ_netlink_xfrm_name = "hmac(sha384)",
	.integ_tcpdump_name = "sha384",
	.integ_ike_audit_name = "sha384",
	.integ_kernel_audit_name = "HMAC_SHA2_384",
};

/* SHA-2 512 */

static const uint8_t asn1_pkcs1_1_5_rsa_sha2_512_blob[1+ASN1_PKCS1_1_5_RSA_SIZE] = {
	ASN1_PKCS1_1_5_RSA_SIZE,
	ASN1_PKCS1_1_5_RSA_SHA2_512_BLOB
};
static const uint8_t asn1_ecdsa_sha2_512_blob[1+ASN1_ECDSA_SHA2_SIZE] = {
	ASN1_ECDSA_SHA2_SIZE,
	ASN1_ECDSA_SHA2_512_BLOB
};
static const uint8_t asn1_rsassa_pss_sha2_512_blob[1+ASN1_RSASSA_PSS_SHA2_SIZE] = {
	ASN1_RSASSA_PSS_SHA2_SIZE,
	ASN1_RSASSA_PSS_SHA2_512_BLOB
};

const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_512 = {
	.hashAlg = CKM_SHA512,
	.mgf = CKG_MGF1_SHA512,
	.sLen = SHA2_512_DIGEST_SIZE,
};

const struct hash_desc ike_alg_hash_sha2_512 = {
	.common = {
		.fqn = "SHA2_512",
		.names = "sha512,sha2_512",
		.type = &ike_alg_hash,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_HASH_ALGORITHM_SHA2_512,
		},
		.fips.approved = true,
	},
	.nss = {
		.oid_tag = SEC_OID_SHA512,
		.derivation_mechanism = CKM_SHA512_KEY_DERIVATION,
		.rsa_pkcs_pss_params = &rsa_pss_sha2_512,
		.pkcs1_1_5_rsa_oid_tag = SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION,
	},
	.hash_digest_size = SHA2_512_DIGEST_SIZE,
	.hash_block_size = 128,	/* from RFC 4868 */
	.hash_ops = &ike_alg_hash_nss_ops,

	.digital_signature_blob = {
		[DIGITAL_SIGNATURE_PKCS1_1_5_RSA_BLOB] = THING_AS_HUNK(asn1_pkcs1_1_5_rsa_sha2_512_blob),
		[DIGITAL_SIGNATURE_ECDSA_BLOB] = THING_AS_HUNK(asn1_ecdsa_sha2_512_blob),
		[DIGITAL_SIGNATURE_RSASSA_PSS_BLOB] = THING_AS_HUNK(asn1_rsassa_pss_sha2_512_blob),
	},
};

const struct prf_desc ike_alg_prf_sha2_512 = {
	.common = {
		.fqn = "HMAC_SHA2_512",
		.names = "sha512,sha2_512,hmac_sha2_512",
		.type = &ike_alg_prf,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA2_512,
		},
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_SHA512_HMAC,
	},
	.prf_key_size = SHA2_512_DIGEST_SIZE,
	.prf_output_size = SHA2_512_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha2_512,
	.prf_mac_ops = &ike_alg_prf_mac_nss_ops,
#ifdef USE_NSS_KDF
	.prf_ikev1_ops = &ike_alg_prf_ikev1_nss_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_nss_ops,
#else
	.prf_ikev1_ops = &ike_alg_prf_ikev1_mac_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_mac_ops,
#endif
	.prf_ike_audit_name = "sha512",
};

const struct integ_desc ike_alg_integ_sha2_512 = {
	.common = {
		.fqn = "HMAC_SHA2_512_256",
		.names = "sha512,sha2_512,sha2_512_256,hmac_sha2_512,hmac_sha2_512_256",
		.type = &ike_alg_integ,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA2_512,
			[IKEv1_IPSEC_ID] = AUTH_ALGORITHM_HMAC_SHA2_512,
			[IKEv2_ALG_ID] = IKEv2_INTEG_HMAC_SHA2_512_256,
#ifdef SADB_X_AALG_SHA2_512HMAC
			[SADB_ALG_ID] = SADB_X_AALG_SHA2_512HMAC,
#endif
#ifdef SADB_X_AALG_SHA2_512
			[SADB_ALG_ID] = SADB_X_AALG_SHA2_512,
#endif
		},
		.fips.approved = true,
	},
	.integ_keymat_size = SHA2_512_DIGEST_SIZE,
	.integ_output_size = SHA2_512_DIGEST_SIZE / 2,
	.integ_ikev1_ah_transform = IKEv1_AH_SHA2_512,
	.prf = &ike_alg_prf_sha2_512,
	.integ_netlink_xfrm_name = "hmac(sha512)",
	.integ_tcpdump_name = "sha512",
	.integ_ike_audit_name = "sha512",
	.integ_kernel_audit_name = "HMAC_SHA2_512",
};
