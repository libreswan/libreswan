/* hash algorithms, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
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
#include <pkcs11t.h>

#ifdef USE_SHA1
extern const struct hash_desc ike_alg_hash_sha1;
#endif

extern const struct hash_desc ike_alg_hash_sha2_256;
#ifdef USE_SHA2
extern const struct hash_desc ike_alg_hash_sha2_384;
extern const struct hash_desc ike_alg_hash_sha2_512;
#endif

#ifdef USE_MD5
extern const struct hash_desc ike_alg_hash_md5;
#endif

extern const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_256;
extern const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_384;
extern const CK_RSA_PKCS_PSS_PARAMS rsa_pss_sha2_512;

extern const struct asn1_hash_blob asn1_rsa_pss_sha2_256;
extern const struct asn1_hash_blob asn1_rsa_pss_sha2_384;
extern const struct asn1_hash_blob asn1_rsa_pss_sha2_512;

extern const struct asn1_hash_blob asn1_ecdsa_sha2_256;
extern const struct asn1_hash_blob asn1_ecdsa_sha2_384;
extern const struct asn1_hash_blob asn1_ecdsa_sha2_512;
