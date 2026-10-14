/* AUTH constants, for libreswan
 *
 * Copyright (C) 2020, 2022, 2026 Andrew Cagney
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
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

#ifndef AUTH_H
#define AUTH_H

/*
 * List of all possible auth methods.
 *
 * If an authentication has several variants, then each gets a
 * separate entry.
 *
 * For instance RSA PKCS#1 v1.5 SHA1 has two variants: in the v2AUTH
 * RSA_DIGITAL_SIGNATURE (aka RAW) payload; or the v2AUTH new "Digital
 * Signature" payload (aka BLOB).
 *
 * BLOB is code for uses v2AUTH's Digital Signature Payload.
 *
 * XXX: the order of this enum determines the order that
 * SUPPORTED_AUTH_METHODS is emitted.
 */

enum auth {
#define AUTH_FLOOR 0

	AUTH_PSK,
	AUTH_NULL,

	AUTH_RSASSA_PKCS1_V1_5_SHA1_RAW,

	AUTH_ECDSA_SHA2_256_RAW,
	AUTH_ECDSA_SHA2_384_RAW,
	AUTH_ECDSA_SHA2_512_RAW,

	/*
	 * XXX: Full name is:
	 *
	 *   RSASSA-PSS: RSA Signature Scheme with Appendix,
	 *   Probabilistic Signature Scheme.
	 */

	AUTH_RSASSA_PSS_SHA2_512_BLOB,
	AUTH_RSASSA_PSS_SHA2_384_BLOB,
	AUTH_RSASSA_PSS_SHA2_256_BLOB,

	AUTH_ECDSA_SHA2_256_BLOB,
	AUTH_ECDSA_SHA2_384_BLOB,
	AUTH_ECDSA_SHA2_512_BLOB,

	AUTH_EDDSA_ED25519,
#if 0
	AUTH_EDDSA_ED448,
#endif

	AUTH_MLDSA_44,
	AUTH_MLDSA_65,
	AUTH_MLDSA_87,

	AUTH_RSASSA_PKCS1_V1_5_SHA2_512_BLOB,
	AUTH_RSASSA_PKCS1_V1_5_SHA2_384_BLOB,
	AUTH_RSASSA_PKCS1_V1_5_SHA2_256_BLOB,

	AUTH_RSASSA_PKCS1_V1_5_SHA1_BLOB,

	AUTH_RSASIG_IKEv1,

	AUTH_NEVER,
	AUTH_EAPONLY,

#define AUTH_ROOF (AUTH_EAPONLY+1)
};

extern const struct names auth_names;

#endif
