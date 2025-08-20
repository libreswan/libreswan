/* IKEv1 PRF specific operations, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#ifndef IKE_ALG_PRF_IKEv2_OPS_H
#define IKE_ALG_PRF_IKEv2_OPS_H

#include "chunk.h"
#include "shunk.h"
#include "crypt_mac.h"

struct logger;

struct prf_ikev2_ops {
	const char *backend;

	/*
	 * IKEv2 - RFC4306 2.14 SKEYSEED - calculation.
	 */
	PK11SymKey *(*prfplus)(const struct prf_desc *prf_desc,
			       PK11SymKey *key, PK11SymKey *seed,
			       size_t required_keymat,
			       struct logger *logger);
	/* SKEYSEED = prf(Ni | Nr, g^ir) */
	PK11SymKey *(*ike_sa_skeyseed)(const struct prf_desc *prf_desc,
				       const chunk_t Ni, const chunk_t Nr,
				       PK11SymKey *ke_secret,
				       struct logger *logger);
	/* SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr) */
	PK11SymKey *(*ike_sa_rekey_skeyseed)(const struct prf_desc *prf_desc,
					     PK11SymKey *old_SK_d,
					     PK11SymKey *new_ke_secret,
					     const chunk_t Ni, const chunk_t Nr,
					     struct logger *logger);
	/*
	 * IKEv2 - RFC5723 	5.1 SKEYSEED - calculation
	 * SKEYSEED = prf(SK_d (old), "Resumption" | Ni | Nr)
	 */
	PK11SymKey *(*ike_sa_resume_skeyseed)(const struct prf_desc *prf_desc,
					      PK11SymKey *old_SK_d,
					      const chunk_t Ni, const chunk_t Nr,
					      struct logger *logger);
	/* KEYMAT = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr) */
	PK11SymKey *(*ike_sa_keymat)(const struct prf_desc *prf_desc,
				     PK11SymKey *skeyseed,
				     const chunk_t Ni, const chunk_t Nr,
				     const shunk_t SPIi, const shunk_t SPIr,
				     size_t required_bytes,
				     struct logger *logger);
	/* KEYMAT = prf+(SK_d, [ g^ir (new) | ] Ni | Nr) */
	PK11SymKey *(*child_sa_keymat)(const struct prf_desc *prf_desc,
				       PK11SymKey *SK_d,
				       PK11SymKey *new_ke_secret,
				       const chunk_t Ni, const chunk_t Nr,
				       size_t required_bytes,
				       struct logger *logger);
	/* AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <{Initiator,Responder}SignedOctets>) */
	struct crypt_mac (*psk_auth)(const struct prf_desc *prf_desc,
				     PK11SymKey *psk,
				     chunk_t first_packet, chunk_t nonce,
				     const struct crypt_mac *id_hash,
				     chunk_t intermediate_packet,
				     struct logger *logger);
	/* AUTH = prf(SK_px, <message octets>) */
	struct crypt_mac (*psk_resume)(const struct prf_desc *prf_desc,
				       PK11SymKey *SK_px,
				       chunk_t first_packet,
				       struct logger *logger);
};

extern const struct prf_ikev2_ops ike_alg_prf_ikev2_mac_ops;
#ifdef USE_NSS_KDF
extern const struct prf_ikev2_ops ike_alg_prf_ikev2_nss_ops;
#endif

#endif
