/* IKEv1 specific PRF operations, for libreswan.
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKE_ALG_PRF_IKEv1_OPS_H
#define IKE_ALG_PRF_IKEv1_OPS_H

#include "chunk.h"

struct prf_ikev1_ops {
	const char *backend;

	/* SKEYID = prf(Ni_b | Nr_b, g^xy) */
	PK11SymKey *(*signature_skeyid)(const struct prf_desc *prf_desc,
					const chunk_t Ni_b, const chunk_t Nr_b,
					PK11SymKey *dh_secret);
	/* SKEYID = prf(pre-shared-key, Ni_b | Nr_b) */
	PK11SymKey *(*pre_shared_key_skeyid)(const struct prf_desc *prf_desc,
					     chunk_t pre_shared_key,
					     chunk_t Ni_b, chunk_t Nr_b);
	/* SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0) */
	PK11SymKey *(*skeyid_d)(const struct prf_desc *prf_desc,
				PK11SymKey *skeyid,
				PK11SymKey *dh_secret,
				chunk_t cky_i, chunk_t cky_r);
	/* SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1) */
	PK11SymKey *(*skeyid_a)(const struct prf_desc *prf_desc,
				PK11SymKey *skeyid,
				PK11SymKey *skeyid_d, PK11SymKey *dh_secret,
				chunk_t cky_i, chunk_t cky_r);
	/* SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2) */
	PK11SymKey *(*skeyid_e)(const struct prf_desc *prf_desc,
				PK11SymKey *skeyid,
				PK11SymKey *skeyid_a, PK11SymKey *dh_secret,
				chunk_t cky_i, chunk_t cky_r);
	/* KEYMAT_e = prf(SKEYID_e, 0) ... see RFC */
	PK11SymKey *(*appendix_b_keymat_e)(const struct prf_desc *prf_desc,
					   const struct encrypt_desc *encrypter,
					   PK11SymKey *skeyid_e,
					   unsigned required_keymat);
};

extern const struct prf_ikev1_ops ike_alg_prf_ikev1_mac_ops;

#endif
