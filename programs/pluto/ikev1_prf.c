/*
 * Calculate IKEv1 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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

#include "ikev1_prf.h"
#include "ike_alg.h"
#include "ike_alg_prf_ikev1_ops.h"

/*
 * Compute: SKEYID = prf(Ni_b | Nr_b, g^xy)
 *
 * MUST BE THREAD-SAFE
 */
PK11SymKey *ikev1_signature_skeyid(const struct prf_desc *prf_desc,
				   const chunk_t Ni,
				   const chunk_t Nr,
				   /*const*/ PK11SymKey *dh_secret /* NSS doesn't do const */,
				   struct logger *logger)
{

	return prf_desc->prf_ikev1_ops->signature_skeyid(prf_desc, Ni, Nr, dh_secret, logger);
}

/*
 * Compute: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
 */
PK11SymKey *ikev1_pre_shared_key_skeyid(const struct prf_desc *prf_desc,
					chunk_t pre_shared_key,
					chunk_t Ni, chunk_t Nr,
					struct logger *logger)
{
	return prf_desc->prf_ikev1_ops->pre_shared_key_skeyid(prf_desc, pre_shared_key, Ni, Nr, logger);
}

/*
 * SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
 */
PK11SymKey *ikev1_skeyid_d(const struct prf_desc *prf_desc,
			   PK11SymKey *skeyid,
			   PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r,
			   struct logger *logger)
{
	return prf_desc->prf_ikev1_ops->skeyid_d(prf_desc, skeyid, dh_secret, cky_i, cky_r, logger);
}

/*
 * SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
 */
PK11SymKey *ikev1_skeyid_a(const struct prf_desc *prf_desc,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_d, PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r,
			   struct logger *logger)
{
	return prf_desc->prf_ikev1_ops->skeyid_a(prf_desc, skeyid, skeyid_d, dh_secret, cky_i, cky_r, logger);
}

/*
 * SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
 */
PK11SymKey *ikev1_skeyid_e(const struct prf_desc *prf_desc,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_a, PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r,
			   struct logger *logger)
{
	return prf_desc->prf_ikev1_ops->skeyid_e(prf_desc, skeyid, skeyid_a, dh_secret, cky_i, cky_r, logger);
}

PK11SymKey *ikev1_appendix_b_keymat_e(const struct prf_desc *prf_desc,
				      const struct encrypt_desc *encrypter,
				      PK11SymKey *skeyid_e,
				      unsigned required_keymat,
				      struct logger *logger)
{
	return prf_desc->prf_ikev1_ops->appendix_b_keymat_e(prf_desc, encrypter, skeyid_e,
							    required_keymat, logger);
}

chunk_t ikev1_section_5_keymat(const struct prf_desc *prf,
			       PK11SymKey *SKEYID_d,
			       PK11SymKey *g_xy,
			       uint8_t protocol,
			       shunk_t SPI,
			       chunk_t Ni_b, chunk_t Nr_b,
			       unsigned required_keymat,
			       struct logger *logger)
{
	return prf->prf_ikev1_ops->section_5_keymat(prf, SKEYID_d,
						    g_xy, protocol, SPI,
						    Ni_b, Nr_b, required_keymat,
						    logger);
}
