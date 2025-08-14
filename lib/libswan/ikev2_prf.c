/*
 * Calculate IKEv2 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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
 *
 * This code was developed with the support of Redhat corporation.
 *
 */

#include "ike_alg.h"
#include "ike_alg_prf_ikev2_ops.h"

#include "ikev2_prf.h"

#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "fips_mode.h"
#include "pexpect.h"

/*
 * IKEv2 - RFC4306 2.14 SKEYSEED - calculation.
 */

PK11SymKey *ikev2_prfplus(const struct prf_desc *prf_desc,
			  PK11SymKey *key,
			  PK11SymKey *seed,
			  size_t required_keymat,
			  struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->prfplus(prf_desc, key, seed, required_keymat, logger);
}

/*
 * SKEYSEED = prf(Ni | Nr, g^ir)
 *
 *
 */
PK11SymKey *ikev2_IKE_SA_INIT_skeyseed(const struct prf_desc *prf_desc,
				       const chunk_t Ni, const chunk_t Nr,
				       PK11SymKey *ke_secret,
				       struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->ike_sa_skeyseed(prf_desc, Ni, Nr,
							ke_secret, logger);
}

/*
 * SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
 */
PK11SymKey *ikev2_CREATE_CHILD_SA_ike_rekey_skeyseed(const struct prf_desc *prf_desc,
						     PK11SymKey *SK_d_old,
						     PK11SymKey *new_ke_secret,
						     const chunk_t Ni, const chunk_t Nr,
						     struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->ike_sa_rekey_skeyseed(prf_desc, SK_d_old,
							      new_ke_secret,
							      Ni, Nr, logger);
}

/*
 * Compute: prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
 */
PK11SymKey *ikev2_ike_sa_keymat(const struct prf_desc *prf_desc,
				PK11SymKey *skeyseed,
				const chunk_t Ni, const chunk_t Nr,
				const ike_spis_t *SPIir,
				size_t required_bytes,
				struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->ike_sa_keymat(prf_desc, skeyseed, Ni, Nr,
						      THING_AS_SHUNK(SPIir->initiator),
						      THING_AS_SHUNK(SPIir->responder),
						      required_bytes,
						      logger);
}

/*
 * Compute: SKEYSEED = prf+(PPK, SK_d)
 */
PK11SymKey *ikev2_IKE_INTERMEDIATE_ppk_skeyseed(const struct prf_desc *prf_desc,
						shunk_t ppk,
						PK11SymKey *old_SK_d,
						struct logger *logger)
{
	PK11SymKey *ppk_key = symkey_from_hunk("PPK Keying material", ppk, logger);
	PK11SymKey *skeyseed = prf_desc->prf_ikev2_ops->prfplus(prf_desc, ppk_key,
								old_SK_d,
								prf_desc->prf_key_size,
								logger);
	symkey_delref(logger, "PPK key", &ppk_key);
	return skeyseed;
}

/*
 * Compute: SKEYSEED = prf(SK_d(N-1), SK(N), Ni, Nr)
 */
PK11SymKey *ikev2_IKE_INTERMEDIATE_kem_skeyseed(const struct prf_desc *prf_desc,
						PK11SymKey *old_SK_d,
						PK11SymKey *new_ke_secret,
						const chunk_t Ni, const chunk_t Nr,
						struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->ike_sa_rekey_skeyseed(prf_desc, old_SK_d,
							      new_ke_secret,
							      Ni, Nr, logger);
}

/*
 * Compute: prf+(SK_d, [ g^ir (new) | ] Ni | Nr)
 */
PK11SymKey *ikev2_child_sa_keymat(const struct prf_desc *prf_desc,
				  PK11SymKey *SK_d,
				  PK11SymKey *new_ke_secret,
				  const chunk_t Ni, const chunk_t Nr,
				  size_t required_bytes,
				  struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->child_sa_keymat(prf_desc, SK_d, new_ke_secret,
							Ni, Nr, required_bytes,
							logger);
}

struct crypt_mac ikev2_psk_auth(const struct prf_desc *prf_desc, shunk_t pss,
				chunk_t first_packet, chunk_t nonce,
				const struct crypt_mac *id_hash,
				chunk_t intermediate_packet,
				struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->psk_auth(prf_desc, pss, first_packet, nonce,
						 id_hash, intermediate_packet, logger);
}

/*
 * SKEYSEED = prf(SK_d (old), "Resumption" | Ni | Nr)
 *
 * XXX: once NSS is figured out this should become part of the PRF
 * vector (as it was on the branch).
 */

PK11SymKey *ikev2_IKE_SESSION_RESUME_skeyseed(const struct prf_desc *prf_desc,
					      PK11SymKey *SK_d_old,
					      const chunk_t Ni, const chunk_t Nr,
					      struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->ike_sa_resume_skeyseed(prf_desc,
							       SK_d_old,
							       Ni, Nr,
							       logger);
}

/*
 * XXX: once NSS is figured out this should become part of the PRF
 * vector (as it was on the branch).
 */

struct crypt_mac ikev2_psk_resume(const struct prf_desc *prf_desc,
				  PK11SymKey *SK_px,
				  chunk_t first_packet,
				  struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->psk_resume(prf_desc, SK_px,
						   first_packet,
						   logger);
}

