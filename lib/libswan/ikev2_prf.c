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

#include "lswlog.h"
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
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "%s(%s", __func__, prf_desc->common.fqn);
		jam_string(buf, " Ni Nr");
		jam(buf, " ke_secret=");
		jam_symkey(buf, ke_secret);
		jam(buf, ") ...");
	}
	PK11SymKey *skeyseed =
		prf_desc->prf_ikev2_ops->ike_sa_skeyseed(prf_desc, Ni, Nr,
							 ke_secret, logger);
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "  ... %s() -> ", __func__);
		jam_symkey(buf, skeyseed);
	}
	return skeyseed;
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
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "%s(%s", __func__, prf_desc->common.fqn);
		jam_string(buf, " SK_d_old");
		jam_symkey(buf, SK_d_old);
		jam(buf, " new_ke_secret=");
		jam_symkey(buf, new_ke_secret);
		jam(buf, " Ni Nr) ...");
	}
	PK11SymKey *skeyseed =
		prf_desc->prf_ikev2_ops->ike_sa_rekey_skeyseed(prf_desc, SK_d_old,
							       new_ke_secret,
							       Ni, Nr, 0, NULL,
							       logger);
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "  ... %s() -> ", __func__);
		jam_symkey(buf, skeyseed);
	}
	return skeyseed;
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
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "%s(%s=", __func__, prf_desc->common.fqn);
		jam_string(buf, "skeyseed");
		jam_symkey(buf, skeyseed);
		jam(buf, " Ni Nr required_bytes=%zu SPIir", required_bytes);
		jam(buf, ") ...");
	}
	PK11SymKey *keymat =
		prf_desc->prf_ikev2_ops->ike_sa_keymat(prf_desc, skeyseed, Ni, Nr,
						       THING_AS_SHUNK(SPIir->initiator),
						       THING_AS_SHUNK(SPIir->responder),
						       required_bytes,
						       logger);
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "  ... %s() -> ", __func__);
		jam_symkey(buf, keymat);
	}
	return keymat;
}

/*
 * Compute: SKEYSEED = prf+(PPK, SK_d)
 */
PK11SymKey *ikev2_IKE_INTERMEDIATE_ppk_skeyseed(const struct prf_desc *prf_desc,
						shunk_t ppk,
						PK11SymKey *old_SK_d,
						struct logger *logger)
{
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "%s(%s", __func__, prf_desc->common.fqn);
		jam_string(buf, " ppk old_SK_d=");
		jam_symkey(buf, old_SK_d);
		jam(buf, ") ...");
	}
	PK11SymKey *ppk_key = symkey_from_hunk("PPK Keying material", ppk, logger);
	PK11SymKey *skeyseed = prf_desc->prf_ikev2_ops->prfplus(prf_desc, ppk_key,
								old_SK_d,
								prf_desc->prf_key_size,
								logger);
	symkey_delref(logger, "PPK key", &ppk_key);
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "  ... %s() -> ", __func__);
		jam_symkey(buf, skeyseed);
	}
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
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "%s(%s", __func__, prf_desc->common.fqn);
		jam_string(buf, " old_SK_d=");
		jam_symkey(buf, old_SK_d);
		jam(buf, " new_ke_secret=");
		jam_symkey(buf, new_ke_secret);
		jam(buf, " Ni Nr) ...");
	}
	PK11SymKey *skeyseed =
		prf_desc->prf_ikev2_ops->ike_sa_rekey_skeyseed(prf_desc, old_SK_d,
							       new_ke_secret,
							       Ni, Nr, 0, NULL,
							       logger);
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "  ... %s() -> ", __func__);
		jam_symkey(buf, skeyseed);
	}
	return skeyseed;
}

/*
 * Compute: SKEYSEED = prf(SK_d, SK(0) | Ni | Nr [ | SK(1) ... | SK(n) ])
 *
 * XXX: once NSS is figured out this should become part of the PRF
 * vector (as it was on the branch).
 */
PK11SymKey *ikev2_IKE_FOLLOWUP_KE_skeyseed(const struct prf_desc *prf_desc,
					   PK11SymKey *old_SK_d,
					   PK11SymKey *new_ke_secret,
					   const chunk_t Ni, const chunk_t Nr,
					   size_t nr_additional_secrets,
					   PK11SymKey **additional_secrets,
					   struct logger *logger)
{
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "%s(%s", __func__, prf_desc->common.fqn);
		jam_string(buf, " old_SK_d=");
		jam_symkey(buf, old_SK_d);
		jam(buf, " new_ke_secret=");
		jam_symkey(buf, new_ke_secret);
		jam(buf, " Ni Nr) ...");
	}

	PK11SymKey *skeyseed =
		prf_desc->prf_ikev2_ops->ike_sa_rekey_skeyseed(prf_desc, old_SK_d,
							       new_ke_secret,
							       Ni, Nr,
							       nr_additional_secrets,
							       additional_secrets,
							       logger);
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "  ... %s() -> ", __func__);
		jam_symkey(buf, skeyseed);
	}
	return skeyseed;
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
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "%s(%s", __func__, prf_desc->common.fqn);
		jam_string(buf, " SK_d=");
		jam_symkey(buf, SK_d);
		jam(buf, " new_ke_secret=");
		jam_symkey(buf, new_ke_secret);
		jam(buf, " Ni Nr required_bytes=%zu", required_bytes);
		jam_string(buf, ") ...");
	}
	PK11SymKey *keymat =
		prf_desc->prf_ikev2_ops->child_sa_keymat(prf_desc, SK_d, new_ke_secret,
							 Ni, Nr, 0, NULL,
							 required_bytes,
							 logger);
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "  ... %s() -> ", __func__);
		jam_symkey(buf, keymat);
	}
	return keymat;
}

/*
 * Compute: prf+(SK_d, g^ir (new) | Ni | Nr [ | SK(1) ... | SK(n) ])
 *
 * XXX: once NSS is figured out this should become part of the PRF
 * vector (as it was on the branch).
 */
PK11SymKey *ikev2_IKE_FOLLOWUP_KE_child_sa_keymat(const struct prf_desc *prf_desc,
						  PK11SymKey *SK_d,
						  PK11SymKey *new_ke_secret,
						  const chunk_t Ni, const chunk_t Nr,
						  size_t nr_additional_secrets,
						  PK11SymKey **additional_secrets,
						  size_t required_bytes,
						  struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->child_sa_keymat(
		prf_desc, SK_d, new_ke_secret,
		Ni, Nr,
		nr_additional_secrets,
		additional_secrets,
		required_bytes,
		logger);
}

struct crypt_mac ikev2_psk_auth(const struct prf_desc *prf_desc,
				PK11SymKey *psk,
				shunk_t first_packet,
				chunk_t nonce,
				const struct crypt_mac *id_hash,
				chunk_t intermediate_packet,
				struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->psk_auth(prf_desc, psk, first_packet, nonce,
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
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "%s(%s", __func__, prf_desc->common.fqn);
		jam_string(buf, " SK_d_old=");
		jam_symkey(buf, SK_d_old);
		jam(buf, " Ni Nr");
		jam_string(buf, ") ...");
	}
	PK11SymKey *skeyseed =
		prf_desc->prf_ikev2_ops->ike_sa_resume_skeyseed(prf_desc,
								SK_d_old,
								Ni, Nr,
								logger);
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "  ... %s() -> ", __func__);
		jam_symkey(buf, skeyseed);
	}
	return skeyseed;
}

/*
 * XXX: once NSS is figured out this should become part of the PRF
 * vector (as it was on the branch).
 */

struct crypt_mac ikev2_psk_resume(const struct prf_desc *prf_desc,
				  PK11SymKey *SK_px,
				  shunk_t first_packet,
				  struct logger *logger)
{
	return prf_desc->prf_ikev2_ops->psk_resume(prf_desc, SK_px,
						   first_packet,
						   logger);
}
