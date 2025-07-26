/*
 * Calculate IKEv2 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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
#include "lswlog.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "fips_mode.h"

/*
 * IKEv2 - RFC4306 2.14 SKEYSEED - calculation.
 */
static PK11SymKey *prfplus_key_data(const char *target_name,
				    const struct prf_desc *prf_desc,
				    PK11SymKey *key,
				    PK11SymKey *seed_key,
				    chunk_t    seed_data,
				    size_t required_keymat,
				    struct logger *logger)
{
	CK_NSS_IKE_PRF_PLUS_DERIVE_PARAMS ike_prf_plus_params = {
		.pSeedData = seed_data.ptr,
		.ulSeedDataLen = seed_data.len,
		.prfMechanism = prf_desc->nss.mechanism,
	};
	if (seed_key == NULL) {
		ike_prf_plus_params.bHasSeedKey = CK_FALSE;
	} else {
		ike_prf_plus_params.bHasSeedKey = CK_TRUE;
		ike_prf_plus_params.hSeedKey = PK11_GetSymKeyHandle(seed_key);
	}
	SECItem params = {
		.data = (unsigned char *)&ike_prf_plus_params,
		.len = sizeof(ike_prf_plus_params),
	};

	return crypt_derive(key, CKM_NSS_IKE_PRF_PLUS_DERIVE, &params,
			    target_name, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE,
			    /*keysize*/required_keymat, /*flags*/0,
			    HERE, logger);
}

static PK11SymKey *prfplus(const struct prf_desc *prf_desc,
			   PK11SymKey *key,
			   PK11SymKey *seed,
			   size_t required_keymat,
			   struct logger *logger)
{
	return prfplus_key_data("prfplus", prf_desc, key, seed, empty_chunk,
				required_keymat, logger);
}

/*
 * SKEYSEED = prf(Ni | Nr, g^ir)
 */
static PK11SymKey *ike_sa_skeyseed(const struct prf_desc *prf_desc,
				   const chunk_t Ni, const chunk_t Nr,
				   PK11SymKey *ke_secret,
				   struct logger *logger)
{
	int is_aes_prf = 0;
	switch (prf_desc->common.id[IKEv2_ALG_ID]) {
	case IKEv2_PRF_AES128_CMAC:
	case IKEv2_PRF_AES128_XCBC:
		is_aes_prf = 1;
	}

	CK_NSS_IKE_PRF_DERIVE_PARAMS ike_prf_params = {
		.prfMechanism = prf_desc->nss.mechanism,
		.bDataAsKey = CK_TRUE,
		.bRekey = CK_FALSE,
		.pNi = Ni.ptr,
		.ulNiLen = is_aes_prf ? BYTES_FOR_BITS(64) : Ni.len,
		.pNr = Nr.ptr,
		.ulNrLen = is_aes_prf ? BYTES_FOR_BITS(64) : Nr.len,
	};
	SECItem params = {
		.data = (unsigned char *)&ike_prf_params,
		.len = sizeof(ike_prf_params),
	};

	return crypt_derive(ke_secret, CKM_NSS_IKE_PRF_DERIVE, &params,
			    "skeyseed", CKM_NSS_IKE_PRF_PLUS_DERIVE, CKA_DERIVE,
			    /*keysize*/0, /*flags*/0,
			    HERE, logger);
}

/*
 * SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
 */
static PK11SymKey *ike_sa_rekey_skeyseed(const struct prf_desc *prf_desc,
					 PK11SymKey *SK_d_old,
					 PK11SymKey *new_ke_secret,
					 const chunk_t Ni, const chunk_t Nr,
					 struct logger *logger)
{
	CK_NSS_IKE_PRF_DERIVE_PARAMS ike_prf_params = {
		.prfMechanism = prf_desc->nss.mechanism,
		.bDataAsKey = CK_FALSE,
		.bRekey = CK_TRUE,
		.hNewKey = PK11_GetSymKeyHandle(new_ke_secret),
		.pNi = Ni.ptr,
		.ulNiLen = Ni.len,
		.pNr = Nr.ptr,
		.ulNrLen = Nr.len,
	};
	SECItem params = {
		.data = (unsigned char *)&ike_prf_params,
		.len = sizeof(ike_prf_params),
	};

	return crypt_derive(SK_d_old, CKM_NSS_IKE_PRF_DERIVE, &params,
			    "skeyseed", CKM_NSS_IKE_PRF_PLUS_DERIVE, CKA_DERIVE,
			    /*key-size*/0, /*flags*/0,
			    HERE, logger);
}

/*
 * SKEYSEED = prf(SK_d (old), "Resumption" | Ni | Nr)
 */

static PK11SymKey *ike_sa_resume_skeyseed(const struct prf_desc *prf,
						  PK11SymKey *SK_d_old,
						  const chunk_t Ni, const chunk_t Nr,
						  struct logger *logger)
{
	return ike_alg_prf_ikev2_mac_ops.ike_sa_resume_skeyseed(prf,
								SK_d_old,
								Ni, Nr,
								logger);
}

/*
 * Compute: prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
 */
static PK11SymKey *ike_sa_keymat(const struct prf_desc *prf_desc,
				 PK11SymKey *skeyseed,
				 const chunk_t Ni, const chunk_t Nr,
				 shunk_t SPIi, shunk_t SPIr,
				 size_t required_bytes,
				 struct logger *logger)
{
	PK11SymKey *prf_plus;

	chunk_t seed_data = clone_hunk_hunk(Ni, Nr, "seed_data = Ni || Nr");
	append_chunk_hunk("seed_data = Nir || SPIi", &seed_data, SPIi);
	append_chunk_hunk("seed_data = Nir || SPIir", &seed_data, SPIr);
	prf_plus = prfplus_key_data("keymat", prf_desc, skeyseed, NULL, seed_data,
				    required_bytes, logger);
	free_chunk_content(&seed_data);
	return prf_plus;
}

/*
 * Compute: prf+(SK_d, [ g^ir (new) | ] Ni | Nr)
 */
static PK11SymKey *child_sa_keymat(const struct prf_desc *prf_desc,
				   PK11SymKey *SK_d,
				   PK11SymKey *new_ke_secret,
				   const chunk_t Ni, const chunk_t Nr,
				   size_t required_bytes,
				   struct logger *logger)
{
	if (required_bytes == 0) {
		/*
		 * For instance esp=null-none.  Caller should
		 * interpret NULL to mean empty (NSS doesn't create
		 * zero length keys).
		 */
		ldbg(logger, "no CHILD SA KEMAT is required");
		return NULL;
	}
	chunk_t seed_data;
	PK11SymKey *prf_plus;

	seed_data = clone_hunk_hunk(Ni, Nr, "seed_data = Ni || Nr");
	prf_plus = prfplus_key_data("keymat", prf_desc, SK_d, new_ke_secret, seed_data,
				    required_bytes, logger);
	free_chunk_content(&seed_data);
	return prf_plus;
}

static struct crypt_mac psk_auth(const struct prf_desc *prf_desc,
				 shunk_t pss,
				 chunk_t first_packet, chunk_t nonce,
				 const struct crypt_mac *id_hash,
				 chunk_t intermediate_packet,
				 struct logger *logger)
{
	PK11SymKey *prf_psk;

	{
		static const char psk_key_pad_str[] = "Key Pad for IKEv2";  /* RFC 4306  2:15 */
		CK_MECHANISM_TYPE prf_mech = prf_desc->nss.mechanism;
		PK11SymKey *pss_key = prf_key_from_hunk("pss", prf_desc, pss, logger);
		if (pss_key == NULL) {
			if (is_fips_mode()) {
				llog_passert(logger, HERE, "FIPS: failure creating %s PRF context for digesting PSK",
					     prf_desc->common.fqn);
			}
			llog_pexpect(logger, HERE, "failure creating %s PRF context for digesting PSK",
				     prf_desc->common.fqn);
			return empty_mac;
		}

		CK_NSS_IKE_PRF_DERIVE_PARAMS ike_prf_params = {
			.prfMechanism = prf_mech,
			.bDataAsKey = CK_FALSE,
			.bRekey = CK_FALSE,
			.pNi = (CK_BYTE_PTR) psk_key_pad_str,
			.ulNiLen = sizeof(psk_key_pad_str) - 1,
			.pNr = NULL,
			.ulNrLen = 0,
		};
		SECItem params = {
			.data = (unsigned char *)&ike_prf_params,
			.len = sizeof(ike_prf_params),
		};
		prf_psk = crypt_derive(pss_key, CKM_NSS_IKE_PRF_DERIVE, &params,
				       "prf(Shared Secret, \"Key Pad for IKEv2\")", prf_mech,
				       CKA_SIGN, 0/*key-size*/, 0/*flags*/,
				       HERE, logger);
		symkey_delref(logger, "psk pss_key", &pss_key);
	}

	/* calculate outer prf */
	struct crypt_mac signed_octets;
	{
		struct crypt_prf *prf = crypt_prf_init_symkey("<signed-octets> = prf(<prf-psk>, <msg octets>)",
							      prf_desc,
							      "<prf-psk>", prf_psk,
							      logger);
		/*
		 * For the responder, the octets to be signed start
		 * with the first octet of the first SPI in the header
		 * of the second message and end with the last octet
		 * of the last payload in the second message.
		 * Appended to this (for purposes of computing the
		 * signature) are the initiator's nonce Ni (just the
		 * value, not the payload containing it), and the
		 * value prf(SK_pr,IDr') where IDr' is the responder's
		 * ID payload excluding the fixed header.  Note that
		 * neither the nonce Ni nor the value prf(SK_pr,IDr')
		 * are transmitted.
		 */
		crypt_prf_update_hunk(prf, "first-packet", first_packet);
		crypt_prf_update_hunk(prf, "nonce", nonce);
		crypt_prf_update_hunk(prf, "hash", *id_hash);
		crypt_prf_update_hunk(prf,"IntAuth", intermediate_packet);
		signed_octets = crypt_prf_final_mac(&prf, NULL);
	}
	symkey_delref(logger, "prf-psk", &prf_psk);

	return signed_octets;
}

static struct crypt_mac psk_resume(const struct prf_desc *prf,
				   PK11SymKey *SK_px,
				   chunk_t first_packet,
				   struct logger *logger)
{
	return ike_alg_prf_ikev2_mac_ops.psk_resume(prf, SK_px,
						    first_packet,
						    logger);
}

const struct prf_ikev2_ops ike_alg_prf_ikev2_nss_ops = {
	.backend = "NSS",
	.prfplus = prfplus,
	.ike_sa_skeyseed = ike_sa_skeyseed,
	.ike_sa_rekey_skeyseed = ike_sa_rekey_skeyseed,
	.ike_sa_resume_skeyseed = ike_sa_resume_skeyseed,
	.ike_sa_keymat = ike_sa_keymat,
	.child_sa_keymat = child_sa_keymat,
	.psk_auth = psk_auth,
	.psk_resume = psk_resume,
};
