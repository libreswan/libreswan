/*
 * Calculate IKEv2 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015,2017 Andrew Cagney
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
#include "lswlog.h"

#include "ikev2_prf.h"

#include "crypt_prf.h"
#include "crypt_symkey.h"

/*
 * IKEv2 - RFC4306 2.14 SKEYSEED - calculation.
 */

PK11SymKey *ikev2_prfplus(const struct prf_desc *prf_desc,
				 PK11SymKey *key, PK11SymKey *seed,
				 size_t required_keymat)
{
	uint8_t count = 1;

	/* T1(prfplus) = prf(KEY, SEED|1) */
	PK11SymKey *prfplus;
	{
		struct crypt_prf *prf = crypt_prf_init_symkey("prf+0", DBG_CRYPT,
							      prf_desc, "key", key);
		crypt_prf_update_symkey("seed", prf, seed);
		crypt_prf_update_byte("1++", prf, count++);
		prfplus = crypt_prf_final_symkey(&prf);
	}

	/* make a copy to keep things easy */
	PK11SymKey *old_t = reference_symkey(__func__, "old_t[1]", prfplus);
	while (sizeof_symkey(prfplus) < required_keymat) {
		/* Tn = prf(KEY, Tn-1|SEED|n) */
		struct crypt_prf *prf = crypt_prf_init_symkey("prf+N", DBG_CRYPT,
							      prf_desc, "key", key);
		crypt_prf_update_symkey("old_t", prf, old_t);
		crypt_prf_update_symkey("seed", prf, seed);
		crypt_prf_update_byte("N++", prf, count++);
		PK11SymKey *new_t = crypt_prf_final_symkey(&prf);
		append_symkey_symkey(&prfplus, new_t);
		release_symkey(__func__, "old_t[N]", &old_t);
		old_t = new_t;
	}
	release_symkey(__func__, "old_t[final]", &old_t);
	return prfplus;
}

/*
 * SKEYSEED = prf(Ni | Nr, g^ir)
 *
 *
 */
PK11SymKey *ikev2_ike_sa_skeyseed(const struct prf_desc *prf_desc,
				  const chunk_t Ni, const chunk_t Nr,
				  PK11SymKey *dh_secret)
{
	/*
	 * 2.14.  Generating Keying Material for the IKE SA
	 *
	 *                Ni and Nr are the nonces, stripped of any headers.  For
	 *   historical backward-compatibility reasons, there are two PRFs that
	 *   are treated specially in this calculation.  If the negotiated PRF is
	 *   AES-XCBC-PRF-128 [AESXCBCPRF128] or AES-CMAC-PRF-128 [AESCMACPRF128],
	 *   only the first 64 bits of Ni and the first 64 bits of Nr are used in
	 *   calculating SKEYSEED, but all the bits are used for input to the prf+
	 *   function.
	 */
	chunk_t key;
	const char *key_name;
	switch (prf_desc->common.id[IKEv2_ALG_ID]) {
	case IKEv2_PRF_AES128_CMAC:
	case IKEv2_PRF_AES128_XCBC:
	{
		chunk_t Ni64 = chunk(Ni.ptr, BYTES_FOR_BITS(64));
		chunk_t Nr64 = chunk(Nr.ptr, BYTES_FOR_BITS(64));
		key = clone_chunk_chunk(Ni64, Nr64, "key = Ni|Nr");
		key_name = "Ni[0:63] | Nr[0:63]";
		break;
	}
	default:
		key = clone_chunk_chunk(Ni, Nr, "key = Ni|Nr");
		key_name = "Ni | Nr";
		break;
	}
	struct crypt_prf *prf = crypt_prf_init_chunk("SKEYSEED = prf(Ni | Nr, g^ir)",
						     DBG_CRYPT, prf_desc,
						     key_name, key);
	freeanychunk(key);
	if (prf == NULL) {
		libreswan_log("failed to create IKEv2 PRF for computing SKEYSEED = prf(Ni | Nr, g^ir)");
		return NULL;
	}
	/* seed = g^ir */
	crypt_prf_update_symkey("g^ir", prf, dh_secret);
	/* generate */
	return crypt_prf_final_symkey(&prf);
}

/*
 * SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
 */
PK11SymKey *ikev2_ike_sa_rekey_skeyseed(const struct prf_desc *prf_desc,
					PK11SymKey *SK_d_old,
					PK11SymKey *new_dh_secret,
					const chunk_t Ni, const chunk_t Nr)
{
	/* key = SK_d (old) */
	struct crypt_prf *prf = crypt_prf_init_symkey("ike sa rekey skeyseed",
						      DBG_CRYPT, prf_desc,
						      "SK_d (old)", SK_d_old);
	if (prf == NULL) {
		libreswan_log("failed to create IKEv2 PRF for computing SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)");
		return NULL;
	}

	/* seed: g^ir (new) | Ni | Nr) */
	crypt_prf_update_symkey("g^ir (new)", prf, new_dh_secret);
	crypt_prf_update_chunk("Ni", prf, Ni);
	crypt_prf_update_chunk("Nr", prf, Nr);
	/* generate */
	return crypt_prf_final_symkey(&prf);
}

/*
 * Compute: prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
 */
PK11SymKey *ikev2_ike_sa_keymat(const struct prf_desc *prf_desc,
				PK11SymKey *skeyseed,
				const chunk_t Ni, const chunk_t Nr,
				const ike_spis_t *SPIir,
				size_t required_bytes)
{
	PK11SymKey *data = symkey_from_chunk("data", Ni);
	append_symkey_chunk(&data, Nr);
	append_symkey_bytes(&data, &SPIir->initiator, sizeof(SPIir->initiator));
	append_symkey_bytes(&data, &SPIir->responder, sizeof(SPIir->responder));
	PK11SymKey *prfplus = ikev2_prfplus(prf_desc,
					    skeyseed, data,
					    required_bytes);
	release_symkey(__func__, "data", &data);
	return prfplus;
}

/*
 * Compute: prf+(SK_d, [ g^ir (new) | ] Ni | Nr)
 */
PK11SymKey *ikev2_child_sa_keymat(const struct prf_desc *prf_desc,
				  PK11SymKey *SK_d,
				  PK11SymKey *new_dh_secret,
				  const chunk_t Ni, const chunk_t Nr,
				  size_t required_bytes)
{
	PK11SymKey *data;
	if (new_dh_secret == NULL) {
		data = symkey_from_chunk("data", Ni);
		append_symkey_chunk(&data, Nr);
	} else {
		data = concat_symkey_chunk(new_dh_secret, Ni);
		append_symkey_chunk(&data, Nr);
	}
	PK11SymKey *prfplus = ikev2_prfplus(prf_desc,
					    SK_d, data,
					    required_bytes);
	release_symkey(__func__, "data", &data);
	return prfplus;
}
