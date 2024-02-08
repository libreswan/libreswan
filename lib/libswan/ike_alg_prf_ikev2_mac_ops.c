/*
 * Calculate IKEv2 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

static PK11SymKey *prfplus(const struct prf_desc *prf_desc,
			   PK11SymKey *key,
			   PK11SymKey *seed,
			   size_t required_keymat,
			   struct logger *logger)
{
	uint8_t count = 1;

	/* T1(prfplus) = prf(KEY, SEED|1) */
	PK11SymKey *concatenated;
	{
		struct crypt_prf *prf = crypt_prf_init_symkey("prf+0", prf_desc,
							      "key", key,
							      logger);
		crypt_prf_update_symkey(prf, "seed", seed);
		crypt_prf_update_byte(prf, "1++", count++);
		concatenated = crypt_prf_final_symkey(&prf);
	}

	/* make a copy to keep things easy */
	PK11SymKey *old_t = reference_symkey(__func__, "old_t[1]", concatenated);
	while (sizeof_symkey(concatenated) < required_keymat) {
		/* Tn = prf(KEY, Tn-1|SEED|n) */
		struct crypt_prf *prf = crypt_prf_init_symkey("prf+N", prf_desc,
							      "key", key, logger);
		crypt_prf_update_symkey(prf, "old_t", old_t);
		crypt_prf_update_symkey(prf, "seed", seed);
		crypt_prf_update_byte(prf, "N++", count++);
		PK11SymKey *new_t = crypt_prf_final_symkey(&prf);
		append_symkey_symkey(&concatenated, new_t, logger);
		release_symkey(__func__, "old_t[N]", &old_t);
		old_t = new_t;
	}
	release_symkey(__func__, "old_t[final]", &old_t);

	/* truncate the result to match the length with required_keymat */
	PK11SymKey *result = key_from_symkey_bytes("result", concatenated,
						   0, required_keymat,
						   HERE, logger);
	release_symkey(__func__, "concatenated", &concatenated);
	return result;
}

/*
 * SKEYSEED = prf(Ni | Nr, g^ir)
 *
 *
 */
static PK11SymKey *ike_sa_skeyseed(const struct prf_desc *prf_desc,
				   const chunk_t Ni, const chunk_t Nr,
				   PK11SymKey *dh_secret,
				   struct logger *logger)
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
		chunk_t Ni64 = chunk2(Ni.ptr, BYTES_FOR_BITS(64));
		chunk_t Nr64 = chunk2(Nr.ptr, BYTES_FOR_BITS(64));
		key = clone_hunk_hunk(Ni64, Nr64, "key = Ni|Nr");
		key_name = "Ni[0:63] | Nr[0:63]";
		break;
	}
	default:
		key = clone_hunk_hunk(Ni, Nr, "key = Ni|Nr");
		key_name = "Ni | Nr";
		break;
	}
	struct crypt_prf *prf = crypt_prf_init_hunk("SKEYSEED = prf(Ni | Nr, g^ir)",
						    prf_desc,
						    key_name, key,
						    logger);
	free_chunk_content(&key);
	if (prf == NULL) {
		llog_pexpect(logger, HERE,
			     "failed to create IKEv2 PRF for computing SKEYSEED = prf(Ni | Nr, g^ir)");
		return NULL;
	}
	/* seed = g^ir */
	crypt_prf_update_symkey(prf, "g^ir", dh_secret);
	/* generate */
	return crypt_prf_final_symkey(&prf);
}

/*
 * SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
 */
static PK11SymKey *ike_sa_rekey_skeyseed(const struct prf_desc *prf_desc,
					PK11SymKey *SK_d_old,
					PK11SymKey *new_dh_secret,
					const chunk_t Ni, const chunk_t Nr,
					 struct logger *logger)
{
	/* key = SK_d (old) */
	struct crypt_prf *prf = crypt_prf_init_symkey("ike sa rekey skeyseed", prf_desc,
						      "SK_d (old)", SK_d_old,
						      logger);
	if (prf == NULL) {
		llog_pexpect(logger, HERE,
			     "failed to create IKEv2 PRF for computing SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)");
		return NULL;
	}

	/* seed: g^ir (new) | Ni | Nr) */
	crypt_prf_update_symkey(prf, "g^ir (new)", new_dh_secret);
	crypt_prf_update_hunk(prf, "Ni", Ni);
	crypt_prf_update_hunk(prf, "Nr", Nr);
	/* generate */
	return crypt_prf_final_symkey(&prf);
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
	PK11SymKey *data = symkey_from_hunk("data=Ni", Ni, logger);
	append_symkey_hunk("data+=Nr", &data, Nr, logger);
	append_symkey_hunk("data+=SPIi", &data, SPIi, logger);
	append_symkey_hunk("data+=SPIr", &data, SPIr, logger);
	PK11SymKey *result = prfplus(prf_desc,
				     skeyseed, data,
				     required_bytes,
				     logger);
	release_symkey(__func__, "data", &data);
	return result;
}

/*
 * Compute: prf+(SK_d, [ g^ir (new) | ] Ni | Nr)
 */
static PK11SymKey *child_sa_keymat(const struct prf_desc *prf_desc,
				   PK11SymKey *SK_d,
				   PK11SymKey *new_dh_secret,
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
	PK11SymKey *data;
	if (new_dh_secret == NULL) {
		data = symkey_from_hunk("data=Ni", Ni, logger);
		append_symkey_hunk("data+=Nr", &data, Nr, logger);
	} else {
		/* make a local "readonly copy" and manipulate that */
		data = reference_symkey("prf", "data", new_dh_secret);
		append_symkey_hunk("data+=Ni", &data, Ni, logger);
		append_symkey_hunk("data+=Nr", &data, Nr, logger);
	}
	PK11SymKey *result = prfplus(prf_desc,
				     SK_d, data,
				     required_bytes,
				     logger);
	release_symkey(__func__, "data", &data);
	return result;
}

static struct crypt_mac psk_auth(const struct prf_desc *prf_desc,
				 shunk_t pss,
				 chunk_t first_packet, chunk_t nonce,
				 const struct crypt_mac *id_hash,
				 chunk_t intermediate_packet,
				 struct logger *logger)
{
	/* calculate inner prf */
	PK11SymKey *prf_psk;

	{
		struct crypt_prf *prf =
			crypt_prf_init_hunk("<prf-psk> = prf(<psk>,\"Key Pad for IKEv2\")",
					    prf_desc, "shared secret", pss, logger);
		if (prf == NULL) {
			if (is_fips_mode()) {
				llog_passert(logger, HERE,
					     "FIPS: failure creating %s PRF context for digesting PSK",
					     prf_desc->common.fqn);
			}
			llog_pexpect(logger, HERE, "failure creating %s PRF context for digesting PSK",
				     prf_desc->common.fqn);
			return empty_mac;
		}

		static const char psk_key_pad_str[] = "Key Pad for IKEv2";  /* RFC 4306  2:15 */

		crypt_prf_update_bytes(prf, psk_key_pad_str, /* name */
				       psk_key_pad_str,
				       sizeof(psk_key_pad_str) - 1);
		prf_psk = crypt_prf_final_symkey(&prf);
	}

	/* calculate outer prf */
	struct crypt_mac signed_octets;
	{
		struct crypt_prf *prf =
			crypt_prf_init_symkey("<signed-octets> = prf(<prf-psk>, <msg octets>)",
					      prf_desc, "<prf-psk>", prf_psk, logger);
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
	release_symkey(__func__, "prf-psk", &prf_psk);

	return signed_octets;
}

const struct prf_ikev2_ops ike_alg_prf_ikev2_mac_ops = {
	.backend = "native",
	.prfplus = prfplus,
	.ike_sa_skeyseed = ike_sa_skeyseed,
	.ike_sa_rekey_skeyseed = ike_sa_rekey_skeyseed,
	.ike_sa_keymat = ike_sa_keymat,
	.child_sa_keymat = child_sa_keymat,
	.psk_auth = psk_auth,
};
