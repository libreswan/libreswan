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

struct logger;
struct secret_preshared_stuff;

struct prf_ikev1_ops {
	const char *backend;

	/*
	 * SKEYID is a string derived from secret material known only
	 * to the active players in the exchange (from 3.2 Notation).
	 *
	 * For signatures:
	 *   SKEYID = prf(Ni_b | Nr_b, g^xy)
	 *
	 * For pre-shared keys:
	 *   SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
	 *
	 * For public key encryption (NOT IMPLEMENTED?):
	 *   SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R)
	 *
	 * (see 5. Exchanges)
	 */
	PK11SymKey *(*signature_skeyid)(const struct prf_desc *prf_desc,
					const chunk_t Ni_b, const chunk_t Nr_b,
					PK11SymKey *dh_secret,
					struct logger *logger);
	PK11SymKey *(*pre_shared_key_skeyid)(const struct prf_desc *prf_desc,
					     const struct secret_preshared_stuff *pre_shared_key,
					     chunk_t Ni_b, chunk_t Nr_b,
					     struct logger *logger);

	/*
	 * SKEYID_d is the keying material used to derive keys for
	 * non-ISAKMP security associations (from 3.2 Notation) (for
	 * instance SKEYID_a).
	 *
	 * 5. Exchanges:
	 *
	 *   SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
	 *
	 * If SKEYID_d's size is too small to be fed back into the PRF
	 * then, per Appendix B, it is expanded using:
	 *
	 *   BLOCK1-8 = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
	 *   BLOCK9-16 = prf(SKEYID, BLOCK1-8 | g^xy | CKY-I | CKY-R | 0)
	 *   BLOCK17-24 = prf(SKEYID, BLOCK9-16 | g^xy | CKY-I | CKY-R | 0)
	 *
	 * and:
	 *
	 *   SKEYID_d = BLOCK1-8 | BLOCK9-16 | BLOCK17-24
	 */
	PK11SymKey *(*skeyid_d)(const struct prf_desc *prf_desc,
				PK11SymKey *skeyid,
				PK11SymKey *dh_secret,
				chunk_t cky_i, chunk_t cky_r,
				struct logger *logger);

	/*
	 * SKEYID_a is the keying material used by the ISAKMP SA to
	 * authenticate its messages (from 3.2 Notation).
	 *
	 * 5. Exchanges:
	 *
	 *   SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
	 *
	 * See also Appendix B and expanding for PRF.
	 */
	PK11SymKey *(*skeyid_a)(const struct prf_desc *prf_desc,
				PK11SymKey *skeyid,
				PK11SymKey *skeyid_d, PK11SymKey *dh_secret,
				chunk_t cky_i, chunk_t cky_r,
				struct logger *logger);

	/*
	 * SKEYID_e is the keying material used by the ISAKMP SA to
	 * protect the confidentiality of its messages (from 3.2
	 * Notation).
	 *
	 * 5. Exchanges:
	 *
	 *   SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
	 *
	 * See also Appendix B and expanding for PRF.
	 */
	PK11SymKey *(*skeyid_e)(const struct prf_desc *prf_desc,
				PK11SymKey *skeyid,
				PK11SymKey *skeyid_a, PK11SymKey *dh_secret,
				chunk_t cky_i, chunk_t cky_r,
				struct logger *logger);

	/*
	 * Appendix B - IKE (ISAKMP) SA keys
	 *
	 * Encryption keys used to protect the ISAKMP SA are derived
	 * from SKEYID_e in an algorithm-specific manner. When
	 * SKEYID_e is not long enough to supply all the necessary
	 * keying material an algorithm requires, the key is derived
	 * from feeding the results of a pseudo-random function into
	 * itself, concatenating the results, and taking the highest
	 * necessary bits.
	 *
	 * KEYMAT_e = prf(SKEYID_e, 0) ... see RFC
	 *
	 *   Ka = K1 | K2 | K3 | ...
	 *
	 * where:
	 *
	 *   K1 = prf(SKEYID_e, 0)
	 *   K2 = prf(SKEYID_e, K1)
	 *   K3 = prf(SKEYID_e, K2)
	 *   etc.
	 */
	PK11SymKey *(*appendix_b_keymat_e)(const struct prf_desc *prf_desc,
					   const struct encrypt_desc *encrypter,
					   PK11SymKey *skeyid_e,
					   unsigned required_keymat,
					   struct logger *logger);

	/*
	 * Section 5.5 - CHILD (IPSEC) SA keys & Quick Mode
	 *
	 * If PFS is not needed, and KE payloads are not exchanged,
	 * the new keying material is defined as
	 *
	 *   KEYMAT = prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b).
	 *
	 * If PFS is desired and KE payloads were exchanged, the new
	 * keying material is defined as
	 *
	 *   KEYMAT = prf(SKEYID_d, g(qm)^xy | protocol | SPI | Ni_b | Nr_b)
	 *
	 * where g(qm)^xy is the shared secret from the ephemeral
	 * Diffie-Hellman exchange of this Quick Mode.
	 *
	 * For situations where the amount of keying material desired
	 * is greater than that supplied by the prf, KEYMAT is
	 * expanded by feeding the results of the prf back into itself
	 * and concatenating results until the required keying
	 * material has been reached. In other words,
	 *
	 *   KEYMAT = K1 | K2 | K3 | ...
	 *
	 * where
	 *
	 *   K1 = prf(SKEYID_d, [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b)
	 *   K2 = prf(SKEYID_d, K1 | [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b)
	 *   K3 = prf(SKEYID_d, K2 | [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b)
	 *   etc.
	 */
	chunk_t (*section_5_keymat)(const struct prf_desc *prf_desc,
				    PK11SymKey *SKEYID_d,
				    PK11SymKey *g_xy,
				    uint8_t protocol,
				    shunk_t SPI,
				    chunk_t NI_b, chunk_t Nr_b,
				    unsigned required_keymat,
				    struct logger *logger);
};

extern const struct prf_ikev1_ops ike_alg_prf_ikev1_mac_ops;
#ifdef USE_NSS_KDF
extern const struct prf_ikev1_ops ike_alg_prf_ikev1_nss_ops;
#endif

#endif
