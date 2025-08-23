/*
 * Cryptographic helper function - calculate DH
 *
 * Copyright (C) 2006-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
 * This code was developed with the support of IXIA communications.
 *
 */

#include "ike_alg.h"
#include "crypt_symkey.h"

#include "defs.h"
#include "log.h"
#include "ikev2_prf.h"
#include "crypt_dh.h"
#include "state.h"
#include "crypt_cipher.h"

void calc_v2_ike_keymat(struct state *st,
			PK11SymKey *skeyseed,
			const ike_spis_t *ike_spis)
{
	struct logger *logger = st->logger;

	PASSERT(logger, st->st_ni.len > 0);
	PASSERT(logger, st->st_nr.len > 0);

	size_t total_keysize = nr_ikev2_ike_keymat_bytes(st);
	PK11SymKey *keymat = ikev2_ike_sa_keymat(st->st_oakley.ta_prf,
						 skeyseed,
						 st->st_ni, st->st_nr,
						 ike_spis,
						 total_keysize, logger);

	extract_ikev2_ike_keys(st, keymat);
	symkey_delref(st->logger, "keymat", &keymat);
}

size_t nr_ikev2_ike_keymat_bytes(struct state *st)
{
	const struct encrypt_desc *cipher = st->st_oakley.ta_encrypt;
	const struct prf_desc *prf = st->st_oakley.ta_prf;
	const struct integ_desc *integ = st->st_oakley.ta_integ;

	/* need to know how many bits to generate */
	/* SK_d needs PRF hasher key bytes */
	/* SK_p needs PRF hasher*2 key bytes */
	/* SK_e needs key_size*2 key bytes */
	/* ..._salt needs salt_size*2 bytes */
	/* SK_a needs integ's key size*2 bytes */

 	int skd_size = prf->prf_key_size;
 	int integ_size = integ != NULL ? integ->integ_keymat_size : 0;
	size_t key_size = st->st_oakley.enckeylen / BITS_IN_BYTE;
	size_t salt_size = cipher->salt_size;
 	int skp_size = prf->prf_key_size;

	return (skd_size +
		2 * integ_size +
		2 * (key_size + salt_size) +
		2 * skp_size);
}

void extract_ikev2_ike_keys(struct state *st,
			    PK11SymKey *keymat)
{
	struct logger *logger = st->logger;

	const struct encrypt_desc *cipher = st->st_oakley.ta_encrypt;
	const struct prf_desc *prf = st->st_oakley.ta_prf;
	const struct integ_desc *integ = st->st_oakley.ta_integ;

	size_t key_size = st->st_oakley.enckeylen / BITS_IN_BYTE;
	size_t salt_size = cipher->salt_size;

	int skd_bytes = prf->prf_key_size;
	int skp_bytes = prf->prf_key_size;
	int integ_size = integ != NULL ? integ->integ_keymat_size : 0;

	size_t next_byte = 0;

	st->st_skey_d_nss = key_from_symkey_bytes("SK_d", keymat,
						  next_byte, skd_bytes,
						  HERE, logger);
	next_byte += skd_bytes;

	st->st_skey_ai_nss = key_from_symkey_bytes("SK_ai", keymat,
						   next_byte, integ_size,
						   HERE, logger);
	next_byte += integ_size;

	st->st_skey_ar_nss = key_from_symkey_bytes("SK_ar", keymat,
						   next_byte, integ_size,
						   HERE, logger);
	next_byte += integ_size;

	/*
	 * The initiator encryption key and salt are extracted
	 * together.
	 */

	st->st_skey_ei_nss = encrypt_key_from_symkey_bytes("SK_ei",
							   cipher,
							   next_byte, key_size,
							   keymat,
							   HERE, logger);
	next_byte += key_size;

	st->st_skey_initiator_salt = chunk_from_symkey_bytes("initiator salt",
							     keymat,
							     next_byte, salt_size,
							     logger, HERE);
	next_byte += salt_size;

	/*
	 * The responder encryption key and salt are extracted
	 * together.
	 */

	st->st_skey_er_nss = encrypt_key_from_symkey_bytes("SK_er_k",
						   cipher,
						   next_byte, key_size,
						   keymat,
						   HERE, logger);
	next_byte += key_size;

	st->st_skey_responder_salt = chunk_from_symkey_bytes("responder salt",
							     keymat, next_byte,
							     salt_size,
							     logger, HERE);
	next_byte += salt_size;

	/*
	 * PPK and AUTH NULL
	 */

	st->st_skey_pi_nss = prf_key_from_symkey_bytes("SK_pi", prf,
						       next_byte, skp_bytes,
						       keymat, HERE, logger);
	next_byte += skp_bytes;

	st->st_skey_pr_nss = prf_key_from_symkey_bytes("SK_pr", prf,
						       next_byte, skp_bytes,
						       keymat, HERE, logger);
	next_byte += skp_bytes;

	switch (st->st_sa_role) {
	case SA_INITIATOR:
		/* encrypt outbound uses I */
		st->st_ike_encrypt_cipher_context =
			cipher_context_create(st->st_oakley.ta_encrypt,
					      ENCRYPT, FILL_WIRE_IV,
					      st->st_skey_ei_nss,
					      HUNK_AS_SHUNK(st->st_skey_initiator_salt),
					      st->logger);
		/* decrypt inbound uses R */
		st->st_ike_decrypt_cipher_context =
			cipher_context_create(st->st_oakley.ta_encrypt,
					      DECRYPT, USE_WIRE_IV,
					      st->st_skey_er_nss,
					      HUNK_AS_SHUNK(st->st_skey_responder_salt),
					      st->logger);
		break;
	case SA_RESPONDER:
		/* encrypt outbound uses R */
		st->st_ike_encrypt_cipher_context =
			cipher_context_create(st->st_oakley.ta_encrypt,
					      ENCRYPT, FILL_WIRE_IV,
					      st->st_skey_er_nss,
					      HUNK_AS_SHUNK(st->st_skey_responder_salt),
					      st->logger);
		/* decrypt inbound uses I */
		st->st_ike_decrypt_cipher_context =
			cipher_context_create(st->st_oakley.ta_encrypt,
					      DECRYPT, USE_WIRE_IV,
					      st->st_skey_ei_nss,
					      HUNK_AS_SHUNK(st->st_skey_initiator_salt),
					      st->logger);
		break;
	default:
		bad_case(st->st_sa_role);
	}

	st->hidden_variables.st_skeyid_calculated = true;
}
