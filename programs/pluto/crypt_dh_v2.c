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

/* MUST BE THREAD-SAFE */
static void calc_skeyseed_v2(PK11SymKey *shared,
			     const struct encrypt_desc *encrypter,
			     const struct prf_desc *prf,
			     const struct integ_desc *integ,
			     const size_t key_size,
			     const size_t salt_size,
			     chunk_t ni,
			     chunk_t nr,
			     const ike_spis_t *ike_spis,
			     const struct prf_desc *old_prf,
			     PK11SymKey *old_skey_d,
			     /* outputs */
			     PK11SymKey **SK_d_out,
			     PK11SymKey **SK_ai_out,
			     PK11SymKey **SK_ar_out,
			     PK11SymKey **SK_ei_out,
			     PK11SymKey **SK_er_out,
			     PK11SymKey **SK_pi_out,
			     PK11SymKey **SK_pr_out,
			     chunk_t *initiator_salt_out,
			     chunk_t *responder_salt_out,
			     chunk_t *chunk_SK_pi_out,
			     chunk_t *chunk_SK_pr_out,
			     struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "NSS: Started key computation");

	passert(prf != NULL);
	dbg("calculating skeyseed using prf=%s integ=%s cipherkey-size=%zu salt-size=%zu",
	    prf->common.fqn,
	    (integ != NULL ? integ->common.fqn : "n/a"),
	    key_size, salt_size);

	passert(*SK_d_out == NULL);
	passert(*SK_ai_out == NULL);
	passert(*SK_ar_out == NULL);
	passert(*SK_ei_out == NULL);
	passert(*SK_er_out == NULL);
	passert(*SK_pi_out == NULL);
	passert(*SK_pr_out == NULL);

	PK11SymKey *skeyseed;
	if (old_skey_d == NULL) {
		/* generate SKEYSEED from key=(Ni|Nr), hash of shared */
		skeyseed = ikev2_ike_sa_skeyseed(prf, ni, nr, shared,
						 logger);
	}  else {
		skeyseed = ikev2_ike_sa_rekey_skeyseed(old_prf,
						       old_skey_d,
						       shared, ni, nr,
						       logger);
	}

	passert(skeyseed != NULL);

	/* now we have to generate the keys for everything */

	/* need to know how many bits to generate */
	/* SK_d needs PRF hasher key bytes */
	/* SK_p needs PRF hasher*2 key bytes */
	/* SK_e needs key_size*2 key bytes */
	/* ..._salt needs salt_size*2 bytes */
	/* SK_a needs integ's key size*2 bytes */

	int skd_bytes = prf->prf_key_size;
	int skp_bytes = prf->prf_key_size;
	int integ_size = integ != NULL ? integ->integ_keymat_size : 0;
	size_t total_keysize = skd_bytes + 2*skp_bytes + 2*key_size + 2*salt_size + 2*integ_size;
	PK11SymKey *finalkey = ikev2_ike_sa_keymat(prf, skeyseed,
						   ni, nr, ike_spis,
						   total_keysize, logger);
	symkey_delref(logger, "skeyseed", &skeyseed);

	size_t next_byte = 0;

	*SK_d_out = key_from_symkey_bytes("SK_d", finalkey,
					  next_byte, skd_bytes,
					  HERE, logger);
	next_byte += skd_bytes;

	*SK_ai_out = key_from_symkey_bytes("SK_ai", finalkey,
					   next_byte, integ_size,
					   HERE, logger);
	next_byte += integ_size;

	*SK_ar_out = key_from_symkey_bytes("SK_ar", finalkey,
					   next_byte, integ_size,
					   HERE, logger);
	next_byte += integ_size;

	/* The encryption key and salt are extracted together. */

	if (encrypter != NULL) {
		*SK_ei_out = encrypt_key_from_symkey_bytes("SK_ei",
							   encrypter,
							   next_byte, key_size,
							   finalkey,
							   HERE, logger);
		next_byte += key_size;
	}

	PK11SymKey *initiator_salt_key = key_from_symkey_bytes("initiator salt",
							       finalkey, next_byte,
							       salt_size,
							       HERE, logger);
	*initiator_salt_out = chunk_from_symkey("initiator salt",
						initiator_salt_key,
						logger);
	symkey_delref(logger, "initiator-salt-key", &initiator_salt_key);

	next_byte += salt_size;

	/* The encryption key and salt are extracted together. */
	if (encrypter != NULL) {
		*SK_er_out = encrypt_key_from_symkey_bytes("SK_er_k",
							   encrypter,
							   next_byte, key_size,
							   finalkey,
							   HERE, logger);
		next_byte += key_size;
	}

	PK11SymKey *responder_salt_key = key_from_symkey_bytes("responder salt",
							       finalkey, next_byte,
							       salt_size,
							       HERE, logger);
	*responder_salt_out = chunk_from_symkey("responder salt",
						responder_salt_key,
						logger);
	symkey_delref(logger, "responder-salt-key", &responder_salt_key);
	next_byte += salt_size;

	*SK_pi_out = key_from_symkey_bytes("SK_pi", finalkey,
					   next_byte, skp_bytes,
					   HERE, logger);
	/* store copy of SK_pi_k for later use in authnull */
	*chunk_SK_pi_out = chunk_from_symkey("chunk_SK_pi", *SK_pi_out, logger);

	next_byte += skp_bytes;

	*SK_pr_out = key_from_symkey_bytes("SK_pr", finalkey,
					   next_byte, skp_bytes,
					   HERE, logger);
	/* store copy of SK_pr_k for later use in authnull */
	*chunk_SK_pr_out = chunk_from_symkey("chunk_SK_pr", *SK_pr_out, logger);

	ldbgf(DBG_CRYPT, logger, "NSS ikev2: finished computing individual keys for IKEv2 SA");
	symkey_delref(logger, "finalkey", &finalkey);
}

void calc_v2_keymat(struct state *st,
		    PK11SymKey *old_skey_d, /* SKEYSEED IKE Rekey */
		    const struct prf_desc *old_prf, /* IKE Rekey */
		    const ike_spis_t *new_ike_spis)
{
	calc_skeyseed_v2(st->st_dh_shared_secret,
			 /* input */
			 st->st_oakley.ta_encrypt,
			 st->st_oakley.ta_prf,
			 st->st_oakley.ta_integ,
			 st->st_oakley.enckeylen / BITS_IN_BYTE,
			 (st->st_oakley.ta_encrypt != NULL ?
			  st->st_oakley.ta_encrypt->salt_size : 0),
			 st->st_ni, st->st_nr,
			 new_ike_spis,
			 old_prf, old_skey_d,
			 /* output */
			 &st->st_skey_d_nss,
			 &st->st_skey_ai_nss,
			 &st->st_skey_ar_nss,
			 &st->st_skey_ei_nss,
			 &st->st_skey_er_nss,
			 &st->st_skey_pi_nss,
			 &st->st_skey_pr_nss,
			 &st->st_skey_initiator_salt,
			 &st->st_skey_responder_salt,
			 &st->st_skey_chunk_SK_pi,
			 &st->st_skey_chunk_SK_pr,
			 st->logger);

	st->hidden_variables.st_skeyid_calculated = true;
}
