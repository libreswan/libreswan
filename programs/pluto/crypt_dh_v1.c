/*
 * Cryptographic helper function - calculate DH
 *
 * Copyright (C) 2006-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015 Paul Wouters <pwouters@redaht.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
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
 *
 * This code was developed with the support of IXIA communications.
 *
 */

#include "ike_alg.h"

#include "ikev1_prf.h"
#include "crypt_dh.h"
#include "crypt_symkey.h"
#include "crypt_hash.h"
#include "keys.h"

#include "defs.h"

#include "log.h"
#include "state.h"

/* Generate the SKEYID_* and new IV
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
/* MUST BE THREAD-SAFE */

struct crypt_mac calc_v1_skeyid_and_iv(struct ike_sa *ike)
{
	const struct prf_desc *prf = ike->sa.st_oakley.ta_prf;
	const struct encrypt_desc *cipher = ike->sa.st_oakley.ta_encrypt;

	const struct secret_preshared_stuff *psk =
		get_connection_psk(ike->sa.st_connection);

	chunk_t ni = ike->sa.st_ni;
	chunk_t nr = ike->sa.st_nr;
	chunk_t icookie = chunk2(ike->sa.st_ike_spis.initiator.bytes, COOKIE_SIZE);
	chunk_t rcookie = chunk2(ike->sa.st_ike_spis.responder.bytes, COOKIE_SIZE);
	chunk_t gi = ike->sa.st_gi;
	chunk_t gr = ike->sa.st_gr;

	PK11SymKey *shared = ike->sa.st_dh_shared_secret;
	const size_t keysize = ike->sa.st_oakley.enckeylen / BITS_IN_BYTE;

	/* Generate the SKEYID */
	PK11SymKey *skeyid;
	switch (ike->sa.st_oakley.auth) {
	case OAKLEY_PRESHARED_KEY:
		skeyid = ikev1_pre_shared_key_skeyid(prf, psk,
						     ni, nr,
						     ike->sa.logger);
		break;

	case OAKLEY_RSA_SIG:
		skeyid = ikev1_signature_skeyid(prf, ni, nr, shared, ike->sa.logger);
		break;

	/* Not implemented */
	case OAKLEY_DSS_SIG:
	case OAKLEY_RSA_ENC:
	case OAKLEY_RSA_REVISED_MODE:
	case OAKLEY_ECDSA_P256:
	case OAKLEY_ECDSA_P384:
	case OAKLEY_ECDSA_P521:
	default:
		bad_case(ike->sa.st_oakley.auth);
	}

	PEXPECT(ike->sa.logger, ike->sa.st_skeyid_nss == NULL);
	PEXPECT(ike->sa.logger, ike->sa.st_v1_isakmp_skeyid_d == NULL);
	PEXPECT(ike->sa.logger, ike->sa.st_skeyid_a_nss == NULL);
	PEXPECT(ike->sa.logger, ike->sa.st_skeyid_e_nss == NULL);
	PEXPECT(ike->sa.logger, ike->sa.st_enc_key_nss == NULL);

	/* generate SKEYID_* from SKEYID */
	PK11SymKey *skeyid_d = ikev1_skeyid_d(prf, skeyid, shared,
					      icookie, rcookie,
					      ike->sa.logger);
	PK11SymKey *skeyid_a = ikev1_skeyid_a(prf, skeyid, skeyid_d,
					      shared, icookie, rcookie,
					      ike->sa.logger);
	PK11SymKey *skeyid_e = ikev1_skeyid_e(prf, skeyid, skeyid_a,
					      shared, icookie, rcookie,
					      ike->sa.logger);

	PK11SymKey *enc_key = ikev1_appendix_b_keymat_e(prf, cipher,
							skeyid_e, keysize,
							ike->sa.logger);

	ike->sa.st_skeyid_nss = skeyid;
	ike->sa.st_v1_isakmp_skeyid_d = skeyid_d;
	ike->sa.st_skeyid_a_nss = skeyid_a;
	ike->sa.st_skeyid_e_nss = skeyid_e;
	ike->sa.st_enc_key_nss = enc_key;

	ldbg(ike->sa.logger,
	     "NSS: "PRI_SO" pointers skeyid_d %p,  skeyid_a %p,  skeyid_e %p,  enc_key %p",
	     pri_so(ike->sa.st_serialno),
	     ike->sa.st_v1_isakmp_skeyid_d,
	     ike->sa.st_skeyid_a_nss,
	     ike->sa.st_skeyid_e_nss,
	     ike->sa.st_enc_key_nss);

	/* generate IV */

	if (LDBGP(DBG_CRYPT, ike->sa.logger)) {
		LDBG_log(ike->sa.logger, "DH_i");
		LDBG_hunk(ike->sa.logger, gi);
		LDBG_log(ike->sa.logger, "DH_r");
		LDBG_hunk(ike->sa.logger, gr);
	}

	struct crypt_hash *ctx = crypt_hash_init("new IV", prf->hasher, ike->sa.logger);
	crypt_hash_digest_hunk(ctx, "GI", gi);
	crypt_hash_digest_hunk(ctx, "GR", gr);
	struct crypt_mac iv = crypt_hash_final_mac(&ctx);

	PASSERT(ike->sa.logger, iv.len >= cipher->enc_blocksize);
	if (iv.len > cipher->enc_blocksize) {
		ldbg(ike->sa.logger, "truncating %zd byte IV to block size %zd",
		     iv.len, cipher->enc_blocksize);
		iv.len = cipher->enc_blocksize;
	}

	ike->sa.hidden_variables.st_skeyid_calculated = true;
	/* XXX: truncate IV.len */
	return iv;
}
