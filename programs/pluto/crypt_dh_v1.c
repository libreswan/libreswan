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
static void calc_skeyids_iv(const struct state *st,
			    oakley_auth_t auth, chunk_t pss,
			    const struct prf_desc *prf_desc,
			    const struct encrypt_desc *encrypter,
			    chunk_t ni, chunk_t nr,
			    chunk_t icookie, chunk_t rcookie,
			    chunk_t gi, chunk_t gr,
			    /*const*/ PK11SymKey *shared,	/* NSS doesn't do const */
			    const size_t keysize,	/* = st->st_oakley.enckeylen/BITS_IN_BYTE; */
			    PK11SymKey **skeyid_out,	/* output */
			    PK11SymKey **skeyid_d_out,	/* output */
			    PK11SymKey **skeyid_a_out,	/* output */
			    PK11SymKey **skeyid_e_out,	/* output */
			    struct crypt_mac *new_iv,	/* output */
			    PK11SymKey **enc_key_out,	/* output */
			    struct logger *logger)
{
	/* Generate the SKEYID */
	PK11SymKey *skeyid;
	switch (auth) {
	case OAKLEY_PRESHARED_KEY:
		skeyid = ikev1_pre_shared_key_skeyid(prf_desc, pss,
						     ni, nr, logger);
		break;

	case OAKLEY_RSA_SIG:
		skeyid = ikev1_signature_skeyid(prf_desc, ni, nr, shared, logger);
		break;

	/* Not implemented */
	case OAKLEY_DSS_SIG:
	case OAKLEY_RSA_ENC:
	case OAKLEY_RSA_REVISED_MODE:
	case OAKLEY_ECDSA_P256:
	case OAKLEY_ECDSA_P384:
	case OAKLEY_ECDSA_P521:
	default:
		bad_case(auth);
	}

	pexpect(*skeyid_out == NULL);
	pexpect(*skeyid_d_out == NULL);
	pexpect(*skeyid_a_out == NULL);
	pexpect(*skeyid_e_out == NULL);
	pexpect(*enc_key_out == NULL);

	dbg("NSS: "PRI_SO" pointers skeyid_d %p,  skeyid_a %p,  skeyid_e %p,  enc_key %p",
	    st->st_serialno, *skeyid_d_out, *skeyid_a_out, *skeyid_e_out, *enc_key_out);

	/* generate SKEYID_* from SKEYID */
	PK11SymKey *skeyid_d = ikev1_skeyid_d(prf_desc, skeyid, shared,
					      icookie, rcookie,
					      logger);
	PK11SymKey *skeyid_a = ikev1_skeyid_a(prf_desc, skeyid, skeyid_d,
					      shared, icookie, rcookie,
					      logger);
	PK11SymKey *skeyid_e = ikev1_skeyid_e(prf_desc, skeyid, skeyid_a,
					      shared, icookie, rcookie,
					      logger);

	PK11SymKey *enc_key = ikev1_appendix_b_keymat_e(prf_desc, encrypter,
							skeyid_e, keysize,
							logger);

	*skeyid_out = skeyid;
	*skeyid_d_out = skeyid_d;
	*skeyid_a_out = skeyid_a;
	*skeyid_e_out = skeyid_e;
	*enc_key_out = enc_key;

	dbg("NSS: "PRI_SO" pointers skeyid_d %p,  skeyid_a %p,  skeyid_e %p,  enc_key %p",
	    st->st_serialno, *skeyid_d_out, *skeyid_a_out, *skeyid_e_out, *enc_key_out);

	/* generate IV */
	{
		if (DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("DH_i:", gi);
			DBG_dump_hunk("DH_r:", gr);
		}
		struct crypt_hash *ctx = crypt_hash_init("new IV", prf_desc->hasher, logger);
		crypt_hash_digest_hunk(ctx, "GI", gi);
		crypt_hash_digest_hunk(ctx, "GR", gr);
		*new_iv = crypt_hash_final_mac(&ctx);
	}
}

void calc_v1_skeyid_and_iv(struct state *st)
{
	const chunk_t *pss = get_connection_psk(st->st_connection);
	calc_skeyids_iv(st,
			st->st_oakley.auth, pss != NULL ? *pss : empty_chunk,
			st->st_oakley.ta_prf, st->st_oakley.ta_encrypt,
			st->st_ni, st->st_nr,
			chunk2(st->st_ike_spis.initiator.bytes, COOKIE_SIZE),
			chunk2(st->st_ike_spis.responder.bytes, COOKIE_SIZE),
			st->st_gi, st->st_gr,
			st->st_dh_shared_secret,
			st->st_oakley.enckeylen / BITS_IN_BYTE,
			&st->st_skeyid_nss,	/* output */
			&st->st_v1_isakmp_skeyid_d,	/* output */
			&st->st_skeyid_a_nss,	/* output */
			&st->st_skeyid_e_nss,	/* output */
			&st->st_v1_new_iv,	/* output */
			&st->st_enc_key_nss,	/* output */
			st->logger);
	st->hidden_variables.st_skeyid_calculated = true;
}
