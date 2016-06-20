/*
 * Calculate IKEv1 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdlib.h>
#include <stdint.h>

#include "libreswan.h"
#include "lswlog.h"
#include "constants.h"
#include "defs.h"
#include <sys/queue.h>
#include "crypto.h"
#include "crypt_dh.h"
#include "crypt_prf.h"
#include "ikev1_prf.h"
#include "ike_alg.h"
#include "packet.h"
#include "pluto_crypt.h"
#include "crypt_symkey.h"

/*
 * Compute: SKEYID = prf(Ni_b | Nr_b, g^xy)
 *
 * MUST BE THREAD-SAFE
 */
PK11SymKey *ikev1_signature_skeyid(const struct hash_desc *hasher,
				   const chunk_t Ni,
				   const chunk_t Nr,
				   /*const*/ PK11SymKey *dh_secret /* NSS doesn't do const */)
{
	struct crypt_prf *prf = crypt_prf_init("SKEYID sig", hasher, dh_secret);
	/* key = Ni|Nr */
	crypt_prf_init_chunk("Ni", prf, Ni);
	crypt_prf_init_chunk("Nr", prf, Nr);
	/* seed = g^xy */
	crypt_prf_update(prf);
	crypt_prf_update_symkey("g^xy", prf, dh_secret);
	/* generate */
	return crypt_prf_final(prf);
}

/*
 * Compute: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
 */
PK11SymKey *ikev1_pre_shared_key_skeyid(const struct hash_desc *hasher,
					chunk_t pre_shared_key,
					chunk_t Ni, chunk_t Nr,
					PK11SymKey *scratch)
{
	struct crypt_prf *prf = crypt_prf_init("SKEYID psk", hasher, scratch);
	/* key = pre-shared-key */
	crypt_prf_init_chunk("psk", prf, pre_shared_key);
	/* seed = Ni_b | Nr_b */
	crypt_prf_update(prf);
	crypt_prf_update_chunk("Ni", prf, Ni);
	crypt_prf_update_chunk("Nr", prf, Nr);
	/* generate */
	return crypt_prf_final(prf);
}

/*
 * SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
 */
PK11SymKey *ikev1_skeyid_d(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r)
{
	struct crypt_prf *prf = crypt_prf_init("SKEYID_d", hasher, dh_secret);
	/* key = SKEYID */
	crypt_prf_init_symkey("SKEYID", prf, skeyid);
	/* seed = g^xy | CKY-I | CKY-R | 0 */
	crypt_prf_update(prf);
	crypt_prf_update_symkey("g^xy", prf, dh_secret);
	crypt_prf_update_chunk("CKI_i", prf, cky_i);
	crypt_prf_update_chunk("CKI_r", prf, cky_r);
	crypt_prf_update_byte("0", prf, 0);
	/* generate */
	return crypt_prf_final(prf);
}

/*
 * SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
 */
PK11SymKey *ikev1_skeyid_a(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_d, PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r)
{
	struct crypt_prf *prf = crypt_prf_init("SKEYID_a", hasher, dh_secret);
	/* key = SKEYID */
	crypt_prf_init_symkey("SKEYID", prf, skeyid);
	/* seed = SKEYID_d | g^xy | CKY-I | CKY-R | 1 */
	crypt_prf_update(prf);
	crypt_prf_update_symkey("SKEYID_d", prf, skeyid_d);
	crypt_prf_update_symkey("g^xy", prf, dh_secret);
	crypt_prf_update_chunk("CKI_i", prf, cky_i);
	crypt_prf_update_chunk("CKI_r", prf, cky_r);
	crypt_prf_update_byte("1", prf, 1);
	/* generate */
	return crypt_prf_final(prf);
}

/*
 * SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
 */
PK11SymKey *ikev1_skeyid_e(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_a, PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r)
{
	struct crypt_prf *prf = crypt_prf_init("SKEYID_e", hasher, dh_secret);
	/* key = SKEYID */
	crypt_prf_init_symkey("SKEYID", prf, skeyid);
	/* seed = SKEYID_a | g^xy | CKY-I | CKY-R | 2 */
	crypt_prf_update(prf);
	crypt_prf_update_symkey("SKEYID_a", prf, skeyid_a);
	crypt_prf_update_symkey("g^xy", prf, dh_secret);
	crypt_prf_update_chunk("CKI_i", prf, cky_i);
	crypt_prf_update_chunk("CKI_r", prf, cky_r);
	crypt_prf_update_byte("2", prf, 2);
	/* generate */
	return crypt_prf_final(prf);
}

static PK11SymKey *appendix_b_keymat_e(const struct hash_desc *hasher,
				       const struct encrypt_desc *encrypter,
				       PK11SymKey *skeyid_e,
				       unsigned required_keymat)
{
	if (PK11_GetKeyLength(skeyid_e) >= required_keymat) {
		return encrypt_key_from_symkey_bytes(skeyid_e, encrypter, 0,
						     required_keymat);
	}
	/* K1 = prf(skeyid_e, 0) */
	PK11SymKey *keymat;
	{
		struct crypt_prf *prf = crypt_prf_init("appendix_b",
						       hasher, skeyid_e);
		crypt_prf_init_symkey("SKEYID_e", prf, skeyid_e);
		crypt_prf_update(prf);
		crypt_prf_update_byte("0", prf, 0);
		keymat = crypt_prf_final(prf);
	}

	/* make a copy to keep things easy */
	PK11SymKey *old_k = key_from_symkey_bytes(keymat, 0, PK11_GetKeyLength(keymat));
	while (PK11_GetKeyLength(keymat) < required_keymat) {
		/* Kn = prf(skeyid_e, Kn-1) */
		struct crypt_prf *prf = crypt_prf_init("SKEYID_e", hasher, skeyid_e);
		crypt_prf_init_symkey("SKEYID_e", prf, skeyid_e);
		crypt_prf_update(prf);
		crypt_prf_update_symkey("old_k", prf, old_k);
		PK11SymKey *new_k = crypt_prf_final(prf);
		append_symkey_symkey(hasher, &keymat, new_k);
		free_any_symkey("old_k#N", &old_k);
		old_k = new_k;
	}
	free_any_symkey("old_k#final", &old_k);
	PK11SymKey *cryptkey = encrypt_key_from_symkey_bytes(keymat, encrypter, 0,
							     required_keymat);
	free_any_symkey("keymat", &keymat);
	return cryptkey;
}

/* Generate the SKEYID_* and new IV
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
/* MUST BE THREAD-SAFE */
static void calc_skeyids_iv(struct pcr_skeyid_q *skq,
			    /*const*/ PK11SymKey *shared,	/* NSS doesn't do const */
			    const size_t keysize,	/* = st->st_oakley.enckeylen/BITS_PER_BYTE; */
			    PK11SymKey **skeyid_out,	/* output */
			    PK11SymKey **skeyid_d_out,	/* output */
			    PK11SymKey **skeyid_a_out,	/* output */
			    PK11SymKey **skeyid_e_out,	/* output */
			    chunk_t *new_iv,	/* output */
			    PK11SymKey **enc_key_out	/* output */
			    )
{
	oakley_auth_t auth = skq->auth;
	oakley_hash_t hash = skq->prf_hash;
	const struct hash_desc *hasher = crypto_get_hasher(hash);
	chunk_t ni;
	chunk_t nr;
	chunk_t gi;
	chunk_t gr;
	chunk_t icookie;
	chunk_t rcookie;
	const struct encrypt_desc *encrypter = skq->encrypter;

	/* this doesn't allocate any memory */
	setchunk_from_wire(gi, skq, &skq->gi);
	setchunk_from_wire(gr, skq, &skq->gr);
	setchunk_from_wire(ni, skq, &skq->ni);
	setchunk_from_wire(nr, skq, &skq->nr);
	setchunk_from_wire(icookie, skq, &skq->icookie);
	setchunk_from_wire(rcookie, skq, &skq->rcookie);

	/* Generate the SKEYID */
	PK11SymKey *skeyid;
	switch (auth) {
	case OAKLEY_PRESHARED_KEY:
		{
			chunk_t pss;

			setchunk_from_wire(pss, skq, &skq->pss);
			skeyid = ikev1_pre_shared_key_skeyid(hasher, pss,
							     ni, nr, shared);
		}
		break;

	case OAKLEY_RSA_SIG:
		skeyid = ikev1_signature_skeyid(hasher, ni, nr, shared);
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

	/* generate SKEYID_* from SKEYID */
	PK11SymKey *skeyid_d = ikev1_skeyid_d(hasher, skeyid, shared,
					      icookie, rcookie);
	PK11SymKey *skeyid_a = ikev1_skeyid_a(hasher, skeyid, skeyid_d,
					      shared, icookie, rcookie);
	PK11SymKey *skeyid_e = ikev1_skeyid_e(hasher, skeyid, skeyid_a,
					      shared, icookie, rcookie);

	PK11SymKey *enc_key = appendix_b_keymat_e(hasher, encrypter,
						  skeyid_e, keysize);

	*skeyid_out = skeyid;
	*skeyid_d_out = skeyid_d;
	*skeyid_a_out = skeyid_a;
	*skeyid_e_out = skeyid_e;
	*enc_key_out = enc_key;

	DBG(DBG_CRYPT, DBG_log("NSS: pointers skeyid_d %p,  skeyid_a %p,  skeyid_e %p,  enc_key %p",
			       skeyid_d, skeyid_a, skeyid_e, enc_key));

	/* generate IV */
	{
		union hash_ctx hash_ctx;

		new_iv->len = hasher->hash_digest_len;
		new_iv->ptr = alloc_bytes(new_iv->len, "calculated new iv");

		DBG(DBG_CRYPT, {
			    DBG_dump_chunk("DH_i:", gi);
			    DBG_dump_chunk("DH_r:", gr);
		    });
		hasher->hash_init(&hash_ctx);
		hasher->hash_update(&hash_ctx, gi.ptr, gi.len);
		hasher->hash_update(&hash_ctx, gr.ptr, gr.len);
		hasher->hash_final(new_iv->ptr, &hash_ctx);
		DBG(DBG_CRYPT, DBG_log("end of IV generation"));
	}
}

/* MUST BE THREAD-SAFE */
void calc_dh_iv(struct pluto_crypto_req *r)
{
	/* copy the request, since the reply will re-use the memory of the r->pcr_d.dhq */
	struct pcr_skeyid_q dhq;
	memcpy(&dhq, &r->pcr_d.dhq, sizeof(r->pcr_d.dhq));

	/* clear out the reply */
	struct pcr_skeyid_r *const skr = &r->pcr_d.dhr;
	zero(skr);	/* ??? pointer fields may not be NULLed */
	INIT_WIRE_ARENA(*skr);

	const struct oakley_group_desc *group = lookup_group(dhq.oakley_group);
	passert(group != NULL);

	SECKEYPrivateKey *ltsecret = dhq.secret;
	SECKEYPublicKey *pubk = dhq.pubk;

	/*
	 * Now calculate the (g^x)(g^y).
	 * Need gi on responder and gr on initiator.
	 */

	chunk_t g;
	setchunk_from_wire(g, &dhq,
		dhq.role == ORIGINAL_RESPONDER ? &dhq.gi : &dhq.gr);

	DBG(DBG_CRYPT, DBG_dump_chunk("peer's g: ", g));

	const char *story;	/* we don't use the value set in calc_dh_shared */
	skr->shared = calc_dh_shared(g, ltsecret, group, pubk, &story);

	if (skr->shared != NULL) {
		chunk_t new_iv = empty_chunk;

		/* okay, so now calculate IV */
		calc_skeyids_iv(&dhq,
			skr->shared,
			dhq.key_size,

			&skr->skeyid,	/* output */
			&skr->skeyid_d,	/* output */
			&skr->skeyid_a,	/* output */
			&skr->skeyid_e,	/* output */
			&new_iv,	/* output */
			&skr->enc_key	/* output */
			);

		WIRE_CLONE_CHUNK(*skr, new_iv, new_iv);
		freeanychunk(new_iv);
	}
}
