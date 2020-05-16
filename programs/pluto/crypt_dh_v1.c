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

#include "defs.h"
#include "lswlog.h"
#include "ike_alg.h"

#include "pluto_crypt.h"
#include "ikev1_prf.h"
#include "crypt_dh.h"
#include "crypt_symkey.h"
#include "crypt_hash.h"
#include "keys.h"
#include "state.h"

void cancelled_v1_dh(struct pcr_v1_dh *dh)
{
	/* query */
	free_dh_secret(&dh->secret); /* helper must be owner */
	release_symkey("cancelled IKEv1 DH", "skey_d_old", &dh->skey_d_old);

	/* response */
	release_symkey("cancelled IKEv1 DH", "shared", &dh->shared);
	release_symkey("cancelled IKEv1 DH", "skeyid", &dh->skeyid);
	release_symkey("cancelled IKEv1 DH", "skeyid_d", &dh->skeyid_d);
	release_symkey("cancelled IKEv1 DH", "skeyid_a", &dh->skeyid_a);
	release_symkey("cancelled IKEv1 DH", "skeyid_e", &dh->skeyid_e);
	release_symkey("cancelled IKEv1 DH", "enc_key", &dh->enc_key);
}

/*
 * invoke helper to do DH work (IKEv1)
 */
void start_dh_v1_secretiv(crypto_req_cont_func fn, const char *name,
			  struct state *st, enum sa_role role,
			  const struct dh_desc *oakley_group2)
{
	const chunk_t *pss = get_psk(st->st_connection, st->st_logger);

	struct pluto_crypto_req_cont *dh = new_pcrc(fn, name);
	struct pcr_v1_dh *const dhq = pcr_v1_dh_init(dh, pcr_compute_dh_iv);

	/* convert appropriate data to dhq */
	dhq->auth = st->st_oakley.auth;
	dhq->prf = st->st_oakley.ta_prf;
	dhq->oakley_group = oakley_group2;
	dhq->encrypter = st->st_oakley.ta_encrypt;
	dhq->role = role;
	dhq->key_size = st->st_oakley.enckeylen / BITS_PER_BYTE;
	dhq->salt_size = st->st_oakley.ta_encrypt->salt_size;

	passert(dhq->oakley_group != NULL && dhq->oakley_group != &unset_group);

	if (pss != NULL)
		WIRE_CLONE_CHUNK(*dhq, pss, *pss);
	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);

	transfer_dh_secret_to_helper(st, "IKEv1 DH+IV", &dhq->secret);

	ALLOC_WIRE_CHUNK(*dhq, icookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, icookie),
	       st->st_ike_spis.initiator.bytes, COOKIE_SIZE);

	ALLOC_WIRE_CHUNK(*dhq, rcookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, rcookie),
	       st->st_ike_spis.responder.bytes, COOKIE_SIZE);

	send_crypto_helper_request(st, dh);
}

bool finish_dh_secretiv(struct state *st,
			struct pluto_crypto_req *r)
{
	struct pcr_v1_dh *dhr = &r->pcr_d.v1_dh;

	transfer_dh_secret_to_state("IKEv1 DH+IV", &dhr->secret, st);

	st->st_shared_nss = dhr->shared;
	st->st_skeyid_nss = dhr->skeyid;
	st->st_skeyid_d_nss = dhr->skeyid_d;
	st->st_skeyid_a_nss = dhr->skeyid_a;
	st->st_skeyid_e_nss = dhr->skeyid_e;
	st->st_enc_key_nss = dhr->enc_key;

	st->hidden_variables.st_skeyid_calculated = TRUE;

	if (st->st_shared_nss == NULL) {
		return FALSE;
	} else {
		st->st_v1_new_iv = dhr->new_iv;
		return true;
	}
}

void start_dh_v1_secret(crypto_req_cont_func fn, const char *name,
			struct state *st, enum sa_role role,
			const struct dh_desc *oakley_group2)
{
	const chunk_t *pss = get_psk(st->st_connection, st->st_logger);
	struct pluto_crypto_req_cont *cn = new_pcrc(fn, name);
	struct pcr_v1_dh *const dhq = pcr_v1_dh_init(cn, pcr_compute_dh);

	/* convert appropriate data to dhq */
	dhq->auth = st->st_oakley.auth;
	dhq->prf = st->st_oakley.ta_prf;
	dhq->oakley_group = oakley_group2;
	dhq->role = role;
	dhq->key_size = st->st_oakley.enckeylen / BITS_PER_BYTE;
	dhq->salt_size = st->st_oakley.ta_encrypt->salt_size;

	if (pss != NULL)
		WIRE_CLONE_CHUNK(*dhq, pss, *pss);
	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);

	transfer_dh_secret_to_helper(st, "IKEv1 DH", &dhq->secret);

	ALLOC_WIRE_CHUNK(*dhq, icookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, icookie),
	       st->st_ike_spis.initiator.bytes, COOKIE_SIZE);

	ALLOC_WIRE_CHUNK(*dhq, rcookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, rcookie),
	       st->st_ike_spis.responder.bytes, COOKIE_SIZE);

	send_crypto_helper_request(st, cn);
}

/* NOTE: if NSS refuses to calculate DH, skr->shared == NULL */
/* MUST BE THREAD-SAFE */
void calc_dh(struct pcr_v1_dh *dh)
{
	const struct dh_desc *group = dh->oakley_group;
	passert(group != NULL);

	/* now calculate the (g^x)(g^y) */
	chunk_t g;
	setchunk_from_wire(g, dh, dh->role == SA_RESPONDER ? &dh->gi : &dh->gr);
	DBG(DBG_CRYPT, DBG_dump_hunk("peer's g: ", g));

	dh->shared = calc_dh_shared(dh->secret, g);
}

void finish_dh_secret(struct state *st,
		      struct pluto_crypto_req *r)
{
	struct pcr_v1_dh *dhr = &r->pcr_d.v1_dh;
	transfer_dh_secret_to_state("IKEv1 DH", &dhr->secret, st);
	st->st_shared_nss = dhr->shared;
}

/* Generate the SKEYID_* and new IV
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
/* MUST BE THREAD-SAFE */
static void calc_skeyids_iv(struct pcr_v1_dh *skq,
			    /*const*/ PK11SymKey *shared,	/* NSS doesn't do const */
			    const size_t keysize,	/* = st->st_oakley.enckeylen/BITS_PER_BYTE; */
			    PK11SymKey **skeyid_out,	/* output */
			    PK11SymKey **skeyid_d_out,	/* output */
			    PK11SymKey **skeyid_a_out,	/* output */
			    PK11SymKey **skeyid_e_out,	/* output */
			    struct crypt_mac *new_iv,	/* output */
			    PK11SymKey **enc_key_out	/* output */
			    )
{
	oakley_auth_t auth = skq->auth;
	const struct prf_desc *prf_desc = skq->prf;
	const struct hash_desc *hasher = prf_desc ? prf_desc->hasher : NULL;
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
			skeyid = ikev1_pre_shared_key_skeyid(prf_desc, pss,
							     ni, nr);
		}
		break;

	case OAKLEY_RSA_SIG:
		skeyid = ikev1_signature_skeyid(prf_desc, ni, nr, shared);
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
	PK11SymKey *skeyid_d = ikev1_skeyid_d(prf_desc, skeyid, shared,
					      icookie, rcookie);
	PK11SymKey *skeyid_a = ikev1_skeyid_a(prf_desc, skeyid, skeyid_d,
					      shared, icookie, rcookie);
	PK11SymKey *skeyid_e = ikev1_skeyid_e(prf_desc, skeyid, skeyid_a,
					      shared, icookie, rcookie);

	PK11SymKey *enc_key = ikev1_appendix_b_keymat_e(prf_desc, encrypter,
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
		DBG(DBG_CRYPT, {
			    DBG_dump_hunk("DH_i:", gi);
			    DBG_dump_hunk("DH_r:", gr);
		    });
		struct crypt_hash *ctx = crypt_hash_init("new IV", hasher);
		crypt_hash_digest_hunk(ctx, "GI", gi);
		crypt_hash_digest_hunk(ctx, "GR", gr);
		*new_iv = crypt_hash_final_mac(&ctx);
	}
}

/* MUST BE THREAD-SAFE */
void calc_dh_iv(struct pcr_v1_dh *dh)
{
	const struct dh_desc *group = dh->oakley_group;
	passert(group != NULL);

	/*
	 * Now calculate the (g^x)(g^y).
	 * Need gi on responder and gr on initiator.
	 */

	chunk_t g;
	setchunk_from_wire(g, dh,
		dh->role == SA_RESPONDER ? &dh->gi : &dh->gr);

	DBG(DBG_CRYPT, DBG_dump_hunk("peer's g: ", g));

	dh->shared = calc_dh_shared(dh->secret, g);

	if (dh->shared != NULL) {
		/* okay, so now calculate IV */
		calc_skeyids_iv(dh,
			dh->shared,
			dh->key_size,

			&dh->skeyid,	/* output */
			&dh->skeyid_d,	/* output */
			&dh->skeyid_a,	/* output */
			&dh->skeyid_e,	/* output */
			&dh->new_iv,	/* output */
			&dh->enc_key	/* output */
			);
	}
}
