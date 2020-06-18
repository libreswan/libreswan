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

#include "defs.h"
#include "lswlog.h"
#include "ike_alg.h"

#include "pluto_crypt.h"
#include "ikev2_prf.h"
#include "crypt_dh.h"
#include "crypt_symkey.h"
#include "state.h"

void cancelled_dh_v2(struct pcr_dh_v2 *dh)
{
	/* incoming */

	free_dh_secret(&dh->secret); /* must own */
	release_symkey("cancelled IKEv2 DH", "skey_d_old", &dh->skey_d_old);

	/* outgoing */
	release_symkey("cancelled IKEv2 DH", "shared", &dh->shared);
	release_symkey("cancelled IKEv2 DH", "skeyid_d", &dh->skeyid_d);
	release_symkey("cancelled IKEv2 DH", "skeyid_ai", &dh->skeyid_ai);
	release_symkey("cancelled IKEv2 DH", "skeyid_ar", &dh->skeyid_ar);
	release_symkey("cancelled IKEv2 DH", "skeyid_ei", &dh->skeyid_ei);
	release_symkey("cancelled IKEv2 DH", "skeyid_er", &dh->skeyid_er);
	release_symkey("cancelled IKEv2 DH", "skeyid_pi", &dh->skeyid_pi);
	release_symkey("cancelled IKEv2 DH", "skeyid_pr", &dh->skeyid_pr);

	free_chunk_content(&dh->skey_initiator_salt);
	free_chunk_content(&dh->skey_responder_salt);
	free_chunk_content(&dh->skey_chunk_SK_pi);
	free_chunk_content(&dh->skey_chunk_SK_pr);
}

/*
 * invoke helper to do DH work.
 */
void start_dh_v2(struct state *st,
		 const char *name, enum sa_role role,
		 PK11SymKey *skey_d_old, /* SKEYSEED IKE Rekey */
		 const struct prf_desc *old_prf, /* IKE Rekey */
		 const ike_spis_t *new_ike_spis,
		 crypto_req_cont_func pcrc_func)
{
	struct pluto_crypto_req_cont *dh = new_pcrc(pcrc_func, name);
	struct pcr_dh_v2 *const dhq = pcr_dh_v2_init(dh);

	dbg("offloading IKEv2 SKEYSEED using prf=%s integ=%s cipherkey=%s",
	    st->st_oakley.ta_prf->common.fqn,
	    st->st_oakley.ta_integ->common.fqn,
	    st->st_oakley.ta_encrypt != NULL ?
	    st->st_oakley.ta_encrypt->common.fqn : "N/A");

	/* convert appropriate data to dhq */
	dhq->prf = st->st_oakley.ta_prf;
	dhq->integ = st->st_oakley.ta_integ;
	dhq->dh = st->st_oakley.ta_dh;
	dhq->encrypt = st->st_oakley.ta_encrypt;
	dhq->role = role;
	dhq->key_size = st->st_oakley.enckeylen / BITS_PER_BYTE;
	dhq->salt_size = st->st_oakley.ta_encrypt != NULL ?
		st->st_oakley.ta_encrypt->salt_size : 0;

	passert(dhq->dh != NULL && dhq->dh != &unset_group);

	dhq->old_prf = old_prf;
	dhq->skey_d_old = reference_symkey(__func__, "skey_d_old", skey_d_old);
	if (skey_d_old != NULL) {
		passert(old_prf != NULL);
	}

	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);

	transfer_dh_secret_to_helper(st, "IKEv2 DH", &dhq->secret);

	dhq->ike_spis = *new_ike_spis;

	send_crypto_helper_request(st, dh);
}

bool finish_dh_v2(struct state *st,
		  struct pluto_crypto_req *r,  bool only_shared)
{
	struct pcr_dh_v2 *dhv2 = &r->pcr_d.dh_v2;

	transfer_dh_secret_to_state("IKEv2 DH", &dhv2->secret, st);

	release_symkey(__func__, "st_shared_nss", &st->st_shared_nss);
	st->st_shared_nss = dhv2->shared;

	if (only_shared) {
#define free_any_symkey(p) release_symkey(__func__, #p, &p)
		free_any_symkey(dhv2->skeyid_d);
		free_any_symkey(dhv2->skeyid_ai);
		free_any_symkey(dhv2->skeyid_ar);
		free_any_symkey(dhv2->skeyid_pi);
		free_any_symkey(dhv2->skeyid_pr);
		free_any_symkey(dhv2->skeyid_ei);
		free_any_symkey(dhv2->skeyid_er);
#undef free_any_symkey

		free_chunk_content(&dhv2->skey_initiator_salt);
		free_chunk_content(&dhv2->skey_responder_salt);
		free_chunk_content(&dhv2->skey_chunk_SK_pi);
		free_chunk_content(&dhv2->skey_chunk_SK_pr);
	} else {
		pexpect(st->st_skey_d_nss == NULL);
		st->st_skey_d_nss = dhv2->skeyid_d;

		pexpect(st->st_skey_ai_nss == NULL);

		pexpect(st->st_skey_ai_nss == NULL);
		st->st_skey_ai_nss = dhv2->skeyid_ai;

		pexpect(st->st_skey_ar_nss == NULL);
		st->st_skey_ar_nss = dhv2->skeyid_ar;

		pexpect(st->st_skey_pi_nss== NULL);
		st->st_skey_pi_nss = dhv2->skeyid_pi;

		pexpect(st->st_skey_pr_nss== NULL);
		st->st_skey_pr_nss = dhv2->skeyid_pr;

		pexpect(st->st_skey_ei_nss== NULL);
		st->st_skey_ei_nss = dhv2->skeyid_ei;

		pexpect(st->st_skey_er_nss== NULL);
		st->st_skey_er_nss = dhv2->skeyid_er;

		st->st_skey_initiator_salt = dhv2->skey_initiator_salt;
		st->st_skey_responder_salt = dhv2->skey_responder_salt;
		st->st_skey_chunk_SK_pi = dhv2->skey_chunk_SK_pi;
		st->st_skey_chunk_SK_pr = dhv2->skey_chunk_SK_pr;
	}

	st->hidden_variables.st_skeyid_calculated = TRUE;
	return st->st_shared_nss != NULL;	/* was NSS happy to DH? */
}

/* MUST BE THREAD-SAFE */
static void calc_skeyseed_v2(struct pcr_dh_v2 *sk,
			     PK11SymKey *shared,
			     const size_t key_size,
			     const size_t salt_size,
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
			     chunk_t *chunk_SK_pr_out)
{
	DBG(DBG_CRYPT, DBG_log("NSS: Started key computation"));

	PK11SymKey
		*skeyseed_k,
		*SK_d_k,
		*SK_ai_k,
		*SK_ar_k,
		*SK_ei_k,
		*SK_er_k,
		*SK_pi_k,
		*SK_pr_k;
	chunk_t initiator_salt;
	chunk_t responder_salt;
	chunk_t chunk_SK_pi;
	chunk_t chunk_SK_pr;

	/* this doesn't take any memory, it's just moving pointers around */
	chunk_t ni;
	chunk_t nr;
	setchunk_from_wire(ni, sk, &sk->ni);
	setchunk_from_wire(nr, sk, &sk->nr);

	passert(sk->prf != NULL);
	dbg("calculating skeyseed using prf=%s integ=%s cipherkey-size=%zu salt-size=%zu",
	    sk->prf->common.fqn,
	    (sk->integ ? sk->integ->common.fqn : "n/a"),
	    key_size, salt_size);

	const struct prf_desc *prf = sk->prf;

	const struct encrypt_desc *encrypter = sk->encrypt;

	if (sk->skey_d_old == NULL) {
	/* generate SKEYSEED from key=(Ni|Nr), hash of shared */
		skeyseed_k = ikev2_ike_sa_skeyseed(sk->prf, ni, nr, shared);
	}  else {
		skeyseed_k = ikev2_ike_sa_rekey_skeyseed(sk->old_prf,
					sk->skey_d_old,
					shared, ni, nr);
		release_symkey(__func__, "parent-SK_d", &sk->skey_d_old);
	}

	passert(skeyseed_k != NULL);

	/* now we have to generate the keys for everything */

	/* need to know how many bits to generate */
	/* SK_d needs PRF hasher key bytes */
	/* SK_p needs PRF hasher*2 key bytes */
	/* SK_e needs key_size*2 key bytes */
	/* ..._salt needs salt_size*2 bytes */
	/* SK_a needs integ's key size*2 bytes */

	int skd_bytes = prf->prf_key_size;
	int skp_bytes = prf->prf_key_size;
	int integ_size = sk->integ ? sk->integ->integ_keymat_size : 0;
	size_t total_keysize = skd_bytes + 2*skp_bytes + 2*key_size + 2*salt_size + 2*integ_size;
	PK11SymKey *finalkey = ikev2_ike_sa_keymat(sk->prf, skeyseed_k,
						   ni, nr, &sk->ike_spis,
						   total_keysize);
	release_symkey(__func__, "skeyseed_k", &skeyseed_k);

	size_t next_byte = 0;

	SK_d_k = key_from_symkey_bytes(finalkey, next_byte, skd_bytes, HERE);
	next_byte += skd_bytes;

	SK_ai_k = key_from_symkey_bytes(finalkey, next_byte, integ_size, HERE);
	next_byte += integ_size;

	SK_ar_k = key_from_symkey_bytes(finalkey, next_byte, integ_size, HERE);
	next_byte += integ_size;

	/* The encryption key and salt are extracted together. */

	if (encrypter != NULL)
		SK_ei_k = encrypt_key_from_symkey_bytes("SK_ei_k",
							encrypter,
							next_byte, key_size,
							finalkey, HERE);
	else
		SK_ei_k = NULL;

	next_byte += key_size;
	PK11SymKey *initiator_salt_key = key_from_symkey_bytes(finalkey, next_byte,
							       salt_size, HERE);
	initiator_salt = chunk_from_symkey("initiator salt",
					   initiator_salt_key);
	release_symkey(__func__, "initiator-salt-key", &initiator_salt_key);

	next_byte += salt_size;

	/* The encryption key and salt are extracted together. */
	if (encrypter != NULL)
		SK_er_k = encrypt_key_from_symkey_bytes("SK_er_k",
							encrypter,
							next_byte, key_size,
							finalkey, HERE);
	else
		SK_er_k = NULL;

	next_byte += key_size;
	PK11SymKey *responder_salt_key = key_from_symkey_bytes(finalkey, next_byte,
							       salt_size, HERE);
	responder_salt = chunk_from_symkey("responder salt",
					   responder_salt_key);
	release_symkey(__func__, "responder-salt-key", &responder_salt_key);
	next_byte += salt_size;

	SK_pi_k = key_from_symkey_bytes(finalkey, next_byte, skp_bytes, HERE);
	/* store copy of SK_pi_k for later use in authnull */
	chunk_SK_pi = chunk_from_symkey("chunk_SK_pi", SK_pi_k);
	next_byte += skp_bytes;

	SK_pr_k = key_from_symkey_bytes(finalkey, next_byte, skp_bytes, HERE);
	/* store copy of SK_pr_k for later use in authnull */
	chunk_SK_pr = chunk_from_symkey("chunk_SK_pr", SK_pr_k);

	DBG(DBG_CRYPT,
	    DBG_log("NSS ikev2: finished computing individual keys for IKEv2 SA"));
	release_symkey(__func__, "finalkey", &finalkey);

	passert(*SK_d_out == NULL);
	*SK_d_out = SK_d_k;
	passert(*SK_ai_out == NULL);
	*SK_ai_out = SK_ai_k;
	passert(*SK_ar_out == NULL);
	*SK_ar_out = SK_ar_k;
	passert(*SK_ei_out == NULL);
	*SK_ei_out = SK_ei_k;
	passert(*SK_er_out == NULL);
	*SK_er_out = SK_er_k;
	passert(*SK_pi_out == NULL);
	*SK_pi_out = SK_pi_k;
	passert(*SK_pr_out == NULL);
	*SK_pr_out = SK_pr_k;

	*initiator_salt_out = initiator_salt;
	*responder_salt_out = responder_salt;
	*chunk_SK_pi_out = chunk_SK_pi;
	*chunk_SK_pr_out = chunk_SK_pr;

	DBG(DBG_CRYPT, {
		/* ??? this won't fire count-pointers.awk; should it? */
		DBG_log("calc_skeyseed_v2 pointers: shared-key@%p, SK_d-key@%p, SK_ai-key@%p, SK_ar-key@%p, SK_ei-key@%p, SK_er-key@%p, SK_pi-key@%p, SK_pr-key@%p",
			shared, SK_d_k, SK_ai_k, SK_ar_k, SK_ei_k, SK_er_k, SK_pi_k, SK_pr_k);
		DBG_dump_hunk("calc_skeyseed_v2 initiator salt", initiator_salt);
		DBG_dump_hunk("calc_skeyseed_v2 responder salt", responder_salt);
		DBG_dump_hunk("calc_skeyseed_v2 SK_pi", chunk_SK_pi);
		DBG_dump_hunk("calc_skeyseed_v2 SK_pr", chunk_SK_pr);
	});
}

/* NOTE: if NSS refuses to calculate DH, skr->shared == NULL */
/* MUST BE THREAD-SAFE */
void calc_dh_v2(struct pluto_crypto_req *r)
{
	struct pcr_dh_v2 *const sk = &r->pcr_d.dh_v2;

	const struct dh_desc *group = sk->dh;
	passert(group != NULL);

	/* now calculate the (g^x)(g^y) --- need gi on responder, gr on initiator */

	chunk_t remote_ke;
	setchunk_from_wire(remote_ke, sk, sk->role == SA_RESPONDER ? &sk->gi : &sk->gr);

	DBG(DBG_CRYPT, DBG_dump_hunk("peer's g: ", remote_ke));

	sk->shared = calc_dh_shared(sk->secret, remote_ke);
	if (sk->shared == NULL) {
		return; /* something went wrong */
	}

	/* okay, so now all the shared key material */
	calc_skeyseed_v2(sk,  /* input */
			 sk->shared,   /* input */
			 sk->key_size,  /* input */
			 sk->salt_size, /* input */

			 &sk->skeyid_d,        /* output */
			 &sk->skeyid_ai,       /* output */
			 &sk->skeyid_ar,       /* output */
			 &sk->skeyid_ei,       /* output */
			 &sk->skeyid_er,       /* output */
			 &sk->skeyid_pi,       /* output */
			 &sk->skeyid_pr,       /* output */
			 &sk->skey_initiator_salt, /* output */
			 &sk->skey_responder_salt, /* output */
			 &sk->skey_chunk_SK_pi, /* output */
			 &sk->skey_chunk_SK_pr); /* output */
}
