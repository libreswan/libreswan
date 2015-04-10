/*
 * Calculate IKEv2 prf and keying material, for libreswan
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
 *
 * This code was developed with the support of Redhat corporation.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "crypto.h"
#include "rnd.h"
#include "state.h"
#include "pluto_crypt.h"
#include "lswlog.h"
#include "log.h"
#include "timer.h"
#include "ike_alg.h"
#include "id.h"
#include "secrets.h"
#include "keys.h"
#include "ikev2_prf.h"
#include "crypt_prf.h"
#include "crypt_dh.h"

static void v2prfplus(struct v2prf_stuff *vps)
{
	struct hmac_ctx ctx;

	hmac_init(&ctx, vps->prf_hasher, vps->skeyseed);
	hmac_update_chunk(&ctx, vps->t);
	hmac_update_chunk(&ctx, vps->ni);
	hmac_update_chunk(&ctx, vps->nr);
	hmac_update_chunk(&ctx, vps->spii);
	hmac_update_chunk(&ctx, vps->spir);
	hmac_update(&ctx, vps->counter, 1);
	hmac_final_chunk(vps->t, "skeyseed_t1", &ctx);
	DBG(DBG_CRYPT, {
		    char b[20];
		    snprintf(b, sizeof(b), "prf+[%u]:", vps->counter[0]);
		    DBG_dump_chunk(b, vps->t);
	    });

	vps->counter[0]++;
	vps->availbytes  = vps->t.len;
	vps->nextbytes   = 0;
}

void v2genbytes(chunk_t *need,
		unsigned int needed, const char *name,
		struct v2prf_stuff *vps)
{
	u_char *target;

	need->ptr = alloc_bytes(needed, name);
	need->len = needed;
	target = need->ptr;

	while (needed > vps->availbytes) {
		if (vps->availbytes) {
			/* use any bytes which are presently in the buffer */
			memcpy(target, &vps->t.ptr[vps->nextbytes],
			       vps->availbytes);
			target += vps->availbytes;
			needed -= vps->availbytes;
			vps->availbytes = 0;
		}
		/* generate more bits into t1 */
		v2prfplus(vps);
	}
	passert(needed <= vps->availbytes);

	memcpy(target, &vps->t.ptr[vps->nextbytes], needed);
	vps->availbytes -= needed;
	vps->nextbytes  += needed;
}


/*
 * IKEv2 - RFC4306 2.14 SKEYSEED - calculation.
 */

/* MUST BE THREAD-SAFE */
static void calc_skeyseed_v2(struct pcr_skeyid_q *skq,
			     PK11SymKey *shared,
			     const size_t key_size,
			     const size_t salt_size,
			     PK11SymKey **skeyseed_out,
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
	struct v2prf_stuff vpss;

	SECItem param1;
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

	zero(&vpss);

	/* this doesn't take any memory, it's just moving pointers around */
	setchunk_from_wire(vpss.ni, skq, &skq->ni);
	setchunk_from_wire(vpss.nr, skq, &skq->nr);
	setchunk_from_wire(vpss.spii, skq, &skq->icookie);
	setchunk_from_wire(vpss.spir, skq, &skq->rcookie);

	DBG(DBG_CONTROLMORE,
	    DBG_log("calculating skeyseed using prf=%s integ=%s cipherkey-size=%zu salt-size=%zu",
		    enum_name(&ikev2_trans_type_prf_names, skq->prf_hash),
		    enum_name(&ikev2_trans_type_integ_names, skq->integ_hash),
		    key_size, salt_size));

	const struct hash_desc *prf_hasher = (struct hash_desc *)
		ikev2_alg_find(IKE_ALG_HASH, skq->prf_hash);
	passert(prf_hasher != NULL);

	const struct encrypt_desc *encrypter = skq->encrypter;
	passert(encrypter != NULL);

	/* generate SKEYSEED from key=(Ni|Nr), hash of shared */
	skeyseed_k = ikev2_ike_sa_skeyseed(prf_hasher, vpss.ni, vpss.nr, shared);
	passert(skeyseed_k != NULL);
	
	/* now we have to generate the keys for everything */

	/* need to know how many bits to generate */
	/* SK_d needs PRF hasher key bytes */
	/* SK_p needs PRF hasher*2 key bytes */
	/* SK_e needs key_size*2 key bytes */
	/* ..._salt needs salt_size*2 bytes */
	/* SK_a needs integ's key size*2 bytes */

	int skd_bytes = prf_hasher->hash_key_size;
	int skp_bytes = prf_hasher->hash_key_size;
	const struct hash_desc *integ_hasher =
		(struct hash_desc *)ikev2_alg_find(IKE_ALG_INTEG, skq->integ_hash);
	int integ_size = integ_hasher != NULL ? integ_hasher->hash_key_size : 0;
	size_t total_keysize = skd_bytes + 2*skp_bytes + 2*key_size + 2*salt_size + 2*integ_size;
	PK11SymKey *finalkey = ikev2_ike_sa_keymat(prf_hasher, skeyseed_k,
						   vpss.ni, vpss.nr,
						   vpss.spii, vpss.spir,
						   total_keysize);

	CK_EXTRACT_PARAMS bs = 0;
	size_t next_bit = 0;

	SK_d_k = pk11_extract_derive_wrapper_lsw(finalkey, next_bit,
						 CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
						 skd_bytes);
	next_bit += skd_bytes * BITS_PER_BYTE;

	SK_ai_k = pk11_extract_derive_wrapper_lsw(finalkey, next_bit,
						  CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
						  integ_size);
	next_bit += integ_size * BITS_PER_BYTE;

	SK_ar_k = pk11_extract_derive_wrapper_lsw(finalkey, next_bit,
						  CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
						  integ_size);
	next_bit += integ_size * BITS_PER_BYTE;

	bs = next_bit;
	param1.data = (unsigned char*)&bs;
	param1.len = sizeof(bs);
	SK_ei_k = PK11_DeriveWithFlags(finalkey,
				       CKM_EXTRACT_KEY_FROM_KEY,
				       &param1,
				       nss_encryption_mech(encrypter),
				       CKA_FLAGS_ONLY, key_size,
				       CKF_ENCRYPT | CKF_DECRYPT);
	next_bit += key_size * BITS_PER_BYTE;

	initiator_salt = chunk_bytes_from_symkey_bits("initiator salt", finalkey,
						      next_bit, salt_size);
	next_bit += salt_size * BITS_PER_BYTE;

	bs = next_bit;
	param1.data = (unsigned char*)&bs;
	param1.len = sizeof(bs);
	SK_er_k = PK11_DeriveWithFlags(finalkey,
				       CKM_EXTRACT_KEY_FROM_KEY,
				       &param1,
				       nss_encryption_mech(encrypter),
				       CKA_FLAGS_ONLY, key_size,
				       CKF_ENCRYPT | CKF_DECRYPT);
	next_bit += key_size * BITS_PER_BYTE;

	responder_salt = chunk_bytes_from_symkey_bits("responder salt", finalkey,
						      next_bit, salt_size);
	next_bit += salt_size * BITS_PER_BYTE;

	SK_pi_k = pk11_extract_derive_wrapper_lsw(finalkey, next_bit,
						  CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
						  skp_bytes);

	/* store copy of SK_pi_k for later use in authnull */
	chunk_SK_pi = chunk_bytes_from_symkey_bits("chunk_SK_pi", SK_pi_k,
						   0, skp_bytes);

	next_bit += skp_bytes * BITS_PER_BYTE;

	SK_pr_k = pk11_extract_derive_wrapper_lsw(finalkey, next_bit,
						  CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
						  skp_bytes);

	/* store copy of SK_pr_k for later use in authnull */
	chunk_SK_pr = chunk_bytes_from_symkey_bits("chunk_SK_pr", SK_pr_k,
						   0, skp_bytes);

	next_bit += skp_bytes * BITS_PER_BYTE;

	DBG(DBG_CRYPT,
	    DBG_log("NSS ikev2: finished computing individual keys for IKEv2 SA"));
	PK11_FreeSymKey(finalkey);

	*skeyseed_out = skeyseed_k;
	*SK_d_out = SK_d_k;
	*SK_ai_out = SK_ai_k;
	*SK_ar_out = SK_ar_k;
	*SK_ei_out = SK_ei_k;
	*SK_er_out = SK_er_k;
	*SK_pi_out = SK_pi_k;
	*SK_pr_out = SK_pr_k;
	*initiator_salt_out = initiator_salt;
	*responder_salt_out = responder_salt;
	*chunk_SK_pi_out = chunk_SK_pi;
	*chunk_SK_pr_out = chunk_SK_pr;

	DBG(DBG_CRYPT,
	    DBG_log("calc_skeyseed_v2 pointers: shared %p, skeyseed %p, SK_d %p, SK_ai %p, SK_ar %p, SK_ei %p, SK_er %p, SK_pi %p, SK_pr %p",
		    shared, skeyseed_k, SK_d_k, SK_ai_k, SK_ar_k, SK_ei_k, SK_er_k, SK_pi_k, SK_pr_k);
	    DBG_dump_chunk("calc_skeyseed_v2 initiator salt", initiator_salt);
	    DBG_dump_chunk("calc_skeyseed_v2 responder salt", responder_salt);
	    DBG_dump_chunk("calc_skeyseed_v2 SK_pi", chunk_SK_pi);
	    DBG_dump_chunk("calc_skeyseed_v2 SK_pr", chunk_SK_pr));
}

/* MUST BE THREAD-SAFE */
void calc_dh_v2(struct pluto_crypto_req *r)
{
	struct pcr_skeycalc_v2_r *skr = &r->pcr_d.dhv2;
	struct pcr_skeyid_q dhq;
	const struct oakley_group_desc *group;
	PK11SymKey *shared;
	chunk_t g;
	SECKEYPrivateKey *ltsecret;
	PK11SymKey *skeyseed;
	PK11SymKey
		*SK_d,
		*SK_ai,
		*SK_ar,
		*SK_ei,
		*SK_er,
		*SK_pi,
		*SK_pr;
	chunk_t initiator_salt;
	chunk_t responder_salt;
	chunk_t chunk_SK_pi;
	chunk_t chunk_SK_pr;
	SECKEYPublicKey *pubk;

	/* copy the request, since the reply will re-use the memory of the r->pcr_d.dhq */
	memcpy(&dhq, &r->pcr_d.dhq, sizeof(r->pcr_d.dhq));

	/* clear out the reply */
	zero(skr);
	INIT_WIRE_ARENA(*skr);

	group = lookup_group(dhq.oakley_group);
	passert(group != NULL);

	ltsecret = dhq.secret;
	pubk = dhq.pubk;

	/* now calculate the (g^x)(g^y) --- need gi on responder, gr on initiator */

	setchunk_from_wire(g, &dhq, dhq.role == ORIGINAL_RESPONDER ? &dhq.gi : &dhq.gr);

	DBG(DBG_CRYPT, DBG_dump_chunk("peer's g: ", g));

	shared = calc_dh_shared(g, ltsecret, group, pubk);

	/* okay, so now all the shared key material */
	calc_skeyseed_v2(&dhq,	/* input */
			 shared,	/* input */
			 dhq.key_size,	/* input */
			 dhq.salt_size, /* input */

			 &skeyseed,	/* output */
			 &SK_d,	/* output */
			 &SK_ai,	/* output */
			 &SK_ar,	/* output */
			 &SK_ei,	/* output */
			 &SK_er,	/* output */
			 &SK_pi,	/* output */
			 &SK_pr,	/* output */
			 &initiator_salt, /* output */
			 &responder_salt, /* output */
			 &chunk_SK_pi, /* output */
			 &chunk_SK_pr); /* output */

	skr->shared = shared;
	skr->skeyseed = skeyseed;
	skr->skeyid_d = SK_d;
	skr->skeyid_ai = SK_ai;
	skr->skeyid_ar = SK_ar;
	skr->skeyid_ei = SK_ei;
	skr->skeyid_er = SK_er;
	skr->skeyid_pi = SK_pi;
	skr->skeyid_pr = SK_pr;
	skr->skey_initiator_salt = initiator_salt;
	skr->skey_responder_salt = responder_salt;
	skr->skey_chunk_SK_pi = chunk_SK_pi;
	skr->skey_chunk_SK_pr = chunk_SK_pr;
}

PK11SymKey *ikev2_ike_sa_skeyseed(const struct hash_desc *prf_hasher,
				  const chunk_t Ni, const chunk_t Nr,
				  PK11SymKey *dh_secret)
{
	/* generate SKEYSEED from prf(Ni | Nr, g^ir) */
	PK11SymKey *skeyseed = skeyid_digisig(Ni, Nr, dh_secret, prf_hasher);
	passert(skeyseed != NULL);
	return skeyseed;
}

PK11SymKey *ikev2_ike_sa_rekey_skeyseed(const struct hash_desc *prf_hasher,
					PK11SymKey *old_SK_d,
					PK11SymKey *new_dh_secret,
					const chunk_t Ni, const chunk_t Nr)
{
	PK11SymKey *key = old_SK_d;
	/* generate SKEYSEED from prf(SK_d (old), g^ir (new) | Ni | Nr) */

	/* XXX: what if old_SK_d isn't the same size as
	 * prf->hash_block_size? */
	
	chunk_t hmac_opad = hmac_pads(HMAC_OPAD, prf_hasher->hash_block_size);
	chunk_t hmac_ipad = hmac_pads(HMAC_IPAD, prf_hasher->hash_block_size);
	PK11SymKey *inner = pk11_derive_wrapper_lsw(key, CKM_XOR_BASE_AND_DATA,
						    hmac_ipad,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    CKA_DERIVE, 0);
	PK11SymKey *outer = pk11_derive_wrapper_lsw(key, CKM_XOR_BASE_AND_DATA,
						    hmac_opad,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    CKA_DERIVE, 0);
	freeanychunk(hmac_opad);
	freeanychunk(hmac_ipad);

	/* Form inner|DH|Ni|Nr */
	CK_OBJECT_HANDLE keyhandle = PK11_GetSymKeyHandle(new_dh_secret);
	SECItem param = {
		.data = (unsigned char*)&keyhandle,
		.len = sizeof(keyhandle)
	};
	PK11SymKey *inner_dh =
		PK11_Derive_lsw(inner, CKM_CONCATENATE_BASE_AND_KEY,
				&param, nss_key_derivation_mech(prf_hasher),
				CKA_DERIVE, 0);
	PK11_FreeSymKey(inner);
	PK11SymKey *inner_dh_ni =
		pk11_derive_wrapper_lsw(inner_dh,
					CKM_CONCATENATE_BASE_AND_DATA,
					Ni, CKM_CONCATENATE_BASE_AND_DATA,
					CKA_DERIVE, 0);
	PK11_FreeSymKey(inner_dh);
	PK11SymKey *inner_dh_ni_nr =
		pk11_derive_wrapper_lsw(inner_dh_ni,
					CKM_CONCATENATE_BASE_AND_DATA,
					Nr, CKM_CONCATENATE_BASE_AND_DATA,
					CKA_DERIVE, 0);
	PK11_FreeSymKey(inner_dh_ni);

	/* run that through the hash function */
	PK11SymKey *inner_hash =
		PK11_Derive_lsw(inner_dh_ni_nr,
				nss_key_derivation_mech(prf_hasher),
				NULL, CKM_CONCATENATE_BASE_AND_DATA,
				CKA_DERIVE, 0);
	PK11_FreeSymKey(inner_dh_ni_nr);

	/* Form: outer|inner_hash */
	keyhandle = PK11_GetSymKeyHandle(inner_hash);
	param = (SECItem) {
		.data = (unsigned char*)&keyhandle,
		.len = sizeof(keyhandle)
	};
	PK11SymKey *outer_inner =
		PK11_Derive_lsw(outer,
				CKM_CONCATENATE_BASE_AND_KEY,
				&param, nss_key_derivation_mech(prf_hasher),
				CKA_DERIVE, 0);
	PK11_FreeSymKey(outer);
	PK11_FreeSymKey(inner_hash);

	/* Hash outer */
	PK11SymKey *outer_hash =
		PK11_Derive_lsw(outer_inner,
				nss_key_derivation_mech(prf_hasher),
				NULL, CKM_EXTRACT_KEY_FROM_KEY,
				CKA_DERIVE, 0);
	PK11_FreeSymKey(outer_inner);

	return outer_hash;
}

static PK11SymKey *ikev2_prfplus(const struct hash_desc *prf_hasher,
				 PK11SymKey *skeyseed_k,
				 PK11SymKey *dh,
				 const chunk_t Ni, const chunk_t Nr,
				 const chunk_t SPIi, const chunk_t SPIr,
				 size_t total_keysize)
{
	passert(dh == NULL);
	CK_OBJECT_HANDLE keyhandle;
	SECItem param;

	chunk_t hmac_opad = hmac_pads(HMAC_OPAD, prf_hasher->hash_block_size);
	chunk_t hmac_ipad = hmac_pads(HMAC_IPAD, prf_hasher->hash_block_size);
	chunk_t hmac_pad_prf = hmac_pads(0x00, (prf_hasher->hash_block_size -
						prf_hasher->hash_digest_len));

	uint8_t counter = 1;
	
	DBG(DBG_CRYPT, {
			DBG_log("PRF+ input");
			DBG_dump_chunk("Ni", Ni);
			DBG_dump_chunk("Nr", Nr);
			DBG_dump_chunk("SPIi", SPIi);
			DBG_dump_chunk("SPIr", SPIr);
			DBG_log("Total keysize needed %zd",
				total_keysize);
		});

	PK11SymKey *finalkey = NULL;
	PK11SymKey *tkey11 = NULL;
	PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(skeyseed_k,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    hmac_pad_prf, CKM_XOR_BASE_AND_DATA, CKA_DERIVE,
						    prf_hasher->hash_block_size);
	passert(tkey1 != NULL);

	for (;; ) {
		PK11SymKey *tkey3 = NULL;

		if (counter == 0x01) {
			PK11SymKey *tkey2 = pk11_derive_wrapper_lsw(
				tkey1, CKM_XOR_BASE_AND_DATA,
				hmac_ipad,
				CKM_CONCATENATE_BASE_AND_DATA,
				CKA_DERIVE,
				0);
			passert(tkey2 != NULL);

			tkey3 = pk11_derive_wrapper_lsw(tkey2,
							CKM_CONCATENATE_BASE_AND_DATA,
							Ni, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							0);
			PK11_FreeSymKey(tkey2);
		} else {
			PK11SymKey *tkey2 = pk11_derive_wrapper_lsw(
				tkey1, CKM_XOR_BASE_AND_DATA,
				hmac_ipad,
				CKM_CONCATENATE_BASE_AND_KEY,
				CKA_DERIVE,
				0);
			passert(tkey2 != NULL);

			keyhandle = PK11_GetSymKeyHandle(tkey11);
			param.data = (unsigned char*)&keyhandle;
			param.len = sizeof(keyhandle);

			PK11SymKey *tkey12 = PK11_Derive_lsw(tkey2,
							     CKM_CONCATENATE_BASE_AND_KEY,
							     &param, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							     0);
			passert(tkey12 != NULL);

			tkey3 = pk11_derive_wrapper_lsw(tkey12,
							CKM_CONCATENATE_BASE_AND_DATA,
							Ni, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							0);
			PK11_FreeSymKey(tkey2);
			PK11_FreeSymKey(tkey11);
			PK11_FreeSymKey(tkey12);
		}

		passert(tkey3 != NULL);

		PK11SymKey *tkey4 = pk11_derive_wrapper_lsw(tkey3,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    Nr,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    CKA_DERIVE,
							    0);
		passert(tkey4 != NULL);

		PK11SymKey *tkey5 = pk11_derive_wrapper_lsw(tkey4,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    SPIi,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    CKA_DERIVE,
							    0);
		passert(tkey5 != NULL);

		PK11SymKey *tkey6 = pk11_derive_wrapper_lsw(tkey5,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    SPIr,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    CKA_DERIVE,
							    0);
		passert(tkey6 != NULL);

		chunk_t counter_chunk;

		setchunk(counter_chunk, &counter, sizeof(counter));
		PK11SymKey *tkey7 = pk11_derive_wrapper_lsw(tkey6,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    counter_chunk,
							    nss_key_derivation_mech(prf_hasher),
							    CKA_DERIVE,
							    0);
		passert(tkey7 != NULL);

		PK11SymKey *tkey8 = PK11_Derive_lsw(tkey7,
						    nss_key_derivation_mech(prf_hasher),
						    NULL,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    CKA_DERIVE,
						    0);
		passert(tkey8 != NULL);

		PK11SymKey *tkey9 = pk11_derive_wrapper_lsw(tkey1,
							    CKM_XOR_BASE_AND_DATA,
							    hmac_opad,
							    CKM_CONCATENATE_BASE_AND_KEY,
							    CKA_DERIVE,
							    0);
		passert(tkey9 != NULL);

		keyhandle = PK11_GetSymKeyHandle(tkey8);
		param.data = (unsigned char*)&keyhandle;
		param.len = sizeof(keyhandle);

		PK11SymKey *tkey10 = PK11_Derive_lsw(tkey9,
						     CKM_CONCATENATE_BASE_AND_KEY,
						     &param,
						     nss_key_derivation_mech(prf_hasher),
						     CKA_DERIVE,
						     0);
		passert(tkey10 != NULL);

		if (counter == 0x01) {
			finalkey = PK11_Derive_lsw(tkey10,
						   nss_key_derivation_mech(prf_hasher),
						   NULL,
						   CKM_CONCATENATE_BASE_AND_KEY,
						   CKA_DERIVE,
						   0);
			passert(finalkey != NULL);

			tkey11 = PK11_Derive_lsw(tkey10,
						 nss_key_derivation_mech(prf_hasher),
						 NULL,
						 CKM_CONCATENATE_BASE_AND_KEY,
						 CKA_DERIVE,
						 0);
			passert(tkey11 != NULL);
		} else {
			tkey11 = PK11_Derive_lsw(tkey10,
						 nss_key_derivation_mech(prf_hasher),
						 NULL,
						 CKM_EXTRACT_KEY_FROM_KEY,
						 CKA_DERIVE,
						 0);
			passert(tkey11 != NULL);

			keyhandle = PK11_GetSymKeyHandle(tkey11);
			param.data = (unsigned char*)&keyhandle;
			param.len = sizeof(keyhandle);

			if ( total_keysize <=
			     (PK11_GetKeyLength(finalkey) +
			      PK11_GetKeyLength(tkey11)) ) {
				finalkey = PK11_Derive_lsw(finalkey,
							   CKM_CONCATENATE_BASE_AND_KEY,
							   &param,
							   CKM_EXTRACT_KEY_FROM_KEY,
							   CKA_DERIVE,
							   0);
				passert(finalkey != NULL);
			} else {
				finalkey = PK11_Derive_lsw(finalkey,
							   CKM_CONCATENATE_BASE_AND_KEY,
							   &param,
							   CKM_CONCATENATE_BASE_AND_KEY,
							   CKA_DERIVE,
							   0);
				passert(finalkey != NULL);
			}
		}

		PK11_FreeSymKey(tkey3);
		PK11_FreeSymKey(tkey4);
		PK11_FreeSymKey(tkey5);
		PK11_FreeSymKey(tkey6);
		PK11_FreeSymKey(tkey7);
		PK11_FreeSymKey(tkey8);
		PK11_FreeSymKey(tkey9);
		PK11_FreeSymKey(tkey10);

		if (total_keysize <= PK11_GetKeyLength(finalkey)) {
			PK11_FreeSymKey(tkey1);
			PK11_FreeSymKey(tkey11);
			break;
		}

		counter++;
	}

	freeanychunk(hmac_opad);
	freeanychunk(hmac_ipad);
	freeanychunk(hmac_pad_prf);

	DBG(DBG_CRYPT,
	    DBG_log("NSS ikev2: finished computing key material for IKEv2 SA"));

	return finalkey;
}

PK11SymKey *ikev2_ike_sa_keymat(const struct hash_desc *prf_hasher,
				PK11SymKey *skeyseed,
				const chunk_t Ni, const chunk_t Nr,
				const chunk_t SPIi, const chunk_t SPIr,
				size_t required_bytes)
{
	return ikev2_prfplus(prf_hasher, skeyseed, NULL,
			     Ni, Nr, SPIi, SPIr,
			     required_bytes);
}

PK11SymKey *ikev2_child_sa_keymat(const struct hash_desc *prf_hasher,
				  PK11SymKey *SK_d,
				  PK11SymKey *new_dh_secret,
				  const chunk_t Ni, const chunk_t Nr,
				  size_t required_bytes)
{
	return ikev2_prfplus(prf_hasher, SK_d,
			     new_dh_secret, Ni, Nr,
			     empty_chunk, empty_chunk,
			     required_bytes);
}
