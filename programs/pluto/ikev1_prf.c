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
#include "sysqueue.h"
#include "crypto.h"
#include "crypt_dh.h"
#include "crypt_prf.h"
#include "ikev1_prf.h"
#include "ike_alg.h"
#include "packet.h"
#include "pluto_crypt.h"
#include "crypt_symkey.h"

static PK11SymKey *pk11_derive_wrapper_lsw(PK11SymKey *base,
					   CK_MECHANISM_TYPE mechanism,
					   chunk_t data, CK_MECHANISM_TYPE target,
					   CK_ATTRIBUTE_TYPE operation, int keySize)
{
	CK_KEY_DERIVATION_STRING_DATA string;
	SECItem param;

	string.pData = data.ptr;
	string.ulLen = data.len;
	param.data = (unsigned char*)&string;
	param.len = sizeof(string);

	return PK11_Derive(base, mechanism,
		data.len == 0 ? NULL : &param,
		target, operation, keySize);
}

/* MUST BE THREAD-SAFE */
static PK11SymKey *PK11_Derive_lsw(PK11SymKey *base, CK_MECHANISM_TYPE mechanism,
				   SECItem *param, CK_MECHANISM_TYPE target,
				   CK_ATTRIBUTE_TYPE operation, int keysize)
{
	if (param == NULL && keysize == 0) {
		SECOidTag oid;
		PK11Context *ctx;
		unsigned char dkey[HMAC_BUFSIZE * 2];
		SECItem dkey_param;
		SECStatus status;
		unsigned int len;
		CK_EXTRACT_PARAMS bs;
		chunk_t dkey_chunk;

		switch (mechanism) {
		case CKM_SHA256_KEY_DERIVATION:
			oid = SEC_OID_SHA256;
			break;
		case CKM_SHA384_KEY_DERIVATION:
			oid = SEC_OID_SHA384;
			break;
		case CKM_SHA512_KEY_DERIVATION:
			oid = SEC_OID_SHA512;
			break;
		default:
			return PK11_Derive(base, mechanism, param, target,
					   operation, keysize);
		}

		ctx = PK11_CreateDigestContext(oid);
		passert(ctx != NULL);
		status = PK11_DigestBegin(ctx);
		passert(status == SECSuccess);
		status = PK11_DigestKey(ctx, base);
		passert(status == SECSuccess);
		status = PK11_DigestFinal(ctx, dkey, &len, sizeof dkey);
		passert(status == SECSuccess);
		PK11_DestroyContext(ctx, PR_TRUE);

		dkey_chunk.ptr = dkey;
		dkey_chunk.len = len;

		PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(base,
							    CKM_CONCATENATE_DATA_AND_BASE, dkey_chunk, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE,
							    0);
		passert(tkey1 != NULL);

		bs = 0;
		dkey_param.data = (unsigned char*)&bs;
		dkey_param.len = sizeof(bs);
		PK11SymKey *tkey2 = PK11_Derive(tkey1,
						CKM_EXTRACT_KEY_FROM_KEY,
						&dkey_param, target, operation,
						len);
		passert(tkey2 != NULL);

		if (tkey1 != NULL)
			PK11_FreeSymKey(tkey1);

		return tkey2;

	} else {
		return PK11_Derive(base, mechanism, param, target, operation,
				   keysize);
	}
}

/*
 * Compute: SKEYID = prf(Ni_b | Nr_b, g^xy)
 *
 * MUST BE THREAD-SAFE
 */
PK11SymKey *ikev1_digital_signature_skeyid(const struct hash_desc *hasher,
					   const chunk_t Ni,
					   const chunk_t Nr,
					   /*const*/ PK11SymKey *dh_secret /* NSS doesn't do const */)
{
	/* key = Ni|Nr */
	PK11SymKey *key = symkey_from_chunk(dh_secret, Ni);
	append_symkey_chunk(hasher, &key, Nr);

	PK11SymKey *skeyid = crypt_prf(hasher, key, dh_secret);

	PK11_FreeSymKey(key);
	return skeyid;
}

/*
 * Compute: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
 */
PK11SymKey *ikev1_pre_shared_key_skeyid(const struct hash_desc *hasher,
					chunk_t pre_shared_key,
					chunk_t Ni, chunk_t Nr,
					PK11SymKey *scratch)
{
	/* key = pre-shared-key */
	PK11SymKey *key = symkey_from_chunk(scratch, pre_shared_key);

	/* seed = Ni_b | Nr_b */
	PK11SymKey *seed = symkey_from_chunk(scratch, Ni);
	append_symkey_chunk(hasher, &seed, Nr);

	PK11SymKey *skeyid = crypt_prf(hasher, key, seed);

	PK11_FreeSymKey(key);
	PK11_FreeSymKey(seed);
	return skeyid;
}

/*
 * SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
 */
PK11SymKey *ikev1_skeyid_d(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r)
{
	/* seed = g^xy | CKY-I | CKY-R | 0 */
	PK11SymKey *seed = concat_symkey_chunk(hasher, dh_secret, cky_i);
	append_symkey_chunk(hasher, &seed, cky_r);
	chunk_t chunk0 = hmac_pads(0x00, 1);
	append_symkey_chunk(hasher, &seed, chunk0);
	freeanychunk(chunk0);

	PK11SymKey *skeyid_d = crypt_prf(hasher, skeyid, seed);

	PK11_FreeSymKey(seed);
	return skeyid_d;
}

/*
 * SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
 */
PK11SymKey *ikev1_skeyid_a(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_d, PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r)
{
	/* seed = SKEYID_d | g^xy | CKY-I | CKY-R | 1 */
	PK11SymKey *seed = concat_symkey_symkey(hasher, skeyid_d, dh_secret);
	append_symkey_chunk(hasher, &seed, cky_i);
	append_symkey_chunk(hasher, &seed, cky_r);
	chunk_t chunk1 = hmac_pads(0x01, 1);
	append_symkey_chunk(hasher, &seed, chunk1);
	freeanychunk(chunk1);

	PK11SymKey *skeyid_a = crypt_prf(hasher, skeyid, seed);

	PK11_FreeSymKey(seed);
	return skeyid_a;
}

/*
 * SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
 */
PK11SymKey *ikev1_skeyid_e(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_a, PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r)
{
	/* seed = SKEYID_a | g^xy | CKY-I | CKY-R | 2 */
	PK11SymKey *seed = concat_symkey_symkey(hasher, skeyid_a, dh_secret);
	append_symkey_chunk(hasher, &seed, cky_i);
	append_symkey_chunk(hasher, &seed, cky_r);
	chunk_t chunk2 = hmac_pads(0x02, 1);
	append_symkey_chunk(hasher, &seed, chunk2);
	freeanychunk(chunk2);

	PK11SymKey *skeyid_e = crypt_prf(hasher, skeyid, seed);
	PK11_FreeSymKey(seed);
	return skeyid_e;
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
		skeyid = ikev1_digital_signature_skeyid(hasher, ni, nr, shared);
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
	/* XXX: wrong name */
	PK11SymKey *skeyid_e = ikev1_skeyid_e(hasher, skeyid, skeyid_a,
					      shared, icookie, rcookie);
	{

		chunk_t hmac_opad, hmac_ipad, hmac_pad, hmac_zerobyte,
			hmac_val1, hmac_val2;
		CK_OBJECT_HANDLE keyhandle;
		SECItem param, param1;

		hmac_opad = hmac_pads(HMAC_OPAD, hasher->hash_block_size);
		hmac_ipad = hmac_pads(HMAC_IPAD, hasher->hash_block_size);
		hmac_pad  = hmac_pads(0x00,
				      hasher->hash_block_size -
				      hasher->hash_digest_len);
		hmac_zerobyte = hmac_pads(0x00, 1);
		hmac_val1 = hmac_pads(0x01, 1);
		hmac_val2 = hmac_pads(0x02, 1);

		DBG(DBG_CRYPT, DBG_log("NSS: Started key computation"));

		DBG(DBG_CRYPT, DBG_log("NSS: enc keysize=%d", (int)keysize));
		/* Deriving encryption key from SKEYID_e */
		/* Oakley Keying Material
		 * Derived from Skeyid_e: if it is not big enough, generate more
		 * using the PRF.
		 * See RFC 2409 "IKE" Appendix B
		 */

		CK_EXTRACT_PARAMS bitstart = 0;
		param1.data = (unsigned char*)&bitstart;
		param1.len = sizeof(bitstart);

		PK11SymKey *enc_key;
		if (keysize <= hasher->hash_digest_len) {

			enc_key = PK11_DeriveWithFlags(skeyid_e,
						       CKM_EXTRACT_KEY_FROM_KEY, &param1,
						       nss_encryption_mech(encrypter),
						       CKA_FLAGS_ONLY, keysize,
						       CKF_ENCRYPT | CKF_DECRYPT);
			passert(enc_key != NULL);

		} else {
			size_t i = 0;
			PK11SymKey *keymat;
			
			PK11SymKey *tkey25 = pk11_derive_wrapper_lsw(skeyid_e,
								     CKM_CONCATENATE_BASE_AND_DATA,
								     hmac_pad, CKM_XOR_BASE_AND_DATA, CKA_DERIVE,
								     hasher->hash_block_size);
			passert(tkey25 != NULL);

			PK11SymKey *tkey26 = pk11_derive_wrapper_lsw(tkey25,
								     CKM_XOR_BASE_AND_DATA,
								     hmac_ipad, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
								     0);
			passert(tkey26 != NULL);

			PK11SymKey *tkey27 = pk11_derive_wrapper_lsw(tkey26,
								     CKM_CONCATENATE_BASE_AND_DATA,
								     hmac_zerobyte,
								     nss_key_derivation_mech(
									     hasher), CKA_DERIVE,
								     0);
			passert(tkey27 != NULL);

			PK11SymKey *tkey28 = PK11_Derive_lsw(tkey27, nss_key_derivation_mech(
								     hasher), NULL,
							     CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							     0);
			passert(tkey28 != NULL);

			PK11SymKey *tkey29 = pk11_derive_wrapper_lsw(tkey25,
								     CKM_XOR_BASE_AND_DATA,
								     hmac_opad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE,
								     0);
			passert(tkey29 != NULL);

			keyhandle = PK11_GetSymKeyHandle(tkey28);
			param.data = (unsigned char*)&keyhandle;
			param.len = sizeof(keyhandle);

			PK11SymKey *tkey30 = PK11_Derive_lsw(tkey29,
							     CKM_CONCATENATE_BASE_AND_KEY, &param,
							     nss_key_derivation_mech(
								     hasher), CKA_DERIVE,
							     0);
			passert(tkey30 != NULL);

			PK11SymKey *tkey31 = PK11_Derive_lsw(tkey30, nss_key_derivation_mech(
								     hasher), NULL, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE,
							     0);
			passert(tkey31 != NULL);

			keymat = tkey31;

			i += hasher->hash_digest_len;

			PK11SymKey *tkey32 = pk11_derive_wrapper_lsw(skeyid_e,
								     CKM_CONCATENATE_BASE_AND_DATA,
								     hmac_pad, CKM_XOR_BASE_AND_DATA, CKA_DERIVE,
								     hasher->hash_block_size);
			passert(tkey32 != NULL);

			PK11SymKey *tkey33 = pk11_derive_wrapper_lsw(tkey32,
								     CKM_XOR_BASE_AND_DATA,
								     hmac_ipad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE,
								     0);
			passert(tkey33 != NULL);

			PK11SymKey *tkey36 = pk11_derive_wrapper_lsw(tkey32,
								     CKM_XOR_BASE_AND_DATA,
								     hmac_opad, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE,
								     0);
			passert(tkey36 != NULL);

			for (;; ) {

				keyhandle = PK11_GetSymKeyHandle(tkey31);
				param.data = (unsigned char*)&keyhandle;
				param.len = sizeof(keyhandle);

				PK11SymKey *tkey34 = PK11_Derive_lsw(tkey33,
								     CKM_CONCATENATE_BASE_AND_KEY, &param,
								     nss_key_derivation_mech(
									     hasher), CKA_DERIVE,
								     0);
				passert(tkey34 != NULL);

				PK11SymKey *tkey35 = PK11_Derive_lsw(tkey34, nss_key_derivation_mech(
									     hasher), NULL,
								     CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
								     0);
				passert(tkey35 != NULL);

				keyhandle = PK11_GetSymKeyHandle(tkey35);
				param.data = (unsigned char*)&keyhandle;
				param.len = sizeof(keyhandle);

				PK11SymKey *tkey37 = PK11_Derive_lsw(tkey36,
								     CKM_CONCATENATE_BASE_AND_KEY, &param,
								     nss_key_derivation_mech(
									     hasher), CKA_DERIVE,
								     0);
				passert(tkey37 != NULL);

				PK11SymKey *tkey38 = PK11_Derive_lsw(tkey37, nss_key_derivation_mech(
									     hasher), NULL, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE,
								     0);
				passert(tkey38 != NULL);

				i += hasher->hash_digest_len;

				if (i >= keysize ) {

					/*concatenating K1 and K2 */
					keyhandle =
						PK11_GetSymKeyHandle(tkey38);
					param.data =
						(unsigned char*)&keyhandle;
					param.len = sizeof(keyhandle);

					PK11SymKey *tkey39 = PK11_Derive_lsw(
						keymat,
						CKM_CONCATENATE_BASE_AND_KEY,
						&param,
						CKM_EXTRACT_KEY_FROM_KEY,
						CKA_DERIVE, 0);
					passert(tkey39 != NULL);

					enc_key = PK11_DeriveWithFlags(tkey39,
								       CKM_EXTRACT_KEY_FROM_KEY, &param1,
								       nss_encryption_mech(encrypter),
								       CKA_FLAGS_ONLY, /*0*/ keysize,
								       CKF_ENCRYPT | CKF_DECRYPT);

					passert(enc_key != NULL);

					PK11_FreeSymKey(tkey25);
					PK11_FreeSymKey(tkey26);
					PK11_FreeSymKey(tkey27);
					PK11_FreeSymKey(tkey28);
					PK11_FreeSymKey(tkey29);
					PK11_FreeSymKey(tkey30);
					PK11_FreeSymKey(tkey31);
					PK11_FreeSymKey(tkey32);
					PK11_FreeSymKey(tkey33);
					PK11_FreeSymKey(tkey34);
					PK11_FreeSymKey(tkey35);
					PK11_FreeSymKey(tkey36);
					PK11_FreeSymKey(tkey37);
					PK11_FreeSymKey(tkey38);
					PK11_FreeSymKey(tkey39);
					PK11_FreeSymKey(keymat);

					DBG(DBG_CRYPT,
					    DBG_log(
						    "NSS: Freed 25-39 symkeys"));
					break;
				} else {

					keyhandle =
						PK11_GetSymKeyHandle(tkey38);
					param.data =
						(unsigned char*)&keyhandle;
					param.len = sizeof(keyhandle);

					PK11SymKey *tkey39 = PK11_Derive_lsw(
						keymat,
						CKM_CONCATENATE_BASE_AND_KEY,
						&param,
						CKM_CONCATENATE_BASE_AND_KEY,
						CKA_DERIVE, 0);
					passert(tkey39 != NULL);

					keymat = tkey39;
					PK11_FreeSymKey(tkey31);
					tkey31 = tkey38;
					PK11_FreeSymKey(tkey34);
					PK11_FreeSymKey(tkey35);
					PK11_FreeSymKey(tkey37);

					DBG(DBG_CRYPT,
					    DBG_log(
						    "NSS: Freed symkeys 31 34 35 37"));
				}
			}       /*end for*/
		}               /*end else skeyid_e */

		/*****End of SKEYID_e and encryption key derivation***************************************/

		/********Saving pointers of all derived keys**********************************************/
		*skeyid_out = skeyid;
		*skeyid_d_out = skeyid_d;
		*skeyid_a_out = skeyid_a;
		*skeyid_e_out = skeyid_e;
		*enc_key_out = enc_key;

		DBG(DBG_CRYPT, DBG_log("NSS: pointers skeyid_d %p,  skeyid_a %p,  skeyid_e %p,  enc_key %p",
			skeyid_d, skeyid_a, skeyid_e, enc_key));



		DBG(DBG_CRYPT, DBG_log("NSS: Freed symkeys 1-23"));

		freeanychunk(hmac_opad);
		freeanychunk(hmac_ipad);
		freeanychunk(hmac_pad);
		freeanychunk(hmac_zerobyte);
		freeanychunk(hmac_val1);
		freeanychunk(hmac_val2);
		DBG(DBG_CRYPT, DBG_log("NSS: Freed padding chunks"));
	}

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
	struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
	struct pcr_skeyid_q dhq;
	const struct oakley_group_desc *group;
	PK11SymKey *shared;
	chunk_t g;
	SECKEYPrivateKey *ltsecret;
	PK11SymKey
		*skeyid,
		*skeyid_d,
		*skeyid_a,
		*skeyid_e,
		*enc_key;
	chunk_t new_iv;
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

	/* now calculate the (g^x)(g^y) ---
	 * need gi on responder, gr on initiator
	 */

	setchunk_from_wire(g, &dhq, dhq.role == ORIGINAL_RESPONDER ? &dhq.gi : &dhq.gr);

	DBG(DBG_CRYPT,
	    DBG_dump_chunk("peer's g: ", g));

	shared = calc_dh_shared(g, ltsecret, group, pubk);

	zero(&new_iv);

	/* okay, so now calculate IV */
	calc_skeyids_iv(&dhq,
			shared,
			dhq.key_size,
			&skeyid,
			&skeyid_d,
			&skeyid_a,
			&skeyid_e,
			&new_iv,
			&enc_key);

	skr->shared = shared;
	skr->skeyid = skeyid;
	skr->skeyid_d = skeyid_d;
	skr->skeyid_a = skeyid_a;
	skr->skeyid_e = skeyid_e;
	skr->enc_key = enc_key;


	WIRE_CLONE_CHUNK(*skr, new_iv, new_iv);
	freeanychunk(new_iv);
}
