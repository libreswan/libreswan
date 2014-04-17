/*
 * Cryptographic helper function - calculate DH
 *
 * Copyright (C) 2007-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
 * This code was developed with the support of IXIA communications.
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
#include "ikev2_prfplus.h"

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>
#include "lswconf.h"

/* #define PK11_Derive(base, mechanism, param, target, operation, keysize) \
 *	PK11_Derive_lsw(base, mechanism, param, target, operation, keysize)
 */

/* MUST BE THREAD-SAFE */
static PK11SymKey *pk11_extract_derive_wrapper_lsw(PK11SymKey *base,
						   CK_EXTRACT_PARAMS bs,
						   CK_MECHANISM_TYPE target,
						   CK_ATTRIBUTE_TYPE operation,
						   int keySize)
{
	SECItem param;

	param.data = (unsigned char*)&bs;
	param.len = sizeof(bs);

	return PK11_Derive_lsw(base, CKM_EXTRACT_KEY_FROM_KEY, &param, target,
			       operation, keySize);
}

static CK_MECHANISM_TYPE nss_encryption_mech(
	const struct encrypt_desc *encrypter)
{
	CK_MECHANISM_TYPE mechanism = 0x80000000;

	switch (encrypter->common.algo_id) {
	case OAKLEY_3DES_CBC:
		mechanism = CKM_DES3_CBC;
		break;
	case OAKLEY_AES_CBC:
		mechanism = CKM_AES_CBC;
		break;
	default:
		loglog(RC_LOG_SERIOUS,
			"NSS: Unsupported encryption mechanism");
		break;
	}
	return mechanism;
}

/** Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 */
/* MUST BE THREAD-SAFE */
static PK11SymKey *calc_dh_shared(const chunk_t g,	/* converted to SECItem */
				  /*const*/ SECKEYPrivateKey *privk,	/* NSS doesn't do const */
				  const struct oakley_group_desc *group,
				  const SECKEYPublicKey *local_pubk)
{
	struct timeval tv0;
	SECKEYPublicKey *remote_pubk;
	SECItem nss_g;
	PK11SymKey *dhshared;
	PRArenaPool *arena;
	SECStatus status;
	unsigned int dhshared_len;

	DBG(DBG_CRYPT,
		DBG_log("Started DH shared-secret computation in NSS:\n"));

	gettimeofday(&tv0, NULL);

	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	passert(arena != NULL);

	remote_pubk = (SECKEYPublicKey *)
		PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));

	remote_pubk->arena = arena;
	remote_pubk->keyType = dhKey;
	remote_pubk->pkcs11Slot = NULL;
	remote_pubk->pkcs11ID = CK_INVALID_HANDLE;

	nss_g.data = g.ptr;
	nss_g.len = (unsigned int)g.len;
	nss_g.type = siBuffer;

	status = SECITEM_CopyItem(remote_pubk->arena, &remote_pubk->u.dh.prime,
				  &local_pubk->u.dh.prime);
	passert(status == SECSuccess);

	status = SECITEM_CopyItem(remote_pubk->arena, &remote_pubk->u.dh.base,
				  &local_pubk->u.dh.base);
	passert(status == SECSuccess);

	status = SECITEM_CopyItem(remote_pubk->arena,
				  &remote_pubk->u.dh.publicValue, &nss_g);
	passert(status == SECSuccess);

	dhshared = PK11_PubDerive(privk, remote_pubk, PR_FALSE, NULL, NULL,
				  CKM_DH_PKCS_DERIVE,
				  CKM_CONCATENATE_DATA_AND_BASE,
				  CKA_DERIVE, group->bytes,
				  lsw_return_nss_password_file_info());
	passert(dhshared != NULL);

	dhshared_len = PK11_GetKeyLength(dhshared);
	if (group->bytes > dhshared_len) {
		DBG(DBG_CRYPT,
		    DBG_log("Dropped %lu leading zeros",
			    group->bytes - dhshared_len));
		chunk_t zeros;
		PK11SymKey *newdhshared;
		CK_KEY_DERIVATION_STRING_DATA string_params;
		SECItem params;

		zeros = hmac_pads(0x00, group->bytes - dhshared_len);
		params.data = (unsigned char *)&string_params;
		params.len = sizeof(string_params);
		string_params.pData = zeros.ptr;
		string_params.ulLen = zeros.len;

		newdhshared = PK11_Derive(dhshared,
					  CKM_CONCATENATE_DATA_AND_BASE,
					  &params,
					  CKM_CONCATENATE_DATA_AND_BASE,
					  CKA_DERIVE, 0);
		passert(newdhshared != NULL);
		PK11_FreeSymKey(dhshared);
		dhshared = newdhshared;
		freeanychunk(zeros);
	} else {
		DBG(DBG_CRYPT,
		    DBG_log("Dropped no leading zeros %d", dhshared_len));
	}

	/* nss_symkey_log(dhshared, "dhshared"); */

	DBG(DBG_CRYPT, {
		struct timeval tv1;
		unsigned long tv_diff;

		gettimeofday(&tv1, NULL);
		tv_diff = (tv1.tv_sec  - tv0.tv_sec) * 1000000 +
			  (tv1.tv_usec - tv0.tv_usec);
		DBG_log("calc_dh_shared(): time elapsed (%s): %ld usec",
			       enum_show(&oakley_group_names, group->group),
			       tv_diff);
	});

	SECKEY_DestroyPublicKey(remote_pubk);
	return dhshared;
}

/* SKEYID for preshared keys.
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */

static PK11SymKey *skeyid_preshared(const chunk_t pss,
				    const chunk_t ni,
				    const chunk_t nr,
				    PK11SymKey *shared,
				    const struct hash_desc *hasher)
{
	struct hmac_ctx ctx;

	passert(hasher != NULL);

	chunk_t nir;
	unsigned int k;
	CK_MECHANISM_TYPE mechanism;
	u_char buf1[HMAC_BUFSIZE * 2], buf2[HMAC_BUFSIZE * 2];
	chunk_t buf1_chunk, buf2_chunk;
	PK11SymKey *skeyid;

	DBG(DBG_CRYPT, {
		    DBG_log("NSS: skeyid inputs (pss+NI+NR+shared-secret) hasher: %s",
			    hasher->common.name);
		    DBG_log("shared-secret (pointer in chunk_t): %p", shared);
		    DBG_dump_chunk("ni: ", ni);
		    DBG_dump_chunk("nr: ", nr);
	    });

	/* We need to hmac_init with the concatenation of Ni_b and Nr_b,
	 * so we have to build a temporary concatentation.
	 */

	nir.len = ni.len + nr.len;
	nir.ptr = alloc_bytes(nir.len, "Ni + Nr in skeyid_preshared");
	memcpy(nir.ptr, ni.ptr, ni.len);
	memcpy(nir.ptr + ni.len, nr.ptr, nr.len);

	zero(&buf1);

	if (pss.len <= hasher->hash_block_size) {
		memcpy(buf1, pss.ptr, pss.len);
	} else {
		hasher->hash_init(&ctx.hash_ctx);
		hasher->hash_update(&ctx.hash_ctx, pss.ptr, pss.len);
		hasher->hash_final(buf1, &ctx.hash_ctx);
	}

	memcpy(buf2, buf1, hasher->hash_block_size);

	for (k = 0; k < hasher->hash_block_size; k++) {
		buf1[k] ^= HMAC_IPAD;
		buf2[k] ^= HMAC_OPAD;
	}

	/* pfree(nir.ptr); */

	mechanism = nss_key_derivation_mech(hasher);
	buf1_chunk.ptr = buf1;
	buf1_chunk.len = hasher->hash_block_size;

	buf2_chunk.ptr = buf2;
	buf2_chunk.len = hasher->hash_block_size;

	PK11SymKey *tkey4 = pk11_derive_wrapper_lsw(shared,
						    CKM_CONCATENATE_DATA_AND_BASE, buf1_chunk, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE,
						    0);
	/* nss_symkey_log(tkey4, "pss+ipad+shared"); */

	CK_EXTRACT_PARAMS bs = 0;
	PK11SymKey *tkey5 = pk11_extract_derive_wrapper_lsw(tkey4, bs,
							    CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							    hasher->hash_block_size);
	/* nss_symkey_log(tkey5, "pss+ipad"); */

	PK11SymKey *tkey6 = pk11_derive_wrapper_lsw(tkey5,
						    CKM_CONCATENATE_BASE_AND_DATA, nir, mechanism, CKA_DERIVE,
						    0);
	pfree(nir.ptr);
	/* nss_symkey_log(tkey6, "pss+ipad+nir"); */

	/* PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(shared, CKM_CONCATENATE_DATA_AND_BASE, buf1_chunk, mechanism, CKA_DERIVE, 0); */
	PK11SymKey *tkey2 = PK11_Derive_lsw(tkey6, mechanism, NULL,
					    CKM_CONCATENATE_DATA_AND_BASE,
					    CKA_DERIVE, 0);
	/* nss_symkey_log(tkey2, "pss : tkey2"); */

	PK11SymKey *tkey3 = pk11_derive_wrapper_lsw(tkey2,
						    CKM_CONCATENATE_DATA_AND_BASE, buf2_chunk, mechanism, CKA_DERIVE,
						    0);
	skeyid = PK11_Derive_lsw(tkey3, mechanism, NULL,
				 CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);
	/* nss_symkey_log(tkey2, "pss : tkey3"); */

	PK11_FreeSymKey(tkey4);
	PK11_FreeSymKey(tkey5);
	PK11_FreeSymKey(tkey6);
	PK11_FreeSymKey(tkey2);
	PK11_FreeSymKey(tkey3);

	DBG(DBG_CRYPT,
	    DBG_log("NSS: skeyid in skeyid_preshared() (pointer) %p: ",
		    skeyid));
	return skeyid;
}

/* MUST BE THREAD-SAFE */
static PK11SymKey *skeyid_digisig(const chunk_t ni,
			   const chunk_t nr,
			   /*const*/ PK11SymKey *shared,	/* NSS doesn't do const */
			   const struct hash_desc *hasher)
{
	struct hmac_ctx ctx;
	chunk_t nir;
	unsigned int k;
	CK_MECHANISM_TYPE mechanism;
	u_char buf1[HMAC_BUFSIZE * 2], buf2[HMAC_BUFSIZE * 2];
	chunk_t buf1_chunk, buf2_chunk;
	PK11SymKey *skeyid;

	DBG(DBG_CRYPT, {
		    DBG_log("skeyid inputs (digi+NI+NR+shared) hasher: %s",
			    hasher->common.name);
		    DBG_dump_chunk("ni: ", ni);
		    DBG_dump_chunk("nr: ", nr);
	    });

	/* We need to hmac_init with the concatenation of Ni_b and Nr_b,
	 * so we have to build a temporary concatentation.
	 */
	nir.len = ni.len + nr.len;
	nir.ptr = alloc_bytes(nir.len, "Ni + Nr in skeyid_digisig");
	memcpy(nir.ptr, ni.ptr, ni.len);
	memcpy(nir.ptr + ni.len, nr.ptr, nr.len);
	zero(&buf1);
	if (nir.len <= hasher->hash_block_size) {
		memcpy(buf1, nir.ptr, nir.len);
	} else {
		hasher->hash_init(&ctx.hash_ctx);
		hasher->hash_update(&ctx.hash_ctx, nir.ptr, nir.len);
		hasher->hash_final(buf1, &ctx.hash_ctx);
	}

	memcpy(buf2, buf1, hasher->hash_block_size);

	for (k = 0; k < hasher->hash_block_size; k++) {
		buf1[k] ^= HMAC_IPAD;
		buf2[k] ^= HMAC_OPAD;
	}

	pfree(nir.ptr);
	mechanism = nss_key_derivation_mech(hasher);
	buf1_chunk.ptr = buf1;
	buf1_chunk.len = hasher->hash_block_size;

	buf2_chunk.ptr = buf2;
	buf2_chunk.len = hasher->hash_block_size;

	PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(shared,
						    CKM_CONCATENATE_DATA_AND_BASE, buf1_chunk, mechanism, CKA_DERIVE,
						    0);
	PK11SymKey *tkey2 = PK11_Derive_lsw(tkey1, mechanism, NULL,
					    CKM_CONCATENATE_DATA_AND_BASE,
					    CKA_DERIVE, 0);
	PK11SymKey *tkey3 = pk11_derive_wrapper_lsw(tkey2,
						    CKM_CONCATENATE_DATA_AND_BASE, buf2_chunk, mechanism, CKA_DERIVE,
						    0);
	skeyid = PK11_Derive_lsw(tkey3, mechanism, NULL,
				 CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);

	PK11_FreeSymKey(tkey1);
	PK11_FreeSymKey(tkey2);
	PK11_FreeSymKey(tkey3);

	DBG(DBG_CRYPT,
	    DBG_log("NSS: digisig skeyid pointer: %p", skeyid));

	return skeyid;
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
	PK11SymKey
		*skeyid,
		*skeyid_d,
		*skeyid_a,
		*skeyid_e,
		*enc_key;
	/* const struct encrypt_desc *encrypter = crypto_get_encrypter(skq->encrypt_algo);*/
	const struct encrypt_desc *encrypter = skq->encrypter;

	/* this doesn't allocate any memory */
	setchunk_from_wire(gi, skq, &skq->gi);
	setchunk_from_wire(gr, skq, &skq->gr);
	setchunk_from_wire(ni, skq, &skq->ni);
	setchunk_from_wire(nr, skq, &skq->nr);
	setchunk_from_wire(icookie, skq, &skq->icookie);
	setchunk_from_wire(rcookie, skq, &skq->rcookie);

	/* Generate the SKEYID */
	switch (auth) {
	case OAKLEY_PRESHARED_KEY:
		{
			chunk_t pss;

			setchunk_from_wire(pss, skq, &skq->pss);
			skeyid = skeyid_preshared(pss, ni, nr, shared, hasher);
		}
		break;

	case OAKLEY_RSA_SIG:
		skeyid = skeyid_digisig(ni, nr, shared, hasher);
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

		DBG(DBG_CRYPT, DBG_log("NSS: Started key computation\n"));

		/*Deriving SKEYID_d = hmac_xxx(SKEYID, g^xy | CKY-I | CKY-R | 0) */
		PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(skeyid,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    hmac_pad,
							    CKM_XOR_BASE_AND_DATA,
							    CKA_DERIVE,
							    hasher->hash_block_size);

		passert(tkey1 != NULL);

		/*DBG(DBG_CRYPT, DBG_log("Started key computation: 1, length=%d\n", PK11_GetKeyLength(tkey1)));
		 * nss_symkey_log(tkey1, "1");
		 */

		PK11SymKey *tkey2 = pk11_derive_wrapper_lsw(tkey1,
							    CKM_XOR_BASE_AND_DATA,
							    hmac_ipad,
							    CKM_CONCATENATE_BASE_AND_KEY,
							    CKA_DERIVE,
							    0);

		passert(tkey2 != NULL);

		keyhandle = PK11_GetSymKeyHandle(shared);
		param.data = (unsigned char *) &keyhandle;
		param.len = sizeof(keyhandle);
		DBG(DBG_CRYPT,
		    DBG_log("NSS: dh shared param len=%d\n", param.len));

		PK11SymKey *tkey3 = PK11_Derive_lsw(tkey2,
						    CKM_CONCATENATE_BASE_AND_KEY,
						    &param,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    CKA_DERIVE,
						    0);
		passert(tkey3 != NULL);

		PK11SymKey *tkey4 = pk11_derive_wrapper_lsw(tkey3,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    icookie,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    CKA_DERIVE,
							    0);
		passert(tkey4 != NULL);

		PK11SymKey *tkey5 = pk11_derive_wrapper_lsw(tkey4,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    rcookie,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    CKA_DERIVE,
							    0);

		passert(tkey5 != NULL);

		PK11SymKey *tkey6 = pk11_derive_wrapper_lsw(tkey5,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    hmac_zerobyte,
							    nss_key_derivation_mech(hasher),
							    CKA_DERIVE,
							    0);

		passert(tkey6 != NULL);

		PK11SymKey *tkey7 = PK11_Derive_lsw(tkey6,
						    nss_key_derivation_mech(hasher),
						    NULL,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    CKA_DERIVE,
						    0);
		passert(tkey7 != NULL);

		PK11SymKey *tkey8 = pk11_derive_wrapper_lsw(tkey1,
							    CKM_XOR_BASE_AND_DATA,
							    hmac_opad,
							    CKM_CONCATENATE_BASE_AND_KEY,
							    CKA_DERIVE,
							    0);
		passert(tkey8 != NULL);

		keyhandle = PK11_GetSymKeyHandle(tkey7);
		param.data = (unsigned char*)&keyhandle;
		param.len = sizeof(keyhandle);

		PK11SymKey *tkey9 = PK11_Derive_lsw(tkey8,
						    CKM_CONCATENATE_BASE_AND_KEY,
						    &param,
						    nss_key_derivation_mech(hasher),
						    CKA_DERIVE,
						    0);
		passert(tkey9 != NULL);

		skeyid_d = PK11_Derive_lsw(tkey9,
					   nss_key_derivation_mech(hasher),
					   NULL,
					   CKM_CONCATENATE_BASE_AND_DATA,
					   CKA_DERIVE,
					   0);
		passert(skeyid_d != NULL);
		/* nss_symkey_log(skeyid_d, "skeyid_d"); */
		/*****End of SKEYID_d derivation***************************************/

		/*Deriving SKEYID_a = hmac_xxx(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)*/
		keyhandle = PK11_GetSymKeyHandle(skeyid_d);
		param.data = (unsigned char*)&keyhandle;
		param.len = sizeof(keyhandle);

		PK11SymKey *tkey10 = PK11_Derive_lsw(tkey2,
						     CKM_CONCATENATE_BASE_AND_KEY,
						     &param,
						     CKM_CONCATENATE_BASE_AND_KEY,
						     CKA_DERIVE,
						     0);
		passert(tkey10 != NULL);

		keyhandle = PK11_GetSymKeyHandle(shared);
		param.data = (unsigned char*)&keyhandle;
		param.len = sizeof(keyhandle);

		PK11SymKey *tkey11 = PK11_Derive_lsw(tkey10,
						     CKM_CONCATENATE_BASE_AND_KEY,
						     &param,
						     CKM_CONCATENATE_BASE_AND_DATA,
						     CKA_DERIVE,
						     0);
		passert(tkey11 != NULL);

		PK11SymKey *tkey12 = pk11_derive_wrapper_lsw(tkey11,
							     CKM_CONCATENATE_BASE_AND_DATA,
							     icookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							     0);
		passert(tkey12 != NULL);

		PK11SymKey *tkey13 = pk11_derive_wrapper_lsw(tkey12,
							     CKM_CONCATENATE_BASE_AND_DATA,
							     rcookie,
							     CKM_CONCATENATE_BASE_AND_DATA,
							     CKA_DERIVE,
							     0);
		passert(tkey13 != NULL);

		PK11SymKey *tkey14 = pk11_derive_wrapper_lsw(tkey13,
							     CKM_CONCATENATE_BASE_AND_DATA,
							     hmac_val1,
							     nss_key_derivation_mech(hasher),
							     CKA_DERIVE,
							     0);
		passert(tkey14 != NULL);

		PK11SymKey *tkey15 = PK11_Derive_lsw(tkey14,
						     nss_key_derivation_mech(hasher),
						     NULL,
						     CKM_CONCATENATE_BASE_AND_DATA,
						     CKA_DERIVE,
						     0);
		passert(tkey15 != NULL);

		keyhandle = PK11_GetSymKeyHandle(tkey15);
		param.data = (unsigned char*)&keyhandle;
		param.len = sizeof(keyhandle);

		PK11SymKey *tkey16 = PK11_Derive_lsw(tkey8,
						     CKM_CONCATENATE_BASE_AND_KEY, &param,
						     nss_key_derivation_mech(hasher),
						     CKA_DERIVE,
						     0);
		passert(tkey16 != NULL);

		skeyid_a = PK11_Derive_lsw(tkey16,
					   nss_key_derivation_mech(hasher),
					   NULL,
					   CKM_CONCATENATE_BASE_AND_DATA,
					   CKA_DERIVE,
					   0);
		passert(skeyid_a != NULL);
		/* nss_symkey_log(skeyid_a, "skeyid_a"); */
		/*****End of SKEYID_a derivation***************************************/

		/*Deriving SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)*/
		keyhandle = PK11_GetSymKeyHandle(skeyid_a);
		param.data = (unsigned char*)&keyhandle;
		param.len = sizeof(keyhandle);

		PK11SymKey *tkey17 = PK11_Derive_lsw(tkey2,
						     CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_CONCATENATE_BASE_AND_KEY, CKA_DERIVE,
						     0);
		passert(tkey17 != NULL);

		keyhandle = PK11_GetSymKeyHandle(shared);
		param.data = (unsigned char*)&keyhandle;
		param.len = sizeof(keyhandle);

		PK11SymKey *tkey18 = PK11_Derive_lsw(tkey17,
						     CKM_CONCATENATE_BASE_AND_KEY, &param, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
						     0);
		passert(tkey18 != NULL);

		PK11SymKey *tkey19 = pk11_derive_wrapper_lsw(tkey18,
							     CKM_CONCATENATE_BASE_AND_DATA,
							     icookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							     0);
		passert(tkey19 != NULL);

		PK11SymKey *tkey20 = pk11_derive_wrapper_lsw(tkey19,
							     CKM_CONCATENATE_BASE_AND_DATA,
							     rcookie, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							     0);
		passert(tkey20 != NULL);

		PK11SymKey *tkey21 = pk11_derive_wrapper_lsw(tkey20,
							     CKM_CONCATENATE_BASE_AND_DATA,
							     hmac_val2,
							     nss_key_derivation_mech(
								     hasher), CKA_DERIVE,
							     0);
		passert(tkey21 != NULL);

		PK11SymKey *tkey22 = PK11_Derive_lsw(tkey21, nss_key_derivation_mech(
							     hasher), NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
						     0);
		passert(tkey22 != NULL);

		keyhandle = PK11_GetSymKeyHandle(tkey22);
		param.data = (unsigned char*)&keyhandle;
		param.len = sizeof(keyhandle);

		PK11SymKey *tkey23 = PK11_Derive_lsw(tkey8,
						     CKM_CONCATENATE_BASE_AND_KEY, &param,
						     nss_key_derivation_mech(
							     hasher), CKA_DERIVE,
						     0);
		passert(tkey23 != NULL);

		DBG(DBG_CRYPT, DBG_log("NSS: enc keysize=%d\n", (int)keysize));
		/*Deriving encryption key from SKEYID_e*/
		/* Oakley Keying Material
		 * Derived from Skeyid_e: if it is not big enough, generate more
		 * using the PRF.
		 * See RFC 2409 "IKE" Appendix B
		 */

		CK_EXTRACT_PARAMS bitstart = 0;
		param1.data = (unsigned char*)&bitstart;
		param1.len = sizeof(bitstart);

		if (keysize <= hasher->hash_digest_len) {
			skeyid_e = PK11_Derive_lsw(tkey23,
						   nss_key_derivation_mech(hasher),
						   NULL,
						   CKM_EXTRACT_KEY_FROM_KEY,	/* note */
						   CKA_DERIVE, 0);
			passert(skeyid_e != NULL);
			/* nss_symkey_log(skeyid_e, "skeyid_e"); */

			enc_key = PK11_DeriveWithFlags(skeyid_e,
						       CKM_EXTRACT_KEY_FROM_KEY, &param1,
						       nss_encryption_mech(encrypter),
						       CKA_FLAGS_ONLY, keysize,
						       CKF_ENCRYPT | CKF_DECRYPT);
			passert(enc_key != NULL);

			/* nss_symkey_log(enc_key, "enc_key"); */
		} else {
			size_t i = 0;
			PK11SymKey *keymat;

			skeyid_e = PK11_Derive_lsw(tkey23,
						   nss_key_derivation_mech(hasher),
						   NULL,
						   CKM_CONCATENATE_BASE_AND_DATA,	/* note */
						   CKA_DERIVE, 0);
			passert(skeyid_e != NULL);
			/* nss_symkey_log(skeyid_e, "skeyid_e"); */

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

					/* nss_symkey_log(enc_key, "enc_key"); */
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
						    "NSS: Freed 25-39 symkeys\n"));
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
						    "NSS: Freed symkeys 31 34 35 37\n"));
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

		DBG(DBG_CRYPT, DBG_log("NSS: pointers skeyid_d %p,  skeyid_a %p,  skeyid_e %p,  enc_key %p\n",
			skeyid_d, skeyid_a, skeyid_e, enc_key));


		/*****Freeing tmp keys***************************************/
		PK11_FreeSymKey(tkey1);
		PK11_FreeSymKey(tkey2);
		PK11_FreeSymKey(tkey3);
		PK11_FreeSymKey(tkey4);
		PK11_FreeSymKey(tkey5);
		PK11_FreeSymKey(tkey6);
		PK11_FreeSymKey(tkey7);
		PK11_FreeSymKey(tkey8);
		PK11_FreeSymKey(tkey9);
		PK11_FreeSymKey(tkey10);
		PK11_FreeSymKey(tkey11);
		PK11_FreeSymKey(tkey12);
		PK11_FreeSymKey(tkey13);
		PK11_FreeSymKey(tkey14);
		PK11_FreeSymKey(tkey15);
		PK11_FreeSymKey(tkey16);
		PK11_FreeSymKey(tkey17);
		PK11_FreeSymKey(tkey18);
		PK11_FreeSymKey(tkey19);
		PK11_FreeSymKey(tkey20);
		PK11_FreeSymKey(tkey21);
		PK11_FreeSymKey(tkey22);
		PK11_FreeSymKey(tkey23);

		DBG(DBG_CRYPT, DBG_log("NSS: Freed symkeys 1-23\n"));

		freeanychunk(hmac_opad);
		freeanychunk(hmac_ipad);
		freeanychunk(hmac_pad);
		freeanychunk(hmac_zerobyte);
		freeanychunk(hmac_val1);
		freeanychunk(hmac_val2);
		DBG(DBG_CRYPT, DBG_log("NSS: Freed padding chunks\n"));
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
		DBG(DBG_CRYPT, DBG_log("end of IV generation\n"));
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

	setchunk_from_wire(g, &dhq, dhq.init == RESPONDER ? &dhq.gi : &dhq.gr);

	DBG(DBG_CRYPT,
	    DBG_dump_chunk("peer's g: ", g));

	shared = calc_dh_shared(g, ltsecret, group, pubk);

	zero(&new_iv);

	/* okay, so now calculate IV */
	calc_skeyids_iv(&dhq,
			shared,
			dhq.keysize,
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

/* MUST BE THREAD-SAFE */
void calc_dh(struct pluto_crypto_req *r)
{
	struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
	struct pcr_skeyid_q dhq;
	const struct oakley_group_desc *group;
	chunk_t g;
	SECKEYPrivateKey *ltsecret;
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

	/* now calculate the (g^x)(g^y) */

	setchunk_from_wire(g, &dhq, dhq.init == RESPONDER ? &dhq.gi : &dhq.gr);

	DBG(DBG_CRYPT, DBG_dump_chunk("peer's g: ", g));

	skr->shared = calc_dh_shared(g, ltsecret, group, pubk);
}

/*
 * IKEv2 - RFC4306 2.14 SKEYSEED - calculation.
 */

/* MUST BE THREAD-SAFE */
static void calc_skeyseed_v2(struct pcr_skeyid_q *skq,
			     PK11SymKey *shared,
			     const size_t keysize,
			     PK11SymKey **skeyseed_out,
			     PK11SymKey **SK_d_out,
			     PK11SymKey **SK_ai_out,
			     PK11SymKey **SK_ar_out,
			     PK11SymKey **SK_ei_out,
			     PK11SymKey **SK_er_out,
			     PK11SymKey **SK_pi_out,
			     PK11SymKey **SK_pr_out
			     )
{
	struct v2prf_stuff vpss;
	size_t total_keysize;

	chunk_t hmac_opad, hmac_ipad, hmac_pad_prf;
	/* chunk_t hmac_pad_integ, hmac_zerobyte, hmac_val1, hmac_val2; */

	CK_OBJECT_HANDLE keyhandle;
	SECItem param, param1;
	DBG(DBG_CRYPT, DBG_log("NSS: Started key computation\n"));

	PK11SymKey
		*skeyseed_k,
		*SK_d_k,
		*SK_ai_k,
		*SK_ar_k,
		*SK_ei_k,
		*SK_er_k,
		*SK_pi_k,
		*SK_pr_k;

	zero(&vpss);

	/* this doesn't take any memory, it's just moving pointers around */
	setchunk_from_wire(vpss.ni, skq, &skq->ni);
	setchunk_from_wire(vpss.nr, skq, &skq->nr);
	setchunk_from_wire(vpss.spii, skq, &skq->icookie);
	setchunk_from_wire(vpss.spir, skq, &skq->rcookie);

	DBG(DBG_CONTROLMORE,
	    DBG_log("calculating skeyseed using prf=%s integ=%s cipherkey=%lu",
		    enum_name(&ikev2_trans_type_prf_names, skq->prf_hash),
		    enum_name(&ikev2_trans_type_integ_names, skq->integ_hash),
		    (long unsigned)keysize));

	const struct hash_desc *hasher = (struct hash_desc *)
		ikev2_alg_find(IKE_ALG_HASH, skq->prf_hash);

	passert(hasher != NULL);

	const struct encrypt_desc *encrypter = skq->encrypter;
	passert(encrypter != NULL);

	hmac_opad = hmac_pads(HMAC_OPAD, hasher->hash_block_size);
	hmac_ipad = hmac_pads(HMAC_IPAD, hasher->hash_block_size);
	hmac_pad_prf = hmac_pads(0x00,
				 hasher->hash_block_size -
				 hasher->hash_digest_len);

	/* generate SKEYSEED from key=(Ni|Nr), hash of shared */
	skeyseed_k = skeyid_digisig(vpss.ni, vpss.nr, shared, hasher);
	passert(skeyseed_k != NULL);

	/* now we have to generate the keys for everything */
	{
		/* need to know how many bits to generate */
		/* SK_d needs PRF hasher key bits */
		/* SK_p needs PRF hasher*2 key bits */
		/* SK_e needs keysize*2 key bits */
		/* SK_a needs hash's key bits size */
		const struct hash_desc *integ_hasher =
			(struct hash_desc *)ikev2_alg_find(IKE_ALG_INTEG,
							       skq->integ_hash);
		int skd_bytes = hasher->hash_key_size;
		int skp_bytes = hasher->hash_key_size;
		int ska_bytes = integ_hasher->hash_key_size;
		int ske_bytes = keysize;

		vpss.counter[0] = 0x01;
		vpss.t.len = 0;
		total_keysize = skd_bytes +
				(2 * (ska_bytes + ske_bytes + skp_bytes));

		DBG(DBG_CRYPT, {
			    DBG_log("PRF+ input");
			    DBG_dump_chunk("Ni", vpss.ni);
			    DBG_dump_chunk("Nr", vpss.nr);
			    DBG_dump_chunk("SPIi", vpss.spii);
			    DBG_dump_chunk("SPIr", vpss.spir);
			    DBG_log("Total keysize needed %d",
				    (int)total_keysize);
		    });

		PK11SymKey *finalkey = NULL;
		PK11SymKey *tkey11 = NULL;
		PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(skeyseed_k,
							    CKM_CONCATENATE_BASE_AND_DATA,
							    hmac_pad_prf, CKM_XOR_BASE_AND_DATA, CKA_DERIVE,
							    hasher->hash_block_size);
		passert(tkey1 != NULL);

		for (;; ) {
			PK11SymKey *tkey3 = NULL;

			if (vpss.counter[0] == 0x01) {
				PK11SymKey *tkey2 = pk11_derive_wrapper_lsw(
					tkey1, CKM_XOR_BASE_AND_DATA,
					hmac_ipad,
					CKM_CONCATENATE_BASE_AND_DATA,
					CKA_DERIVE,
					0);
				passert(tkey2 != NULL);

				tkey3 = pk11_derive_wrapper_lsw(tkey2,
								CKM_CONCATENATE_BASE_AND_DATA,
								vpss.ni, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
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
								vpss.ni, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
								0);
				PK11_FreeSymKey(tkey2);
				PK11_FreeSymKey(tkey11);
				PK11_FreeSymKey(tkey12);
			}

			passert(tkey3 != NULL);

			PK11SymKey *tkey4 = pk11_derive_wrapper_lsw(tkey3,
								    CKM_CONCATENATE_BASE_AND_DATA,
								    vpss.nr,
								    CKM_CONCATENATE_BASE_AND_DATA,
								    CKA_DERIVE,
								    0);
			passert(tkey4 != NULL);

			PK11SymKey *tkey5 = pk11_derive_wrapper_lsw(tkey4,
								    CKM_CONCATENATE_BASE_AND_DATA,
								    vpss.spii,
								    CKM_CONCATENATE_BASE_AND_DATA,
								    CKA_DERIVE,
								    0);
			passert(tkey5 != NULL);

			PK11SymKey *tkey6 = pk11_derive_wrapper_lsw(tkey5,
								    CKM_CONCATENATE_BASE_AND_DATA,
								    vpss.spir,
								    CKM_CONCATENATE_BASE_AND_DATA,
								    CKA_DERIVE,
								    0);
			passert(tkey6 != NULL);

			chunk_t counter;

			setchunk(counter, &vpss.counter[0], sizeof(vpss.counter[0]));
			PK11SymKey *tkey7 = pk11_derive_wrapper_lsw(tkey6,
								    CKM_CONCATENATE_BASE_AND_DATA,
								    counter,
								    nss_key_derivation_mech(hasher),
								    CKA_DERIVE,
								    0);
			passert(tkey7 != NULL);

			PK11SymKey *tkey8 = PK11_Derive_lsw(tkey7,
							    nss_key_derivation_mech(hasher),
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
							     nss_key_derivation_mech(hasher),
							     CKA_DERIVE,
							     0);
			passert(tkey10 != NULL);

			if (vpss.counter[0] == 0x01) {
				finalkey = PK11_Derive_lsw(tkey10,
							   nss_key_derivation_mech(hasher),
							   NULL,
							   CKM_CONCATENATE_BASE_AND_KEY,
							   CKA_DERIVE,
							   0);
				passert(finalkey != NULL);

				tkey11 = PK11_Derive_lsw(tkey10,
							 nss_key_derivation_mech(hasher),
							 NULL,
							 CKM_CONCATENATE_BASE_AND_KEY,
							 CKA_DERIVE,
							 0);
				passert(tkey11 != NULL);
			} else {
				tkey11 = PK11_Derive_lsw(tkey10,
							 nss_key_derivation_mech(hasher),
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

			vpss.counter[0]++;
		}

		DBG(DBG_CRYPT,
		    DBG_log("NSS ikev2: finished computing key material for IKEv2 SA\n"));

		CK_EXTRACT_PARAMS bs = 0;

		SK_d_k = pk11_extract_derive_wrapper_lsw(finalkey, bs,
							 CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							 skd_bytes);

		bs = skd_bytes * BITS_PER_BYTE;
		SK_ai_k = pk11_extract_derive_wrapper_lsw(finalkey, bs,
							  CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							  ska_bytes);

		bs = (skd_bytes + ska_bytes) * BITS_PER_BYTE;
		SK_ar_k = pk11_extract_derive_wrapper_lsw(finalkey, bs,
							  CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							  ska_bytes);

		bs = (skd_bytes + (2 * ska_bytes)) * BITS_PER_BYTE;
		param1.data = (unsigned char*)&bs;
		param1.len = sizeof(bs);
		SK_ei_k = PK11_DeriveWithFlags(finalkey,
					       CKM_EXTRACT_KEY_FROM_KEY,
					       &param1,
					       nss_encryption_mech(encrypter),
					       CKA_FLAGS_ONLY, ske_bytes,
					       CKF_ENCRYPT | CKF_DECRYPT);

		bs = (skd_bytes + (2 * ska_bytes) + ske_bytes) * BITS_PER_BYTE;
		param1.data = (unsigned char*)&bs;
		param1.len = sizeof(bs);
		SK_er_k = PK11_DeriveWithFlags(finalkey,
					       CKM_EXTRACT_KEY_FROM_KEY,
					       &param1,
					       nss_encryption_mech(
						       encrypter), CKA_FLAGS_ONLY, ske_bytes, CKF_ENCRYPT |
					       CKF_DECRYPT);

		bs = (skd_bytes + (2 * ska_bytes) + (2 * ske_bytes))
		     * BITS_PER_BYTE;
		SK_pi_k = pk11_extract_derive_wrapper_lsw(finalkey, bs,
							  CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							  skp_bytes);

		bs = (skd_bytes + (2 * ska_bytes) + (2 * ske_bytes) + skp_bytes)
		     * BITS_PER_BYTE;
		SK_pr_k = pk11_extract_derive_wrapper_lsw(finalkey, bs,
							  CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
							  skp_bytes);

		DBG(DBG_CRYPT,
		    DBG_log("NSS ikev2: finished computing individual keys for IKEv2 SA\n"));
		PK11_FreeSymKey(finalkey);

		*skeyseed_out = skeyseed_k;
		*SK_d_out = SK_d_k;
		*SK_ai_out = SK_ai_k;
		*SK_ar_out = SK_ar_k;
		*SK_ei_out = SK_ei_k;
		*SK_er_out = SK_er_k;
		*SK_pi_out = SK_pi_k;
		*SK_pr_out = SK_pr_k;

		freeanychunk(hmac_opad);
		freeanychunk(hmac_ipad);
		freeanychunk(hmac_pad_prf);
	}
	DBG(DBG_CRYPT,
		      DBG_log("calc_skeyseed_v2 pointers: shared %p, skeyseed %p, SK_d %p, SK_ai %p, SK_ar %p, SK_ei %p, SK_er %p, SK_pi %p, SK_pr %p",
			      shared, skeyseed_k, SK_d_k, SK_ai_k, SK_ar_k, SK_ei_k, SK_er_k, SK_pi_k, SK_pr_k));
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

	setchunk_from_wire(g, &dhq, dhq.init == RESPONDER ? &dhq.gi : &dhq.gr);

	DBG(DBG_CRYPT, DBG_dump_chunk("peer's g: ", g));

	shared = calc_dh_shared(g, ltsecret, group, pubk);

	/* okay, so now calculate IV */
	calc_skeyseed_v2(&dhq,	/* input */
			 shared,	/* input */
			 dhq.keysize,	/* input */

			 &skeyseed,	/* output */
			 &SK_d,	/* output */
			 &SK_ai,	/* output */
			 &SK_ar,	/* output */
			 &SK_ei,	/* output */
			 &SK_er,	/* output */
			 &SK_pi,	/* output */
			 &SK_pr);	/* output */

	skr->shared = shared;
	skr->skeyseed = skeyseed;
	skr->skeyid_d = SK_d;
	skr->skeyid_ai = SK_ai;
	skr->skeyid_ar = SK_ar;
	skr->skeyid_ei = SK_ei;
	skr->skeyid_er = SK_er;
	skr->skeyid_pi = SK_pi;
	skr->skeyid_pr = SK_pr;
}
