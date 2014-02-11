/* hmac interface for pluto ciphers.
 *
 * Copyright (C) 2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
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
 */

#include <sys/types.h>
#include <libreswan.h>

#include "constants.h"
#include "defs.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "alg_info.h"
#include "ike_alg.h"

#include <nss.h>
#include <pkcs11t.h>
#include <pk11pub.h>
#include <prlog.h>
#include <prmem.h>
#include <pk11priv.h>
#include <secport.h>
#include "lswconf.h"
#include "lswlog.h"

/* HMAC package
 * rfc2104.txt specifies how HMAC works.
 */

static CK_MECHANISM_TYPE nss_hash_mech(const struct hash_desc *hasher);
static SECOidTag nss_hash_oid(const struct hash_desc *hasher);

void hmac_init(struct hmac_ctx *ctx,
	       const struct hash_desc *h,
	       const u_char *key, size_t key_len)
{
	SECStatus status;
	PK11SymKey *symkey = NULL,
		*tkey1,
		*tkey2;
	unsigned int klen;
	chunk_t hmac_opad, hmac_ipad, hmac_pad;

	ctx->h = h;
	ctx->hmac_digest_len = h->hash_digest_len;

	/* DBG(DBG_CRYPT, DBG_log("NSS: hmac init")); */

	memcpy(&symkey, key, key_len);
	klen =  PK11_GetKeyLength(symkey);

	hmac_opad = hmac_pads(HMAC_OPAD, h->hash_block_size);
	hmac_ipad = hmac_pads(HMAC_IPAD, h->hash_block_size);
	hmac_pad  = hmac_pads(0x00, h->hash_block_size - klen);

	if (klen > h->hash_block_size) {
		tkey1 = PK11_Derive_lsw(symkey, nss_key_derivation_mech(
						h),
					NULL, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE,
					0);
	} else {
		tkey1 = symkey;
	}

	tkey2 = pk11_derive_wrapper_lsw(tkey1,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    hmac_pad, CKM_XOR_BASE_AND_DATA, CKA_DERIVE,
						    h->hash_block_size);
	PR_ASSERT(tkey2 != NULL);

	ctx->ikey = pk11_derive_wrapper_lsw(tkey2, CKM_XOR_BASE_AND_DATA,
					    hmac_ipad, nss_hash_mech(h),
						    CKA_DIGEST, 0);
	PR_ASSERT(ctx->ikey != NULL);

	ctx->okey = pk11_derive_wrapper_lsw(tkey2, CKM_XOR_BASE_AND_DATA,
					    hmac_opad, nss_hash_mech(h),
						    CKA_DIGEST, 0);
	PR_ASSERT(ctx->okey != NULL);

	if (tkey1 != symkey)
		PK11_FreeSymKey(tkey1);
	PK11_FreeSymKey(tkey2);

	freeanychunk(hmac_opad);
	freeanychunk(hmac_ipad);
	freeanychunk(hmac_pad);
	ctx->ctx_nss = PK11_CreateDigestContext(nss_hash_oid(h));
	PR_ASSERT(ctx->ctx_nss != NULL);

	status = PK11_DigestBegin(ctx->ctx_nss);
	PR_ASSERT(status == SECSuccess);

	status = PK11_DigestKey(ctx->ctx_nss, ctx->ikey);
	PR_ASSERT(status == SECSuccess);
}

void hmac_update(struct hmac_ctx *ctx,
		 const u_char *data, size_t data_len)
{
	DBG(DBG_CRYPT, DBG_dump("hmac_update data value: ", data, data_len));
	if (data_len > 0) {
		SECStatus status;

		DBG(DBG_CRYPT, DBG_log("hmac_update: inside if"));
		status = PK11_DigestOp(ctx->ctx_nss, data, data_len);
		DBG(DBG_CRYPT, DBG_log("hmac_update: after digest"));
		PR_ASSERT(status == SECSuccess);
		DBG(DBG_CRYPT, DBG_log("hmac_update: after assert"));
	}
}

void hmac_final(u_char *output, struct hmac_ctx *ctx)
{
	unsigned int outlen;
	SECStatus status;

	status = PK11_DigestFinal(ctx->ctx_nss, output, &outlen,
					    ctx->hmac_digest_len);
	PR_ASSERT(status == SECSuccess);
	PR_ASSERT(outlen == ctx->hmac_digest_len);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
	ctx->ctx_nss = NULL;

	ctx->ctx_nss = PK11_CreateDigestContext(nss_hash_oid(ctx->h));
	PR_ASSERT(ctx->ctx_nss != NULL);

	status = PK11_DigestBegin(ctx->ctx_nss);
	PR_ASSERT(status == SECSuccess);

	status = PK11_DigestKey(ctx->ctx_nss, ctx->okey);
	PR_ASSERT(status == SECSuccess);

	status = PK11_DigestOp(ctx->ctx_nss, output, outlen);
	PR_ASSERT(status == SECSuccess);

	status = PK11_DigestFinal(ctx->ctx_nss, output, &outlen,
				  ctx->hmac_digest_len);
	PR_ASSERT(status == SECSuccess);
	PR_ASSERT(outlen == ctx->hmac_digest_len);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);

	if (ctx->ikey != NULL)
		PK11_FreeSymKey(ctx->ikey);
	if (ctx->okey != NULL)
		PK11_FreeSymKey(ctx->okey);
	/* DBG(DBG_CRYPT, DBG_log("NSS: hmac final end")); */
}

static SECOidTag nss_hash_oid(const struct hash_desc *hasher)
{
	SECOidTag mechanism;

	switch (hasher->common.algo_id) {
	case OAKLEY_MD5:
		mechanism = SEC_OID_MD5;
		break;
	case OAKLEY_SHA1:
		mechanism = SEC_OID_SHA1;
		break;
	case OAKLEY_SHA2_256:
		mechanism = SEC_OID_SHA256;
		break;
	case OAKLEY_SHA2_384:
		mechanism = SEC_OID_SHA384;
		break;
	case OAKLEY_SHA2_512:
		mechanism = SEC_OID_SHA512;
		break;
	default:
		/* ??? surely this requires more than a DBG entry! */
		DBG(DBG_CRYPT,
		     DBG_log("NSS: key derivation mechanism not supported"));
		mechanism = 0;	/* ??? what should we do to recover? */
		break;
	}
	return mechanism;
}

static CK_MECHANISM_TYPE nss_hash_mech(const struct hash_desc *hasher)
{
	CK_MECHANISM_TYPE mechanism;

	switch (hasher->common.algo_id) {
	case OAKLEY_MD5:
		mechanism = CKM_MD5;
		break;
	case OAKLEY_SHA1:
		mechanism = CKM_SHA_1;
		break;
	case OAKLEY_SHA2_256:
		mechanism = CKM_SHA256;
		break;
	case OAKLEY_SHA2_384:
		mechanism = CKM_SHA384;
		break;
	case OAKLEY_SHA2_512:
		mechanism = CKM_SHA512;
		break;
	default:
		/* ??? surely this requires more than a DBG entry! */
		DBG(DBG_CRYPT,
		      DBG_log("NSS: key derivation mechanism not supported"));
		mechanism = 0x80000000;	/* ??? what should we do to recover? */
		break;
	}
	return mechanism;
}

PK11SymKey *pk11_derive_wrapper_lsw(PK11SymKey *base,
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

	return PK11_Derive(base, mechanism, &param, target, operation,
			   keySize);
}

/* MUST BE THREAD-SAFE */
PK11SymKey *PK11_Derive_lsw(PK11SymKey *base, CK_MECHANISM_TYPE mechanism,
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
		PR_ASSERT(ctx != NULL);
		status = PK11_DigestBegin(ctx);
		PR_ASSERT(status == SECSuccess);
		status = PK11_DigestKey(ctx, base);
		PR_ASSERT(status == SECSuccess);
		status = PK11_DigestFinal(ctx, dkey, &len, sizeof dkey);
		PR_ASSERT(status == SECSuccess);
		PK11_DestroyContext(ctx, PR_TRUE);

		dkey_chunk.ptr = dkey;
		dkey_chunk.len = len;

		PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(base,
							    CKM_CONCATENATE_DATA_AND_BASE, dkey_chunk, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE,
							    0);
		PR_ASSERT(tkey1 != NULL);

		bs = 0;
		dkey_param.data = (unsigned char*)&bs;
		dkey_param.len = sizeof(bs);
		PK11SymKey *tkey2 = PK11_Derive(tkey1,
						CKM_EXTRACT_KEY_FROM_KEY,
						&dkey_param, target, operation,
						len);
		PR_ASSERT(tkey2 != NULL);

		if (tkey1 != NULL)
			PK11_FreeSymKey(tkey1);

		return tkey2;

	} else {
		return PK11_Derive(base, mechanism, param, target, operation,
				   keysize);
	}
}

CK_MECHANISM_TYPE nss_key_derivation_mech(const struct hash_desc *hasher)
{
	CK_MECHANISM_TYPE mechanism = 0x80000000;

	switch (hasher->common.algo_id) {
	case OAKLEY_MD5:       mechanism = CKM_MD5_KEY_DERIVATION;
		break;
	case OAKLEY_SHA1:      mechanism = CKM_SHA1_KEY_DERIVATION;
		break;
	case OAKLEY_SHA2_256:  mechanism = CKM_SHA256_KEY_DERIVATION;
		break;
	case OAKLEY_SHA2_384:  mechanism = CKM_SHA384_KEY_DERIVATION;
		break;
	case OAKLEY_SHA2_512:  mechanism = CKM_SHA512_KEY_DERIVATION;
		break;
	default:  DBG(DBG_CRYPT,
		      DBG_log("NSS: key derivation mechanism not supported"));
		break;                                                                           /*should not reach here*/
	}
	return mechanism;
}

chunk_t hmac_pads(u_char val, unsigned int len)
{
	chunk_t ret;

	ret.len = len;
	ret.ptr = alloc_bytes(ret.len, "hmac_pad");

	memset(ret.ptr, val, len);

	return ret;
}

void nss_symkey_log(PK11SymKey *key, const char *msg)
{
	if (key == NULL) {
		DBG_log("NULL key %s", msg);
	} else {
		DBG(DBG_CRYPT, {
			DBG_log("computed key %s with length =%d", msg,
					       PK11_GetKeyLength(key));

			if (!PK11_IsFIPS()) {
				SECStatus status = PK11_ExtractKeyValue(key);
				SECItem *keydata;

				PR_ASSERT(status == SECSuccess);
				keydata = PK11_GetKeyData(key);

				DBG_dump("value: ", keydata->data,
					 keydata->len);

				SECITEM_FreeItem(keydata, PR_TRUE);	/* ??? this was commented out.  Why? */
			}
		});
	}
}
