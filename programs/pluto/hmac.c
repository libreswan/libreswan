/* hmac interface for pluto ciphers.
 *
 * Copyright (C) 2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015, Andrew Cagney <cagney@gnu.org>
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
#include "crypt_symkey.h"

/* HMAC package
 * rfc2104.txt specifies how HMAC works.
 */

static SECOidTag nss_hash_oid(const struct hash_desc *hasher);

void hmac_init(struct hmac_ctx *ctx,
	       const struct hash_desc *h,
	       /*const*/ PK11SymKey *symkey)	/* NSS doesn't like const! */
{
	SECStatus status;
	unsigned int klen;

	if (symkey != NULL) 
		klen = PK11_GetKeyLength(symkey);
	else
		klen = 0;

	ctx->h = h;
	ctx->hmac_digest_len = h->hash_digest_len;

	/*
	 * If the key is too long, cut it down to size using the
	 * hasher.
	 */
	PK11SymKey *tkey1;
	if (klen > h->hash_block_size) {
		tkey1 = hash_symkey(h, symkey);
		klen = PK11_GetKeyLength(tkey1);
	} else {
		tkey1 = symkey;
	}

	/*
	 * If the (possibly hashed) key isn't long enough, pad it to
	 * length.
	 */
	PK11SymKey *tkey2;
	if (klen < h->hash_block_size) {
		chunk_t hmac_pad  = hmac_pads(0x00, h->hash_block_size - klen);
		tkey2 = concat_symkey_chunk(h, tkey1, hmac_pad);
	} else {
		tkey2 = tkey1;
	}
	passert(tkey2 != NULL);
	if (tkey1 != symkey) {
		PK11_FreeSymKey(tkey1);
	}
	tkey1 = NULL;
	
	chunk_t hmac_ipad = hmac_pads(HMAC_IPAD, h->hash_block_size);
	chunk_t hmac_opad = hmac_pads(HMAC_OPAD, h->hash_block_size);
	ctx->ikey = xor_symkey_chunk(tkey2, hmac_ipad);
	ctx->okey = xor_symkey_chunk(tkey2, hmac_opad);
	passert(ctx->ikey != NULL);
	passert(ctx->okey != NULL);
	freeanychunk(hmac_ipad);
	freeanychunk(hmac_opad);
	if (tkey2 != symkey) {
		PK11_FreeSymKey(tkey2);
	}
	tkey2 = NULL;

	ctx->ctx_nss = PK11_CreateDigestContext(nss_hash_oid(h));
	passert(ctx->ctx_nss != NULL);

	status = PK11_DigestBegin(ctx->ctx_nss);
	passert(status == SECSuccess);

	status = PK11_DigestKey(ctx->ctx_nss, ctx->ikey);
	passert(status == SECSuccess);
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
		passert(status == SECSuccess);
		DBG(DBG_CRYPT, DBG_log("hmac_update: after assert"));
	}
}

void hmac_final(u_char *output, struct hmac_ctx *ctx)
{
	unsigned int outlen;
	SECStatus status;

	status = PK11_DigestFinal(ctx->ctx_nss, output, &outlen,
					    ctx->hmac_digest_len);
	passert(status == SECSuccess);
	passert(outlen == ctx->hmac_digest_len);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
	ctx->ctx_nss = NULL;

	ctx->ctx_nss = PK11_CreateDigestContext(nss_hash_oid(ctx->h));
	passert(ctx->ctx_nss != NULL);

	status = PK11_DigestBegin(ctx->ctx_nss);
	passert(status == SECSuccess);

	status = PK11_DigestKey(ctx->ctx_nss, ctx->okey);
	passert(status == SECSuccess);

	status = PK11_DigestOp(ctx->ctx_nss, output, outlen);
	passert(status == SECSuccess);

	status = PK11_DigestFinal(ctx->ctx_nss, output, &outlen,
				  ctx->hmac_digest_len);
	passert(status == SECSuccess);
	passert(outlen == ctx->hmac_digest_len);
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
		libreswan_log("NSS: key derivation mechanism (hasher->common.algo_id=%d not supported",
			hasher->common.algo_id);
		mechanism = 0;	/* ??? what should we do to recover? */
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

	return PK11_Derive(base, mechanism,
		data.len == 0 ? NULL : &param,
		target, operation, keySize);
}

CK_MECHANISM_TYPE nss_key_derivation_mech(const struct hash_desc *hasher)
{
	CK_MECHANISM_TYPE mechanism = 0x80000000;

	switch (hasher->common.algo_id) {
	case OAKLEY_MD5:
		mechanism = CKM_MD5_KEY_DERIVATION;
		break;
	case OAKLEY_SHA1:
		mechanism = CKM_SHA1_KEY_DERIVATION;
		break;
	case OAKLEY_SHA2_256:
		mechanism = CKM_SHA256_KEY_DERIVATION;
		break;
	case OAKLEY_SHA2_384:
		mechanism = CKM_SHA384_KEY_DERIVATION;
		break;
	case OAKLEY_SHA2_512:
		mechanism = CKM_SHA512_KEY_DERIVATION;
		break;
	default:
		DBG(DBG_CRYPT,
		    DBG_log("NSS: key derivation mechanism not supported"));
		break;
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
