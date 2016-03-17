/*
 * SYMKEY manipulation functions, for libreswan
 *
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

#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_symkey.h"
#ifndef FIPS_CHECK
#include "crypt_dbg.h"
#endif
#include "crypto.h"
#include "lswfips.h"

/*
 * XXX: Is there an NSS version of this?
 */

static const char *ckm_to_string(CK_MECHANISM_TYPE mechanism)
{
	const char *t;
#define CASE(T) case T: t = #T; eat(t, "CKM_"); return t
	switch (mechanism) {

		CASE(CKM_CONCATENATE_BASE_AND_DATA);
		CASE(CKM_CONCATENATE_BASE_AND_KEY);
		CASE(CKM_CONCATENATE_DATA_AND_BASE);

		CASE(CKM_XOR_BASE_AND_DATA);

		CASE(CKM_EXTRACT_KEY_FROM_KEY);

		CASE(CKM_AES_CBC);
		CASE(CKM_DES3_CBC);
		CASE(CKM_CAMELLIA_CBC);
		CASE(CKM_AES_CTR);
		CASE(CKM_AES_GCM);

		CASE(CKM_AES_KEY_GEN);

		CASE(CKM_MD5_KEY_DERIVATION);
		CASE(CKM_SHA1_KEY_DERIVATION);
		CASE(CKM_SHA256_KEY_DERIVATION);
		CASE(CKM_SHA384_KEY_DERIVATION);
		CASE(CKM_SHA512_KEY_DERIVATION);

		CASE(CKM_DH_PKCS_DERIVE);

		CASE(CKM_VENDOR_DEFINED);

	default:
		return "unknown-mechanism";
	}
#undef CASE
}

void free_any_symkey(const char *prefix, PK11SymKey **key)
{
	if (*key != NULL) {
		DBG(DBG_CRYPT, DBG_log("%s: free key %p", prefix, *key));
		PK11_FreeSymKey(*key);
	} else {
		DBG(DBG_CRYPT, DBG_log("%s: free key NULL", prefix));
	}
	*key = NULL;
}

void DBG_symkey(const char *prefix, PK11SymKey *key)
{
	if (key == NULL) {
		/*
		 * For instance, when a zero-length key gets extracted
		 * from an existing key.
		 */
		DBG_log("%s key is NULL", prefix);
	} else {
		DBG_log("%s key(%p) length(%d) type/mechanism(%s 0x%08x)",
			prefix, key, PK11_GetKeyLength(key),
			ckm_to_string(PK11_GetMechanism(key)),
			(int)PK11_GetMechanism(key));
	}
}

void DBG_dump_symkey(const char *prefix, PK11SymKey *key)
{
	DBG_symkey(prefix, key);
	if (key != NULL) {
		if (DBGP(DBG_PRIVATE)) {
#ifdef FIPS_CHECK
			if (libreswan_fipsmode()) {
				DBG_log("%s secured by FIPS", prefix);
				return;
			}
#else
			void *bytes = symkey_bytes(prefix, key, NULL, 0);
			DBG_dump(prefix, bytes, PK11_GetKeyLength(key));
			pfreeany(bytes);
#endif
		}
	}
}

/*
 * Merge a symkey and an array of bytes into a new SYMKEY.
 *
 * derive: the operation that is to be performed; target: the
 * mechanism/type of the resulting symkey.
 */
PK11SymKey *merge_symkey_bytes(const char *prefix,
			       PK11SymKey *base_key,
			       const void *bytes, size_t sizeof_bytes,
			       CK_MECHANISM_TYPE derive,
			       CK_MECHANISM_TYPE target)
{
	passert(sizeof_bytes > 0);
	CK_KEY_DERIVATION_STRING_DATA string = {
		.pData = (void *)bytes,
		.ulLen = sizeof_bytes,
	};
	SECItem data_param = {
		.data = (unsigned char*)&string,
		.len = sizeof(string),
	};
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;

	DBG(DBG_CRYPT,
	    DBG_log("%s merge symkey(%p) bytes(%p/%zd) - derive(%s) target(%s)",
		    prefix,
		    base_key, bytes, sizeof_bytes,
		    ckm_to_string(derive),
		    ckm_to_string(target));
	    DBG_symkey("symkey:", base_key);
	    DBG_dump("bytes:", bytes, sizeof_bytes));
	PK11SymKey *result = PK11_Derive(base_key, derive, &data_param, target,
					 operation, key_size);
	DBG(DBG_CRYPT, DBG_symkey(prefix, result))
	return result;
}

/*
 * Merge two SYMKEYs into a new SYMKEY.
 *
 * derive: the operation to be performed; target: the mechanism/type
 * of the resulting symkey.
 */

PK11SymKey *merge_symkey_symkey(const char *prefix,
				PK11SymKey *base_key, PK11SymKey *key,
				CK_MECHANISM_TYPE derive,
				CK_MECHANISM_TYPE target)
{
	CK_OBJECT_HANDLE key_handle = PK11_GetSymKeyHandle(key);
	SECItem key_param = {
		.data = (unsigned char*)&key_handle,
		.len = sizeof(key_handle)
	};
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;
	DBG(DBG_CRYPT,
	    DBG_log("%s merge symkey(1: %p) symkey(2: %p) - derive(%s) target(%s)",
		    prefix, base_key, key,
		    ckm_to_string(derive),
		    ckm_to_string(target));
	    DBG_symkey("symkey 1:", base_key);
	    DBG_symkey("symkey 2:", key));
	PK11SymKey *result = PK11_Derive(base_key, derive, &key_param, target,
					 operation, key_size);
	DBG(DBG_CRYPT, DBG_symkey(prefix, result));
	return result;
}

/*
 * Extract a SYMKEY from an existing SYMKEY.
 */

PK11SymKey *symkey_from_symkey(const char *prefix,
			       PK11SymKey *base_key,
			       CK_MECHANISM_TYPE target,
			       CK_FLAGS flags,
			       size_t next_byte, size_t key_size)
{
	/* spell out all the parameters */
	CK_EXTRACT_PARAMS bs = next_byte * BITS_PER_BYTE;
	SECItem param = {
		.data = (unsigned char*)&bs,
		.len = sizeof(bs),
	};
	CK_MECHANISM_TYPE derive = CKM_EXTRACT_KEY_FROM_KEY;
	CK_ATTRIBUTE_TYPE operation = CKA_FLAGS_ONLY;

	DBG(DBG_CRYPT,
	    DBG_log("%s symkey from symkey(%p) - next-byte(%zd) key-size(%zd) flags(0x%lx) derive(%s) target(%s)",
		    prefix, base_key, next_byte, key_size, (long)flags,
		    ckm_to_string(derive), ckm_to_string(target));
	    DBG_symkey("symkey:", base_key));
	PK11SymKey *result = PK11_DeriveWithFlags(base_key, derive, &param,
						  target, operation,
						  key_size, flags);
	DBG(DBG_CRYPT, DBG_symkey(prefix, result));
	return result;
}

/*
 * SYMKEY I/O operations.
 *
 * SYMKEY_FROM_CHUNK uses the SCRATCH key as a secure starting point
 * for creating the key.
 */

PK11SymKey *symkey_from_bytes(PK11SymKey *scratch, const void *bytes,
			      size_t sizeof_bytes)
{
	PK11SymKey *tmp = merge_symkey_bytes("symkey_from_bytes",
					     scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY);
	passert(tmp != NULL);
	PK11SymKey *key = key_from_symkey_bytes(tmp, 0, sizeof_bytes);
	passert(key != NULL);
	free_any_symkey(__func__, &tmp);
	return key;
}

PK11SymKey *symkey_from_chunk(PK11SymKey *scratch, chunk_t chunk)
{
	return symkey_from_bytes(scratch, chunk.ptr, chunk.len);
}

/*
 * Concatenate two pieces of keying material creating a
 * new SYMKEY object.
 */

PK11SymKey *concat_symkey_symkey(const struct hash_desc *hasher,
				 PK11SymKey *lhs, PK11SymKey *rhs)
{
	return merge_symkey_symkey("concat:", lhs, rhs,
				   CKM_CONCATENATE_BASE_AND_KEY,
				   nss_key_derivation_mech(hasher));
}

PK11SymKey *concat_symkey_bytes(const struct hash_desc *hasher,
				PK11SymKey *lhs, const void *rhs,
				size_t sizeof_rhs)
{
	CK_MECHANISM_TYPE mechanism = nss_key_derivation_mech(hasher);
	return merge_symkey_bytes("concat_symkey_bytes",
				  lhs, rhs, sizeof_rhs,
				  CKM_CONCATENATE_BASE_AND_DATA,
				  mechanism);
}

PK11SymKey *concat_symkey_chunk(const struct hash_desc *hasher,
				PK11SymKey *lhs, chunk_t rhs)
{
	return concat_symkey_bytes(hasher, lhs, rhs.ptr, rhs.len);
}

PK11SymKey *concat_symkey_byte(const struct hash_desc *hasher,
			       PK11SymKey *lhs, uint8_t rhs)
{
	return concat_symkey_bytes(hasher, lhs, &rhs, sizeof(rhs));
}

/*
 * Append new keying material to an existing key; replace the existing
 * key with the result.
 *
 * Use this to chain a series of concat operations.
 */

void append_symkey_symkey(const struct hash_desc *hasher,
			  PK11SymKey **lhs, PK11SymKey *rhs)
{
	PK11SymKey *newkey = concat_symkey_symkey(hasher, *lhs, rhs);
	free_any_symkey(__func__, lhs);
	*lhs = newkey;
}

void append_symkey_bytes(const struct hash_desc *hasher,
			 PK11SymKey **lhs, const void *rhs,
			 size_t sizeof_rhs)
{
	PK11SymKey *newkey = concat_symkey_bytes(hasher, *lhs,
						 rhs, sizeof_rhs);
	free_any_symkey(__func__, lhs);
	*lhs = newkey;
}

void append_symkey_chunk(const struct hash_desc *hasher,
			 PK11SymKey **lhs, chunk_t rhs)
{
	append_symkey_bytes(hasher, lhs, rhs.ptr, rhs.len);
}

void append_symkey_byte(const struct hash_desc *hasher,
			PK11SymKey **lhs, uint8_t rhs)
{
	append_symkey_bytes(hasher, lhs, &rhs, sizeof(rhs));
}

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ENCRYPTER key
 * (i.e., can be used to encrypt/decrypt data using ENCRYPTER).
 *
 * Offset into the SYMKEY is in either BITS or BYTES.
 */

PK11SymKey *encrypt_key_from_symkey_bytes(PK11SymKey *source_key,
					  const struct encrypt_desc *encrypter,
					  size_t next_byte, size_t sizeof_symkey)
{
	return symkey_from_symkey("crypt key:", source_key,
				  nss_encryption_mech(encrypter),
				  CKF_ENCRYPT | CKF_DECRYPT,
				  next_byte, sizeof_symkey);
}

PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, size_t sizeof_key)
{
	return symkey_from_symkey("key:", source_key, CKM_EXTRACT_KEY_FROM_KEY,
				  0, next_byte, sizeof_key);
}

/*
 * Run HASHER on the key.
 *
 * This assumes that NSS works.  Based on old code, 3.14 may have had
 * problems with SHA-2.
 */

PK11SymKey *hash_symkey_to_symkey(const char *prefix,
				  const struct hash_desc *hasher,
				  PK11SymKey *base_key)
{
	CK_MECHANISM_TYPE derive = nss_key_derivation_mech(hasher);
	SECItem *param = NULL;
	CK_MECHANISM_TYPE target = CKM_CONCATENATE_BASE_AND_KEY;
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;

	DBG(DBG_CRYPT,
	    DBG_log("%s hash(%s) symkey(%p) to symkey - derive(%s)",
		    prefix, hasher->common.name,
		    base_key, ckm_to_string(derive));
	    DBG_symkey("symkey:", base_key));
	PK11SymKey *result = PK11_Derive(base_key, derive, param, target,
					 operation, key_size);
	DBG(DBG_CRYPT, DBG_symkey(prefix, result));
	return result;
}

static SECOidTag nss_hash_oid(const struct hash_desc *hasher)
{
	switch (hasher->common.algo_id) {
	case OAKLEY_MD5:
		return SEC_OID_MD5;
	case OAKLEY_SHA1:
		return SEC_OID_SHA1;
	case OAKLEY_SHA2_256:
		return SEC_OID_SHA256;
	case OAKLEY_SHA2_384:
		return SEC_OID_SHA384;
	case OAKLEY_SHA2_512:
		return SEC_OID_SHA512;
	}
	libreswan_log("NSS: hash algorithm %s not supported",
		      hasher->common.name);
	/* should trigger a cascading of errors. */
	return 0;
}

void *hash_symkey_to_bytes(const char *prefix,
			   const struct hash_desc *hasher,
			   PK11SymKey *base_key,
			   void *bytes, size_t sizeof_bytes)
{
	DBG(DBG_CRYPT,
	    DBG_log("%s hash(%s) symkey(%p) to bytes",
		    prefix, hasher->common.name, base_key);
	    DBG_symkey("symkey:", base_key));
	SECStatus status;
	SECOidTag hash_alg = nss_hash_oid(hasher);
	PK11Context *context = PK11_CreateDigestContext(hash_alg);
	passert(context != NULL);
	status = PK11_DigestBegin(context);
	passert(status == SECSuccess);
	status = PK11_DigestKey(context, base_key);
	passert(status == SECSuccess);
	unsigned int out_len;
	void *out_bytes;
	if (bytes != NULL) {
		out_bytes = bytes;
	} else {
		out_bytes = alloc_bytes(sizeof_bytes, prefix);
	}
	status = PK11_DigestFinal(context, out_bytes, &out_len, sizeof_bytes);
	passert(status == SECSuccess);
	passert(out_len == sizeof_bytes);
	PK11_DestroyContext(context, PR_TRUE);
	DBG(DBG_CRYPT, DBG_dump(prefix, out_bytes, sizeof_bytes));
	return out_bytes;
}

/*
 * XOR a symkey with a chunk.
 *
 * XXX: hmac.c had very similar code, only, instead of
 * target=CKM_CONCATENATE_BASE_AND_DATA it used
 * target=hasher-to-ckm(hasher).
 *
 * hasher-to-ckm maped hasher->common.alg_id to CMK vis: OAKLEY_MD5 ->
 * CKM_MD5; OAKLEY_SHA1 -> CKM_SHA_1; OAKLEY_SHA2_256 -> CKM_SHA256;
 * OAKLEY_SHA2_384 -> CKM_SHA384; OAKLEY_SHA2_512 -> CKM_SHA512; only
 * in the default case it would set target to 0x80000000????
 */
PK11SymKey *xor_symkey_chunk(PK11SymKey *lhs, chunk_t rhs)
{
	return merge_symkey_bytes("xor_symkey_chunk", lhs, rhs.ptr, rhs.len,
				  CKM_XOR_BASE_AND_DATA,
				  CKM_CONCATENATE_BASE_AND_DATA);
}
