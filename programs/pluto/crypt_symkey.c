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
#include "crypto.h"

/*
 * XXX: Is there an NSS version of this?
 */
static const char *ckm_to_string(CK_MECHANISM_TYPE mechanism)
{
	switch (mechanism) {
	case CKM_CONCATENATE_BASE_AND_DATA: return "concatentate base and data";
	case CKM_CONCATENATE_BASE_AND_KEY: return "concatentate base and key";
	case CKM_CONCATENATE_DATA_AND_BASE: return "concatentate data and base";
	case CKM_XOR_BASE_AND_DATA: return "xor base and data";
	case CKM_EXTRACT_KEY_FROM_KEY: return "extract key from key";

	case CKM_VENDOR_DEFINED: return "vendor defined";

	case CKM_AES_CBC: return "aes cbc";

	case CKM_MD5_KEY_DERIVATION: return "md5 key derivation";
	case CKM_SHA1_KEY_DERIVATION: return "sha1 key derivation";
	case CKM_SHA256_KEY_DERIVATION: return "sha256 key derivation";
	case CKM_SHA384_KEY_DERIVATION: return "sha384 key derivation";
	case CKM_SHA512_KEY_DERIVATION: return "sha512 key derivation";
	default:
		DBG(DBG_CRYPT, DBG_log("unknown mechanism 0x%08x", (int) mechanism));
		return "unknown";
	}
}

void DBG_dump_symkey(const char *prefix, PK11SymKey *key)
{
	DBG_log("%s key %p %d mechanism(type) %s",
		prefix, key, PK11_GetKeyLength(key),
		ckm_to_string(PK11_GetMechanism(key)));
	if (DBGP(DBG_PRIVATE)) {
		chunk_t chunk = chunk_from_symkey(prefix, key);
		DBG_dump_chunk(prefix, chunk);
		freeanychunk(chunk);
	} else {
		DBG_log("%s contents are private", prefix);
	}
}

/*
 * XXX: Is there any documentation on this generic operation?
 */
static PK11SymKey *merge_symkey_bytes(PK11SymKey *base_key,
				      const void *bytes, size_t sizeof_bytes,
				      CK_MECHANISM_TYPE derive,
				      CK_MECHANISM_TYPE target)
{
	passert(sizeof_bytes > 0);
	CK_KEY_DERIVATION_STRING_DATA string = {
		.pData = (void *)bytes,
		.ulLen = sizeof_bytes,
	};
	SECItem param = {
		.data = (unsigned char*)&string,
		.len = sizeof(string),
	};
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;

	DBG(DBG_CRYPT,
	    DBG_log("derive %s using %s", ckm_to_string(derive),
		    ckm_to_string(target));
	    DBG_dump_symkey("base", base_key);
	    DBG_dump("data", bytes, sizeof_bytes));
	PK11SymKey *result = PK11_Derive(base_key, derive, &param, target,
					 operation, key_size);
	DBG(DBG_CRYPT, DBG_dump_symkey("result", result))

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
	PK11SymKey *tmp = merge_symkey_bytes(scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY);
	passert(tmp != NULL);
	PK11SymKey *key = key_from_symkey_bytes(tmp, 0, sizeof_bytes);
	passert(key != NULL);
	DBG(DBG_CRYPT, DBG_log("symkey_from_bytes freeing key at %p", tmp));
	PK11_FreeSymKey(tmp);
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
	CK_OBJECT_HANDLE keyhandle = PK11_GetSymKeyHandle(rhs);
	/* give the parameters explicit names - there are too many */
	PK11SymKey *base_key = lhs;
	CK_MECHANISM_TYPE derive = CKM_CONCATENATE_BASE_AND_KEY;
	SECItem param = {
		.data = (unsigned char*)&keyhandle,
		.len = sizeof(keyhandle)
	};
	CK_MECHANISM_TYPE target = nss_key_derivation_mech(hasher);
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;

	DBG(DBG_CRYPT,
	    DBG_log("concate symkey(base) symkey(key) target %s",
		    ckm_to_string(target));
	    DBG_dump_symkey("base", lhs);
	    DBG_dump_symkey("key", rhs));
	PK11SymKey *result = PK11_Derive(base_key, derive, &param, target,
					 operation, key_size);
	DBG(DBG_CRYPT, DBG_dump_symkey("result", result));

	return result;
}

PK11SymKey *concat_symkey_bytes(const struct hash_desc *hasher,
				PK11SymKey *lhs, const void *rhs,
				size_t sizeof_rhs)
{
	CK_MECHANISM_TYPE mechanism = nss_key_derivation_mech(hasher);
	return merge_symkey_bytes(lhs, rhs, sizeof_rhs,
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
	DBG(DBG_CRYPT, DBG_log("append_symkey_symkey freeing key at %p", *lhs));
	PK11_FreeSymKey(*lhs);
	*lhs = newkey;
}

void append_symkey_bytes(const struct hash_desc *hasher,
			 PK11SymKey **lhs, const void *rhs,
			 size_t sizeof_rhs)
{
	PK11SymKey *newkey = concat_symkey_bytes(hasher, *lhs,
						 rhs, sizeof_rhs);
	DBG(DBG_CRYPT, DBG_log("append_symkey_bytes freeing key at %p", *lhs));
	PK11_FreeSymKey(*lhs);
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
 * Extract raw-bytes from a SYMKEY.
 *
 * Offset into the SYMKEY is in either BITS or BYTES.
 */

static PK11SymKey *key_from_key_bits(PK11SymKey *base_key,
				     CK_MECHANISM_TYPE target,
				     CK_FLAGS flags,
				     size_t next_bit, size_t key_size)
{
	/* spell out all the parameters */
	CK_EXTRACT_PARAMS bs = next_bit;
	SECItem param = {
		.data = (unsigned char*)&bs,
		.len = sizeof(bs),
	};
	CK_MECHANISM_TYPE derive = CKM_EXTRACT_KEY_FROM_KEY;
	CK_ATTRIBUTE_TYPE operation = CKA_FLAGS_ONLY;

	DBG(DBG_CRYPT,
	    DBG_log("%s key from base key bits %zd length %zd flags 0x%lx",
		    ckm_to_string(target), next_bit, key_size, flags);
	    DBG_dump_symkey("base key", base_key));
	PK11SymKey *result = PK11_DeriveWithFlags(base_key, derive, &param,
						  target, operation,
						  key_size, flags);
	DBG(DBG_CRYPT, DBG_dump_symkey("result", result));

	return result;
}

void *bytes_from_symkey_bits(const char *name,
			     PK11SymKey *source_key, size_t next_bit,
			     void *bytes, size_t sizeof_bytes)
{
	DBG(DBG_CRYPT,
	    DBG_log("%s: extracting %zd bytes starting at bit %zd from symkey %p into %p",
		    name, sizeof_bytes, next_bit, source_key, bytes));
	if (sizeof_bytes == 0) {
		return NULL;
	}
	PK11SymKey *sym_key = key_from_key_bits(source_key,
						CKM_VENDOR_DEFINED, 0,
						next_bit, sizeof_bytes);
	if (sym_key == NULL) {
		loglog(RC_LOG_SERIOUS, "NSS key-from-key failed while generating %s", name);
		return NULL;
	}
	SECStatus s = PK11_ExtractKeyValue(sym_key);
	if (s != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_ExtractKeyValue failed while generating %s", name);
		return NULL;
	}
	/* Internal structure address, do not free.  */
	SECItem *data = PK11_GetKeyData(sym_key);
	if (data == NULL) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_GetKeyData failed while generating %s", name);
		return NULL;
	}
	DBG(DBG_CRYPT,
	    DBG_log("chunk_from_symkey: %s: extracted len %d bytes at %p",
		    name, data->len, data->data));
	if (data->len != sizeof_bytes) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_GetKeyData returned wrong number of bytes while generating %s", name);
		return NULL;
	}
	/* Only alloc, when all looks good.  */
	if (bytes == NULL) {
		bytes = alloc_bytes(sizeof_bytes, name);
		DBG(DBG_CRYPT,
		    DBG_log("%s: allocated %zd bytes at %p",
			    name, sizeof_bytes, bytes));
	}
	memcpy(bytes, data->data, sizeof_bytes);
	DBG(DBG_PRIVATE,
	    DBG_dump(name, bytes, sizeof_bytes));
	DBG(DBG_CRYPT, DBG_log("bytes_from_symkey_bits freeing key at %p", sym_key));
	PK11_FreeSymKey(sym_key);
	
	return bytes;
}

void *bytes_from_symkey_bytes(const char *name, PK11SymKey *source_key,
			      size_t next_byte, void *bytes,
			      size_t sizeof_bytes)
{
	return bytes_from_symkey_bits(name, source_key,
				      next_byte * BITS_PER_BYTE,
				      bytes, sizeof_bytes);
}

chunk_t chunk_from_symkey_bits(const char *name, PK11SymKey *source_key,
			       size_t next_bit, size_t sizeof_chunk)
{
	void *bytes = bytes_from_symkey_bits(name, source_key, next_bit,
					     NULL, sizeof_chunk);
	if (bytes == NULL) {
		return empty_chunk;
	}
	chunk_t chunk;
	setchunk(chunk, bytes, sizeof_chunk);
	return chunk;
}

chunk_t chunk_from_symkey_bytes(const char *name, PK11SymKey *source_key,
				size_t next_byte, size_t sizeof_chunk)
{
	return chunk_from_symkey_bits(name, source_key,
				      next_byte * BITS_PER_BYTE, sizeof_chunk);
}

chunk_t chunk_from_symkey(const char *name, PK11SymKey *source_key)
{
	return chunk_from_symkey_bits(name, source_key, 0,
				      PK11_GetKeyLength(source_key));
}

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ENCRYPTER key
 * (i.e., can be used to encrypt/decrypt data using ENCRYPTER).
 *
 * Offset into the SYMKEY is in either BITS or BYTES.
 */

PK11SymKey *encrypt_key_from_symkey_bits(PK11SymKey *source_key,
					 const struct encrypt_desc *encrypter,
					 size_t next_bit, size_t sizeof_symkey)
{
	return key_from_key_bits(source_key,
				 nss_encryption_mech(encrypter),
				 CKF_ENCRYPT | CKF_DECRYPT,
				 next_bit, sizeof_symkey);
}

PK11SymKey *encrypt_key_from_symkey_bytes(PK11SymKey *source_key,
					  const struct encrypt_desc *encrypter,
					  size_t next_byte, size_t sizeof_symkey)
{
	return encrypt_key_from_symkey_bits(source_key, encrypter,
					    next_byte * BITS_PER_BYTE,
					    sizeof_symkey);
}

/*
 * Extract SIZEOF_KEY bytes of keying material as a KEY.  It inherits
 * the BASE_KEYs type.  Good for hash keys.
 *
 * Offset into the SYMKEY is in either BITS or BYTES.
 */

PK11SymKey *key_from_symkey_bits(PK11SymKey *base_key,
				 size_t next_bit, size_t key_size)
{				    
	CK_EXTRACT_PARAMS bs = next_bit;
	SECItem param = {
		.data = (unsigned char*)&bs,
		.len = sizeof(bs),
	};
	CK_MECHANISM_TYPE derive = CKM_EXTRACT_KEY_FROM_KEY;
	CK_MECHANISM_TYPE target = CKM_CONCATENATE_BASE_AND_DATA;
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	/* XXX: can this use key_from_key_bits? */

	DBG(DBG_CRYPT,
	    DBG_log("%s key from symkey(base key) bits %zd length %zd",
		    ckm_to_string(target),
		     next_bit, key_size);
	    DBG_dump_symkey("base key", base_key));
	PK11SymKey *result = PK11_Derive(base_key, derive, &param, target,
					 operation, key_size);
	DBG(DBG_CRYPT, DBG_dump_symkey("result", result));

	return result;
}

PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, size_t sizeof_key)
{
	return key_from_symkey_bits(source_key,
				    next_byte * BITS_PER_BYTE,
				    sizeof_key);
}

/*
 * Run HASHER on the key.
 *
 * This assumes that NSS works.  Based on old code, 3.14 may have had
 * problems with SHA-2.
 */
PK11SymKey *hash_symkey(const struct hash_desc *hasher,
			PK11SymKey *base_key)
{
	CK_MECHANISM_TYPE derive = nss_key_derivation_mech(hasher);
	SECItem *param = NULL;
	CK_MECHANISM_TYPE target = CKM_CONCATENATE_BASE_AND_KEY;
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;

	DBG(DBG_CRYPT,
	    DBG_log("%s hash symkey(base key)", ckm_to_string(derive));
	    DBG_dump_symkey("base key", base_key));
	PK11SymKey *result = PK11_Derive(base_key, derive, param, target,
					 operation, key_size);
	DBG(DBG_CRYPT, DBG_dump_symkey("result", result));
	
	return result;
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
	return merge_symkey_bytes(lhs, rhs.ptr, rhs.len,
				  CKM_XOR_BASE_AND_DATA,
				  CKM_CONCATENATE_BASE_AND_DATA);
}
