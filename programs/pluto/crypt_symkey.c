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
 * XXX: Is there any documentation on this generic operation?
 */
static PK11SymKey *merge_symkey_chunk(PK11SymKey *base_key, chunk_t chunk,
				      CK_MECHANISM_TYPE derive,
				      CK_MECHANISM_TYPE target)
{
	passert(chunk.len > 0);
	CK_KEY_DERIVATION_STRING_DATA string = {
		.pData = chunk.ptr,
		.ulLen = chunk.len,
	};
	SECItem param = {
		.data = (unsigned char*)&string,
		.len = sizeof(string),
	};
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;
	return PK11_Derive(base_key, derive, &param, target, operation, key_size);
}

/*
 * SYMKEY I/O operations.
 *
 * SYMKEY_FROM_CHUNK uses the SCRATCH key as a secure starting point
 * for creating the key.  The others don't so are not FIPS friendly.
 *
 * DECODE_TO_KEY decodes a hex encoded string.
 */

PK11SymKey *symkey_from_chunk(PK11SymKey *scratch, chunk_t chunk)
{
	PK11SymKey *tmp = merge_symkey_chunk(scratch, chunk,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY);
	passert(tmp != NULL);
	PK11SymKey *key = key_from_symkey_bytes(tmp, 0, chunk.len);
	passert(key != NULL);
	PK11_FreeSymKey(tmp);
	return key;
}

void dbg_dump_symkey(const char *prefix, PK11SymKey *key)
{
	chunk_t chunk = chunk_from_symkey_bytes(prefix, key, 0,
						PK11_GetKeyLength(key));
	DBG_dump_chunk(prefix, chunk);
	freeanychunk(chunk);
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
	return PK11_Derive(base_key, derive, &param, target, operation,
			   key_size);
}

PK11SymKey *concat_symkey_chunk(const struct hash_desc *hasher,
				PK11SymKey *lhs, chunk_t rhs)
{
	CK_MECHANISM_TYPE mechanism = nss_key_derivation_mech(hasher);
	return merge_symkey_chunk(lhs, rhs, CKM_CONCATENATE_BASE_AND_DATA,
				  mechanism);
}

PK11SymKey *concat_symkey_byte(const struct hash_desc *hasher,
			       PK11SymKey *lhs, uint8_t rhs)
{
	chunk_t byte;
	setchunk(byte, &rhs, sizeof(rhs));
	return concat_symkey_chunk(hasher, lhs, byte);
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
	PK11_FreeSymKey(*lhs);
	*lhs = newkey;
}

void append_symkey_chunk(const struct hash_desc *hasher,
			 PK11SymKey **lhs, chunk_t rhs)
{
	PK11SymKey *newkey = concat_symkey_chunk(hasher, *lhs, rhs);
	PK11_FreeSymKey(*lhs);
	*lhs = newkey;
}

void append_symkey_byte(const struct hash_desc *hasher,
			PK11SymKey **lhs, uint8_t rhs)
{
	chunk_t byte;
	setchunk(byte, &rhs, sizeof(rhs));
	append_symkey_chunk(hasher, lhs, byte);
}

/*
 * Extract SIZEOF_CHUNK raw-bytes from a SYMKEY.
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
	return PK11_DeriveWithFlags(base_key, derive, &param,
				    target, operation, key_size, flags);
}

chunk_t chunk_from_symkey_bits(const char *name, PK11SymKey *source_key,
			       size_t next_bit, size_t sizeof_chunk)
{
	if (sizeof_chunk == 0) {
		DBG(DBG_CRYPT, DBG_log("chunk_from_symkey: %s: zero size", name));
		return empty_chunk;
	}
	PK11SymKey *sym_key = key_from_key_bits(source_key,
						CKM_VENDOR_DEFINED, 0,
						next_bit, sizeof_chunk);
	if (sym_key == NULL) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_DeriveWithFlags failed while generating %s", name);
		return empty_chunk;
	}
	SECStatus s = PK11_ExtractKeyValue(sym_key);
	if (s != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_ExtractKeyValue failed while generating %s", name);
		return empty_chunk;
	}
	/* Internal structure address, do not free.  */
	SECItem *data = PK11_GetKeyData(sym_key);
	if (data == NULL) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_GetKeyData failed while generating %s", name);
		return empty_chunk;
	}
	DBG(DBG_CRYPT,
	    DBG_log("chunk_from_symkey: %s: extracted len %d bytes at %p",
		    name, data->len, data->data));
	if (data->len != sizeof_chunk) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_GetKeyData returned wrong number of bytes while generating %s", name);
		return empty_chunk;
	}
	chunk_t chunk;
	clonetochunk(chunk, data->data, data->len, name);
	DBG(DBG_CRYPT, DBG_dump_chunk(name, chunk));
	PK11_FreeSymKey(sym_key);
	return chunk;
}

chunk_t chunk_from_symkey_bytes(const char *name, PK11SymKey *source_key,
				size_t next_byte, size_t sizeof_chunk)
{
	return chunk_from_symkey_bits(name, source_key,
				      next_byte * BITS_PER_BYTE, sizeof_chunk);
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
				 size_t next_bit, int key_size)
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
	return PK11_Derive(base_key, derive, &param, target,
			   operation, key_size);
}

PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, int sizeof_key)
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
	return PK11_Derive(base_key, derive, param, target,
			   operation, key_size);
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
	return merge_symkey_chunk(lhs, rhs,
				  CKM_XOR_BASE_AND_DATA,
				  CKM_CONCATENATE_BASE_AND_DATA);
}
