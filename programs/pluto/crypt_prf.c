/*
 * PRF helper functions, for libreswan
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
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
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

//#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_prf.h"
#include "crypto.h"

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

/*
 * Extract SIZEOF_CHUNK bytes, starting at bit NEXT_BIT, from SOURCE_KEY.
 */
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

/*
 * Extract SIZEOF_CHUNK bytes, starting at byte NEXT_BYTE, from SOURCE_KEY.
 */
chunk_t chunk_from_symkey_bytes(const char *name, PK11SymKey *source_key,
				size_t next_byte, size_t sizeof_chunk)
{
	return chunk_from_symkey_bits(name, source_key,
				      next_byte * BITS_PER_BYTE, sizeof_chunk);
}

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
 * Extract key that doesn't need to support encryption.
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
	return key_from_symkey_bits(source_key, next_byte, sizeof_key);
}

/*
 * Run HASHR on the key material.
 *
 * The bizare call results in a hash operation and a returned key.
 */
static PK11SymKey *hash_symkey(const struct hash_desc *hasher,
			       PK11SymKey *material)
{
	return PK11_Derive_lsw(material, 
			       nss_key_derivation_mech(hasher),
			       NULL,
			       CKM_CONCATENATE_BASE_AND_KEY,
			       CKA_DERIVE,
			       0);
}

/*
 * Hack to convert a chunk into a symkey in a way that FIPS doesn't
 * notice - first stuff it into an existing key, and then extract it
 * again!
 */
PK11SymKey *symkey_from_chunk(PK11SymKey *scratch, chunk_t chunk)
{
	PK11SymKey *tmp = pk11_derive_wrapper_lsw(scratch,
						  CKM_CONCATENATE_DATA_AND_BASE,
						  chunk,
						  CKM_EXTRACT_KEY_FROM_KEY,
						  CKA_DERIVE, 0);
	passert(tmp != NULL);
	PK11SymKey *key = key_from_symkey_bytes(tmp, 0, chunk.len);
	passert(key != NULL);
	PK11_FreeSymKey(tmp);
	return key;
}

PK11SymKey *concat_symkey_symkey(const struct hash_desc *hasher,
				 PK11SymKey *lhs, PK11SymKey *rhs)
{
	CK_OBJECT_HANDLE keyhandle = PK11_GetSymKeyHandle(rhs);
	SECItem param = {
		.data = (unsigned char*)&keyhandle,
		.len = sizeof(keyhandle)
	};
	return PK11_Derive_lsw(lhs, CKM_CONCATENATE_BASE_AND_KEY,
			       &param, nss_key_derivation_mech(hasher),
			       CKA_DERIVE, 0);
}

void append_symkey_symkey(const struct hash_desc *hasher,
			  PK11SymKey **lhs, PK11SymKey *rhs)
{
	PK11SymKey *newkey = concat_symkey_symkey(hasher, *lhs, rhs);
	PK11_FreeSymKey(*lhs);
	*lhs = newkey;
}

PK11SymKey *concat_symkey_chunk(const struct hash_desc *hasher,
				PK11SymKey *lhs, chunk_t rhs)
{
	CK_MECHANISM_TYPE mechanism = nss_key_derivation_mech(hasher);
	return pk11_derive_wrapper_lsw(lhs, CKM_CONCATENATE_BASE_AND_DATA,
				       rhs, mechanism, CKA_DERIVE, 0);
}

void append_symkey_chunk(const struct hash_desc *hasher,
			 PK11SymKey **lhs, chunk_t rhs)
{
	PK11SymKey *newkey = concat_symkey_chunk(hasher, *lhs, rhs);
	PK11_FreeSymKey(*lhs);
	*lhs = newkey;
}

PK11SymKey *crypt_prf(const struct hash_desc *hasher,
		      PK11SymKey *raw_key, PK11SymKey *seed)
{
	PK11SymKey *key;
	/* too big, rehash */
	if (PK11_GetKeyLength(raw_key) > hasher->hash_block_size) {
		/* when too long hash, then pad */
		key = hash_symkey(hasher, raw_key);
	} else {
		/* need to be careful - don't free raw_key */
		key = raw_key;
	}
	/* too small, pad */
	if (PK11_GetKeyLength(key) < hasher->hash_block_size) {
		/* pad it to block_size. */
		chunk_t hmac_pad_prf = hmac_pads(0x00, (hasher->hash_block_size -
							PK11_GetKeyLength(raw_key)));
		PK11SymKey *tmp = pk11_derive_wrapper_lsw(key,
							  CKM_CONCATENATE_BASE_AND_DATA,
							  hmac_pad_prf,
							  CKM_CONCATENATE_BASE_AND_DATA,
							  CKA_DERIVE,
							  hasher->hash_block_size);
		freeanychunk(hmac_pad_prf);
		if (key != raw_key) {
			PK11_FreeSymKey(key);
		}
		key = tmp;
	}
	passert(key != NULL);

	/* Input to inner hash: (key^IPAD)|seed */
	chunk_t hmac_ipad = hmac_pads(HMAC_IPAD, hasher->hash_block_size);
	PK11SymKey *inner = pk11_derive_wrapper_lsw(key, CKM_XOR_BASE_AND_DATA,
						    hmac_ipad,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    CKA_DERIVE, 0);
	freeanychunk(hmac_ipad);
	append_symkey_symkey(hasher, &inner, seed);

	/* run that through hasher */
	PK11SymKey *hashed_inner = hash_symkey(hasher, inner);
	PK11_FreeSymKey(inner);

	/* Input to outer hash: (key^OPAD)|hashed_inner.  */
	chunk_t hmac_opad = hmac_pads(HMAC_OPAD, hasher->hash_block_size);
	PK11SymKey *outer = pk11_derive_wrapper_lsw(key, CKM_XOR_BASE_AND_DATA,
						    hmac_opad,
						    CKM_CONCATENATE_BASE_AND_DATA,
						    CKA_DERIVE, 0);
	freeanychunk(hmac_opad);
	append_symkey_symkey(hasher, &outer, hashed_inner);
	PK11_FreeSymKey(hashed_inner);

	/* Finally hash that */
	PK11SymKey *hashed_outer = hash_symkey(hasher, outer);
	PK11_FreeSymKey(outer);

	if (key != raw_key) {
		PK11_FreeSymKey(key);
	}

	return hashed_outer;
}

void dump_symkey(const char *prefix, PK11SymKey *key)
{
	chunk_t chunk = chunk_from_symkey_bytes(prefix, key, 0,
						PK11_GetKeyLength(key));
	DBG_dump_chunk(prefix, chunk);
	freeanychunk(chunk);
}

PK11SymKey *crypt_prfplus(const struct hash_desc *hasher,
			  PK11SymKey *key, PK11SymKey *seed,
			  size_t required_keymat)
{
	uint8_t count = 1;
	chunk_t count_chunk;
	setchunk(count_chunk, &count, sizeof(count));

	/* T1(prfplus) = prf(KEY, SEED|1) */
	PK11SymKey *prfplus;
	{
		PK11SymKey *value = concat_symkey_chunk(hasher, seed, count_chunk);
		prfplus = crypt_prf(hasher, key, value);
		PK11_FreeSymKey(value);
	}

	/* make a copy to keep things easy */
	PK11SymKey *old_t = key_from_symkey_bytes(prfplus, 0, PK11_GetKeyLength(prfplus));
	while (PK11_GetKeyLength(prfplus) < required_keymat) {
		/* Tn = prf(KEY, Tn-1|SEED|n) */
		PK11SymKey *value = concat_symkey_symkey(hasher, old_t, seed);
		count++;
		append_symkey_chunk(hasher, &value, count_chunk);
		PK11SymKey *new_t = crypt_prf(hasher, key, value);
		append_symkey_symkey(hasher, &prfplus, new_t);
		PK11_FreeSymKey(value);
		PK11_FreeSymKey(old_t);
		old_t = new_t;
	} 
	return prfplus;
}
