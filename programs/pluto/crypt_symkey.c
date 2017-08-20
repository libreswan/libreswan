/*
 * SYMKEY manipulation functions, for libreswan
 *
 * Copyright (C) 2015-2017 Andrew Cagney <cagney@gnu.org>
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
#include "lswfips.h"
#include "lswnss.h"


struct nss_alg {
	CK_FLAGS flags;
	CK_MECHANISM_TYPE mechanism;
};

static struct nss_alg nss_alg(const char *verb, const char *name, lset_t debug,
			      const struct ike_alg *alg)
{
	/*
	 * NSS expects a key's mechanism to match the NSS algorithm
	 * the key is intended for.  If this is wrong then the
	 * operation fails.
	 *
	 * Unfortunately, some algorithms are not implemented by NSS,
	 * so the correct key type can't always be specified.  For
	 * those specify CKM_VENDOR_DEFINED.
	 */
	CK_FLAGS flags;
	CK_MECHANISM_TYPE mechanism;
	if (alg == NULL) {
		/*
		 * Something of an old code hack.  Keys fed to the
		 * hasher get this type.
		 */
		mechanism = CKM_EXTRACT_KEY_FROM_KEY;
		flags = 0;
		if (DBGP(debug)) {
			DBG_log("%s %s for non-NSS algorithm: NULL (legacy hack), mechanism: %s(%lu), flags: %lx",
				verb, name,
				lsw_nss_ckm_to_string(mechanism), mechanism,
				flags);
		}
	} else if (alg->nss_mechanism == 0) {
		/*
		 * A non-NSS algorithm.  The values shouldn't matter.
		 */
		mechanism = CKM_VENDOR_DEFINED;
		flags = 0;
		if (DBGP(debug)) {
			DBG_log("%s %s for non-NSS algorithm: %s, mechanism: %s(%lu), flags: %lx",
				verb, name, alg->name,
				lsw_nss_ckm_to_string(mechanism), mechanism,
				flags);
		}
	} else {
		mechanism = alg->nss_mechanism;
		if (alg->algo_type == IKE_ALG_ENCRYPT) {
			flags = CKF_ENCRYPT | CKF_DECRYPT;
		} else if (alg->algo_type == IKE_ALG_PRF
			   || alg->algo_type == IKE_ALG_INTEG) {
			flags = CKF_SIGN;
		} else if (alg->algo_type == IKE_ALG_HASH) {
			flags = CKF_DIGEST;
		} else {
			flags = 0;	/* flags not subsequently used */
			/* should never happen - ike_alg checks for this */
			PASSERT_FAIL("NSS algorithm '%s' type %s unknown",
				     alg->name, ike_alg_type_name(alg->algo_type));
		}
		if (DBGP(debug)) {
			DBG_log("%s %s for NSS algorithm: %s, mechanism: %s(%lu), flags: %lx",
				verb, name, alg->name,
				lsw_nss_ckm_to_string(mechanism), mechanism,
				flags);
		}
	}
	return (struct nss_alg) {
		.mechanism = mechanism,
		.flags = flags,
	};
}

static PK11SymKey *ephemeral_symkey(int debug)
{
	static int tried;
	static PK11SymKey *ephemeral_key;
	if (!tried) {
		tried = 1;
		/* get a secret key */
		PK11SlotInfo *slot = PK11_GetBestSlot(CKM_AES_KEY_GEN,
						      lsw_return_nss_password_file_info());
		if (slot == NULL) {
			loglog(RC_LOG_SERIOUS, "NSS: ephemeral slot error");
			return NULL;
		}
		ephemeral_key = PK11_KeyGen(slot, CKM_AES_KEY_GEN,
					    NULL, 128/8, NULL);
		PK11_FreeSlot(slot); /* reference counted */
	}
	DBG(debug, DBG_symkey("internal", "ephemeral", ephemeral_key));
	return ephemeral_key;
}

void release_symkey(const char *prefix, const char *name,
		    PK11SymKey **key)
{
	if (*key != NULL) {
		DBG(DBG_CRYPT, DBG_log("%s: release %s-key@%p",
				       prefix, name, *key));
		PK11_FreeSymKey(*key);
	} else {
		DBG(DBG_CRYPT, DBG_log("%s: release %s-key@NULL",
				       prefix, name));
	}
	*key = NULL;
}

PK11SymKey *reference_symkey(const char *prefix, const char *name,
			     PK11SymKey *key)
{
	if (key != NULL) {
		DBG(DBG_CRYPT, DBG_log("%s: reference %s-key@%p",
				       prefix, name, key));
		PK11_ReferenceSymKey(key);
	} else {
		DBG(DBG_CRYPT, DBG_log("%s: reference %s-key@NULL",
				       prefix, name));
	}
	return key;
}

size_t sizeof_symkey(PK11SymKey *key)
{
	if (key == NULL) {
		return 0;
	} else {
		return PK11_GetKeyLength(key);
	}
}

void DBG_symkey(const char *prefix, const char *name, PK11SymKey *key)
{
	if (key == NULL) {
		/*
		 * For instance, when a zero-length key gets extracted
		 * from an existing key.
		 */
		DBG_log("%s: %s-key@NULL", prefix, name);
	} else {
		DBG_log("%s: %s-key@%p, size: %zd bytes, type/mechanism: %s (0x%08x)",
			prefix, name, key, sizeof_symkey(key),
			lsw_nss_ckm_to_string(PK11_GetMechanism(key)),
			(int)PK11_GetMechanism(key));
#if 0
		if (DBGP(DBG_PRIVATE)) {
			if (libreswan_fipsmode()) {
				DBG_log("%s secured by FIPS", prefix);
			} else {
				chunk_t bytes = chunk_from_symkey(prefix, 0, key);
				/* NULL suppresses the dump header */
				DBG_dump_chunk(NULL, bytes);
				freeanychunk(bytes);
			}
		}
#endif
	}
}

/*
 * Merge a symkey and an array of bytes into a new SYMKEY.
 *
 * derive: the operation that is to be performed; target: the
 * mechanism/type of the resulting symkey.
 */
static PK11SymKey *merge_symkey_bytes(lset_t debug, PK11SymKey *base_key,
				      const void *data, size_t sizeof_data,
				      CK_MECHANISM_TYPE derive,
				      CK_MECHANISM_TYPE target)
{
	const char *prefix = lsw_nss_ckm_to_string(derive);
	passert(sizeof_data > 0);
	CK_KEY_DERIVATION_STRING_DATA string = {
		.pData = (void *)data,
		.ulLen = sizeof_data,
	};
	SECItem data_param = {
		.data = (unsigned char*)&string,
		.len = sizeof(string),
	};
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;

	DBG(debug,
	    DBG_log("%s: base-key@%p, data-bytes@%p (%zd bytes) -> target: %s",
		    prefix, base_key, data, sizeof_data,
		    lsw_nss_ckm_to_string(target));
	    DBG_symkey(prefix, "base", base_key);
	    DBG_log("%s: data", prefix);
	    /* NULL suppresses the prefix */
	    DBG_dump(NULL, data, sizeof_data));
	PK11SymKey *result = PK11_Derive(base_key, derive, &data_param, target,
					 operation, key_size);
	/*
	 * Should this abort?
	 *
	 * PORT_GetError() typically returns 0 - NSS forgets to save
	 * the error when things fail.
	 */
	if (result == NULL) {
		PEXPECT_LOG("%s: NSS failed with error %d(0x%x) (0 means error unknown)",
			    prefix, PORT_GetError(), PORT_GetError());
	}
	DBG(debug, DBG_symkey(prefix, "new result", result))
	return result;
}

/*
 * Merge two SYMKEYs into a new SYMKEY.
 *
 * derive: the operation to be performed; target: the mechanism/type
 * of the resulting symkey.
 */

static PK11SymKey *merge_symkey_symkey(lset_t debug, PK11SymKey *base_key,
				       PK11SymKey *key,
				       CK_MECHANISM_TYPE derive,
				       CK_MECHANISM_TYPE target)
{
	const char *prefix = lsw_nss_ckm_to_string(derive);
	CK_OBJECT_HANDLE key_handle = PK11_GetSymKeyHandle(key);
	SECItem key_param = {
		.data = (unsigned char*)&key_handle,
		.len = sizeof(key_handle)
	};
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;
	DBG(debug,
	    DBG_log("%s: base-key@%p, key@%p -> target: %s",
		    prefix, base_key, key,
		    lsw_nss_ckm_to_string(target));
	    DBG_symkey(prefix, "base", base_key);
	    DBG_symkey(prefix, "key", key));
	PK11SymKey *result = PK11_Derive(base_key, derive, &key_param, target,
					 operation, key_size);
	/*
	 * Should this abort?
	 *
	 * PORT_GetError() typically returns 0 - NSS forgets to save
	 * the error when things fail.
	 */
	if (result == NULL) {
		PEXPECT_LOG("%s: NSS failed with error %d(0x%x) (0 means error unknown)",
			    prefix, PORT_GetError(), PORT_GetError());
	}
	DBG(debug, DBG_symkey(prefix, "new result", result));
	return result;
}

/*
 * Extract a SYMKEY from an existing SYMKEY.
 */
static PK11SymKey *symkey_from_symkey(lset_t debug,
				      PK11SymKey *base_key,
				      CK_MECHANISM_TYPE target,
				      CK_FLAGS flags,
				      size_t key_offset, size_t key_size)
{
	/* spell out all the parameters */
	CK_EXTRACT_PARAMS bs = key_offset * BITS_PER_BYTE;
	SECItem param = {
		.data = (unsigned char*)&bs,
		.len = sizeof(bs),
	};
	CK_MECHANISM_TYPE derive = CKM_EXTRACT_KEY_FROM_KEY;
	const char *prefix = lsw_nss_ckm_to_string(derive);
	CK_ATTRIBUTE_TYPE operation = CKA_FLAGS_ONLY;

	DBG(debug,
	    DBG_log("%s: key@%p, key-offset: %zd, key-size: %zd, flags: 0x%lx -> target: %s",
		    prefix, base_key, key_offset, key_size, (long)flags,
		    lsw_nss_ckm_to_string(target));
	    DBG_symkey(prefix, "key", base_key));
	PK11SymKey *result = PK11_DeriveWithFlags(base_key, derive, &param,
						  target, operation,
						  key_size, flags);
	/*
	 * Should this abort?
	 *
	 * PORT_GetError() typically returns 0 - NSS forgets to save
	 * the error when things fail.
	 *
	 * NSS returns NULL when key_size is 0.
	 */
	if (result == NULL && key_size > 0) {
		PEXPECT_LOG("%s: NSS failed with error %d(0x%x) (0 means error unknown)",
			    prefix, PORT_GetError(), PORT_GetError());
	}
	DBG(debug, DBG_symkey(prefix, "new result", result));
	return result;
}


/*
 * For on-wire algorithms.
 */
chunk_t chunk_from_symkey(const char *name, lset_t debug,
			  PK11SymKey *symkey)
{
	SECStatus status;
	if (symkey == NULL) {
		DBG(debug, DBG_log("%s NULL key has no bytes", name));
		return empty_chunk;
	}

	size_t sizeof_bytes = sizeof_symkey(symkey);
	DBG(debug, DBG_log("%s extracting all %zd bytes of key@%p",
			     name, sizeof_bytes, symkey));
	DBG(debug, DBG_symkey(name, "symkey", symkey));

	/* get a secret key */
	PK11SymKey *ephemeral_key = ephemeral_symkey(debug);
	if (ephemeral_key == NULL) {
		loglog(RC_LOG_SERIOUS, "%s NSS: ephemeral error", name);
		return empty_chunk;
	}

	/*
	 * Ensure that the source key shares a slot with the
	 * ephemeral_key.  The "move" always returns something that
	 * needs to be released (if no move is needed, the reference
	 * count is incremented).
	 */
	PK11SymKey *slot_key;
	{
		PK11SlotInfo *slot = PK11_GetSlotFromKey(ephemeral_key);
		slot_key = PK11_MoveSymKey(slot, CKA_UNWRAP, 0, 0, symkey);
		PK11_FreeSlot(slot); /* reference counted */
		if (slot_key == NULL) {
			loglog(RC_LOG_SERIOUS, "%s NSS: slot error", name);
			return empty_chunk;
		}
	}
	if (DBGP(debug)) {
	    if (slot_key == symkey) {
		    /* output should mimic reference_symkey() */
		    DBG_log("%s: slot-key@%p: reference sym-key@%p",
			    name, slot_key, symkey);
	    } else {
		    DBG_symkey(name, "new slot", slot_key);
	    }
	}

	SECItem wrapped_key;
	/* Round up the wrapped key length to a 16-byte boundary.  */
	wrapped_key.len = (sizeof_bytes + 15) & ~15;
	wrapped_key.data = alloc_bytes(wrapped_key.len, name);
	DBG(debug, DBG_log("sizeof bytes %d", wrapped_key.len));
	status = PK11_WrapSymKey(CKM_AES_ECB, NULL, ephemeral_key, slot_key,
				 &wrapped_key);
	if (status != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "%s NSS: containment error (%d)",
		       name, status);
		pfreeany(wrapped_key.data);
		release_symkey(name, "slot-key", &slot_key);
		return empty_chunk;
	}
	DBG(debug, DBG_dump("wrapper:", wrapped_key.data, wrapped_key.len));

	void *bytes = alloc_bytes(wrapped_key.len, name);
	unsigned int out_len = 0;
	status = PK11_Decrypt(ephemeral_key, CKM_AES_ECB, NULL,
			      bytes, &out_len, wrapped_key.len,
			      wrapped_key.data, wrapped_key.len);
	pfreeany(wrapped_key.data);
	release_symkey(name, "slot-key", &slot_key);
	if (status != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "%s NSS: error calculating contents (%d)",
		       name, status);
		return empty_chunk;
	}
	passert(out_len >= sizeof_bytes);

	DBG(debug, DBG_log("%s extracted len %d bytes at %p", name, out_len, bytes));
	DBG(debug, DBG_dump("unwrapped:", bytes, out_len));

	return (chunk_t) {
		.ptr = bytes,
		.len = sizeof_bytes,
	};
}

/*
 * SYMKEY I/O operations.
 */

PK11SymKey *symkey_from_bytes(const char *name, lset_t debug,
			      const struct ike_alg *alg,
			      const u_int8_t *bytes, size_t sizeof_bytes)
{
	PK11SymKey *scratch = ephemeral_symkey(debug);
	PK11SymKey *tmp = merge_symkey_bytes(debug, scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY);
	passert(tmp != NULL);
	PK11SymKey *key = symkey_from_symkey_bytes(name, debug, alg,
						   0, sizeof_bytes, tmp);
	passert(key != NULL);
	release_symkey(name, "tmp", &tmp);
	return key;
}

PK11SymKey *symkey_from_chunk(const char *name, lset_t debug,
			      const struct ike_alg *alg,
			      chunk_t chunk)
{
	return symkey_from_bytes(name, debug, alg,
				 chunk.ptr, chunk.len);
}

/*
 * Concatenate two pieces of keying material creating a
 * new SYMKEY object.
 */

PK11SymKey *concat_symkey_symkey(PK11SymKey *lhs, PK11SymKey *rhs)
{
	return merge_symkey_symkey(DBG_CRYPT, lhs, rhs,
				   CKM_CONCATENATE_BASE_AND_KEY,
				   PK11_GetMechanism(lhs));
}

PK11SymKey *concat_symkey_bytes(PK11SymKey *lhs, const void *rhs,
				size_t sizeof_rhs)
{
	return merge_symkey_bytes(DBG_CRYPT, lhs, rhs, sizeof_rhs,
				  CKM_CONCATENATE_BASE_AND_DATA,
				  PK11_GetMechanism(lhs));
}

PK11SymKey *concat_bytes_symkey(const void *lhs, size_t sizeof_lhs,
				PK11SymKey *rhs)
{
	/* copy the existing KEY's type (mechanism).  */
	CK_MECHANISM_TYPE target = PK11_GetMechanism(rhs);
	return merge_symkey_bytes(DBG_CRYPT, rhs, lhs, sizeof_lhs,
				  CKM_CONCATENATE_DATA_AND_BASE,
				  target);
}

PK11SymKey *concat_symkey_chunk(PK11SymKey *lhs, chunk_t rhs)
{
	return concat_symkey_bytes(lhs, rhs.ptr, rhs.len);
}

PK11SymKey *concat_symkey_byte(PK11SymKey *lhs, uint8_t rhs)
{
	return concat_symkey_bytes(lhs, &rhs, sizeof(rhs));
}

chunk_t concat_chunk_chunk(const char *name, chunk_t lhs, chunk_t rhs)
{
	size_t len = lhs.len + rhs.len;
	chunk_t cat = {
		.len = len,
		.ptr = alloc_things(u_int8_t, len, name),
	};
	memcpy(cat.ptr, lhs.ptr, lhs.len);
	memcpy(cat.ptr + lhs.len, rhs.ptr, rhs.len);
	return cat;
}

/*
 * Append new keying material to an existing key; replace the existing
 * key with the result.
 *
 * Use this to chain a series of concat operations.
 */

void append_symkey_symkey(PK11SymKey **lhs, PK11SymKey *rhs)
{
	PK11SymKey *newkey = concat_symkey_symkey(*lhs, rhs);
	release_symkey(__func__, "lhs", lhs);
	*lhs = newkey;
}

void append_symkey_bytes(PK11SymKey **lhs, const void *rhs,
			 size_t sizeof_rhs)
{
	PK11SymKey *newkey = concat_symkey_bytes(*lhs, rhs, sizeof_rhs);
	release_symkey(__func__, "lhs", lhs);
	*lhs = newkey;
}

void append_bytes_symkey(const void *lhs, size_t sizeof_lhs,
			 PK11SymKey **rhs)
{
	PK11SymKey *newkey = concat_bytes_symkey(lhs, sizeof_lhs, *rhs);
	release_symkey(__func__, "rhs", rhs);
	*rhs = newkey;
}

void append_symkey_chunk(PK11SymKey **lhs, chunk_t rhs)
{
	append_symkey_bytes(lhs, rhs.ptr, rhs.len);
}

void append_symkey_byte(PK11SymKey **lhs, uint8_t rhs)
{
	append_symkey_bytes(lhs, &rhs, sizeof(rhs));
}

void append_chunk_chunk(const char *name, chunk_t *lhs, chunk_t rhs)
{
	chunk_t new = concat_chunk_chunk(name, *lhs, rhs);
	freeanychunk(*lhs);
	*lhs = new;
}

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ENCRYPTER key
 * (i.e., can be used to encrypt/decrypt data using ENCRYPTER).
 *
 * Offset into the SYMKEY is in BYTES.
 */

PK11SymKey *symkey_from_symkey_bytes(const char *name, lset_t debug,
				     const struct ike_alg *symkey_alg,
				     size_t symkey_start_byte, size_t sizeof_symkey,
				     PK11SymKey *source_key)
{
	/*
	 * NSS expects a key's mechanism to match the NSS algorithm
	 * the key is intended for.  If this is wrong then the
	 * operation fails.
	 *
	 * Unfortunately, some algorithms are not implemented by NSS,
	 * so the correct key type can't always be specified.  For
	 * those specify CKM_VENDOR_DEFINED.
	 */
	struct nss_alg nss = nss_alg("extract symkey", name, debug, symkey_alg);
	return symkey_from_symkey(debug, source_key, nss.mechanism, nss.flags,
				  symkey_start_byte, sizeof_symkey);
}

PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, size_t sizeof_key)
{
	return symkey_from_symkey(DBG_CRYPT, source_key, CKM_EXTRACT_KEY_FROM_KEY,
				  0, next_byte, sizeof_key);
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
	return merge_symkey_bytes(DBG_CRYPT, lhs, rhs.ptr, rhs.len,
				  CKM_XOR_BASE_AND_DATA,
				  CKM_CONCATENATE_BASE_AND_DATA);
}
