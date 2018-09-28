/*
 * SYMKEY manipulation functions, for libreswan
 *
 * Copyright (C) 2015-2017 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
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

#define SPACES "    "

static PK11SymKey *ephemeral_symkey(void)
{
	static int tried;
	static PK11SymKey *ephemeral_key;
	if (!tried) {
		tried = 1;
		/* get a secret key */
		PK11SlotInfo *slot = PK11_GetBestSlot(CKM_AES_KEY_GEN,
						      lsw_return_nss_password_file_info());
		if (slot == NULL) {
			LSWLOG_RC(RC_LOG_SERIOUS, buf) {
				lswlogs(buf, "NSS: ephemeral slot error");
				lswlog_nss_error(buf);
			}
			return NULL;
		}
		ephemeral_key = PK11_KeyGen(slot, CKM_AES_KEY_GEN,
					    NULL, 128/8, NULL);
		PK11_FreeSlot(slot); /* reference counted */
	}
	DBG(DBG_CRYPT_LOW, DBG_symkey(SPACES, "ephemeral", ephemeral_key));
	return ephemeral_key;
}

void release_symkey(const char *prefix, const char *name,
		    PK11SymKey **key)
{
	if (*key != NULL) {
		DBG(DBG_CRYPT_LOW, DBG_log("%s: release %s-key@%p",
				       prefix, name, *key));
		PK11_FreeSymKey(*key);
	} else {
		DBG(DBG_CRYPT_LOW, DBG_log("%s: release %s-key@NULL",
				       prefix, name));
	}
	*key = NULL;
}

PK11SymKey *reference_symkey(const char *prefix, const char *name,
			     PK11SymKey *key)
{
	if (key != NULL) {
		DBG(DBG_CRYPT_LOW, DBG_log("%s: reference %s-key@%p",
				       prefix, name, key));
		PK11_ReferenceSymKey(key);
	} else {
		DBG(DBG_CRYPT_LOW, DBG_log("%s: reference %s-key@NULL",
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
		LSWLOG_DEBUG(buf) {
			lswlogf(buf, "%s%s-key@%p, size: %zd bytes, type/mechanism: ",
				prefix, name, key, sizeof_symkey(key));
			lswlog_nss_ckm(buf, PK11_GetMechanism(key));
		}
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
static PK11SymKey *merge_symkey_bytes(const char *result_name,
				      PK11SymKey *base_key,
				      const void *data, size_t sizeof_data,
				      CK_MECHANISM_TYPE derive,
				      CK_MECHANISM_TYPE target)
{
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

	DBG(DBG_CRYPT_LOW,
	    LSWLOG_DEBUG(buf) {
		    lswlog_nss_ckm(buf, derive);
		    lswlogs(buf, ":");
	    }
	    DBG_symkey(SPACES, "base", base_key);
	    /* NULL suppresses the prefix */
	    DBG_log(SPACES "data-bytes@%p (%zd bytes)",
		    data, sizeof_data);
	    DBG_dump(SPACES, data, sizeof_data);
	    LSWLOG_DEBUG(buf) {
		    lswlogf(buf, SPACES "-> target: ");
		    lswlog_nss_ckm(buf, target);
	    })
	PK11SymKey *result = PK11_Derive(base_key, derive, &data_param, target,
					 operation, key_size);
	/*
	 * Should this abort?
	 *
	 * PORT_GetError() typically returns 0 - NSS forgets to save
	 * the error when things fail.
	 */
	if (result == NULL) {
		LSWLOG_PEXPECT(buf) {
			lswlog_nss_ckm(buf, derive);
			lswlogs(buf, "NSS failed");
			lswlog_nss_error(buf);
		}
	}
	DBG(DBG_CRYPT_LOW, DBG_symkey(SPACES "result: ", result_name, result))
	return result;
}

/*
 * Merge two SYMKEYs into a new SYMKEY.
 *
 * derive: the operation to be performed; target: the mechanism/type
 * of the resulting symkey.
 */

static PK11SymKey *merge_symkey_symkey(const char *result_name,
				       PK11SymKey *base_key,
				       PK11SymKey *key,
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
	DBG(DBG_CRYPT_LOW,
	    LSWLOG_DEBUG(buf) {
		    lswlog_nss_ckm(buf, derive);
		    lswlogs(buf, ":");
	    }
	    DBG_symkey(SPACES, "base", base_key);
	    DBG_symkey(SPACES, "key", key);
	    LSWLOG_DEBUG(buf) {
	      lswlogf(buf, SPACES "-> target: ");
		    lswlog_nss_ckm(buf, target);
	    })
	PK11SymKey *result = PK11_Derive(base_key, derive, &key_param, target,
					 operation, key_size);
	/*
	 * Should this abort?
	 *
	 * PORT_GetError() typically returns 0 - NSS forgets to save
	 * the error when things fail.
	 */
	if (result == NULL) {
		LSWLOG_PEXPECT(buf) {
			lswlog_nss_ckm(buf, derive);
			lswlogs(buf, ": NSS failed");
			lswlog_nss_error(buf);
		}
	}
	DBG(DBG_CRYPT_LOW, DBG_symkey(SPACES "result: ", result_name, result));
	return result;
}

/*
 * Extract a SYMKEY from an existing SYMKEY.
 */
static PK11SymKey *symkey_from_symkey(const char *result_name,
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
	CK_ATTRIBUTE_TYPE operation = CKA_FLAGS_ONLY;

	DBG(DBG_CRYPT_LOW,
	    LSWLOG_DEBUG(buf) {
		    lswlog_nss_ckm(buf, derive);
		    lswlogs(buf, ":");
	    }
	    DBG_symkey(SPACES, "key", base_key);
	    DBG_log(SPACES "key-offset: %zd, key-size: %zd",
		    key_offset, key_size);
	    LSWLOG_DEBUG(buf) {
		    lswlogs(buf, SPACES "-> flags: ");
		    lswlog_nss_ckf(buf, flags);
		    lswlogf(buf, " target: ");
		    lswlog_nss_ckm(buf, target);
	    })
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
		LSWLOG_PEXPECT(buf) {
			lswlog_nss_ckm(buf, derive);
			lswlogf(buf, ": NSS failed");
			lswlog_nss_error(buf);
		}
	}
	DBG(DBG_CRYPT_LOW, DBG_symkey(SPACES "result: ", result_name, result));
	return result;
}


/*
 * For on-wire algorithms.
 */
chunk_t chunk_from_symkey(const char *name, PK11SymKey *symkey)
{
	SECStatus status;
	if (symkey == NULL) {
		DBGF(DBG_CRYPT_LOW, "%s NULL key has no bytes", name);
		return empty_chunk;
	}

	size_t sizeof_bytes = sizeof_symkey(symkey);
	DBGF(DBG_CRYPT_LOW, "%s extracting all %zd bytes of key@%p",
	     name, sizeof_bytes, symkey);
	DBG(DBG_CRYPT_LOW, DBG_symkey(name, "symkey", symkey));

	/* get a secret key */
	PK11SymKey *ephemeral_key = ephemeral_symkey();
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
	if (DBGP(DBG_CRYPT_LOW)) {
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
	DBG(DBG_CRYPT_LOW, DBG_log("sizeof bytes %d", wrapped_key.len));
	status = PK11_WrapSymKey(CKM_AES_ECB, NULL, ephemeral_key, slot_key,
				 &wrapped_key);
	if (status != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "%s NSS: containment error (%d)",
		       name, status);
		pfreeany(wrapped_key.data);
		release_symkey(name, "slot-key", &slot_key);
		return empty_chunk;
	}
	LSWDBGP(DBG_CRYPT_LOW, buf) {
		lswlogs(buf, "wrapper: ");
		lswlog_nss_secitem(buf, &wrapped_key);
	}

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

	DBG(DBG_CRYPT_LOW, DBG_log("%s extracted len %d bytes at %p", name, out_len, bytes));
	DBG(DBG_CRYPT_LOW, DBG_dump("unwrapped:", bytes, out_len));

	return (chunk_t) {
		.ptr = bytes,
		.len = sizeof_bytes,
	};
}

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as a generic
 * key.
 *
 * Since NSS NSS expects a key's mechanism to match the NSS algorithm
 * the key is intended for, this generic key cannot be used for
 * encryption and/or PRF calculation.  Instead use encrypt_key_*() or
 * prf_key_*().
 *
 * Offset into the SYMKEY is in BYTES.
 */

PK11SymKey *symkey_from_bytes(const char *name, const uint8_t *bytes, size_t sizeof_bytes)
{
	if (sizeof_bytes == 0) {
		/* hopefully caller knows what they are doing */
		return NULL;
	}

	PK11SymKey *scratch = ephemeral_symkey();
	PK11SymKey *tmp = merge_symkey_bytes(name, scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY);
	passert(tmp != NULL);
	/*
	 * Something of an old code hack.  Keys fed to the hasher, for
	 * instance, get this type.
	 */
	CK_FLAGS flags = 0;
	CK_MECHANISM_TYPE target = CKM_EXTRACT_KEY_FROM_KEY;
	PK11SymKey *key = symkey_from_symkey(name, tmp, target, flags,
					     0, sizeof_bytes);
	passert(key != NULL);
	release_symkey(name, "tmp", &tmp);
	return key;
}

PK11SymKey *symkey_from_chunk(const char *name, chunk_t chunk)
{
	return symkey_from_bytes(name, chunk.ptr, chunk.len);
}

PK11SymKey *encrypt_key_from_bytes(const char *name,
				   const struct encrypt_desc *encrypt,
				   const uint8_t *bytes, size_t sizeof_bytes)
{
	PK11SymKey *scratch = ephemeral_symkey();
	PK11SymKey *tmp = merge_symkey_bytes(name, scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY);
	passert(tmp != NULL);
	PK11SymKey *key = encrypt_key_from_symkey_bytes(name, encrypt,
							0, sizeof_bytes, tmp);
	passert(key != NULL);
	release_symkey(name, "tmp", &tmp);
	return key;
}

PK11SymKey *prf_key_from_bytes(const char *name, const struct prf_desc *prf,
			       const uint8_t *bytes, size_t sizeof_bytes)
{
	PK11SymKey *scratch = ephemeral_symkey();
	PK11SymKey *tmp = merge_symkey_bytes(name, scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY);
	passert(tmp != NULL);
	PK11SymKey *key = prf_key_from_symkey_bytes(name, prf,
						    0, sizeof_bytes, tmp);
	passert(key != NULL);
	release_symkey(name, "tmp", &tmp);
	return key;
}

/*
 * Concatenate two pieces of keying material creating a
 * new SYMKEY object.
 */

PK11SymKey *concat_symkey_symkey(PK11SymKey *lhs, PK11SymKey *rhs)
{
	return merge_symkey_symkey("result", lhs, rhs,
				   CKM_CONCATENATE_BASE_AND_KEY,
				   PK11_GetMechanism(lhs));
}

PK11SymKey *concat_symkey_bytes(PK11SymKey *lhs, const void *rhs,
				size_t sizeof_rhs)
{
	return merge_symkey_bytes("result", lhs, rhs, sizeof_rhs,
				  CKM_CONCATENATE_BASE_AND_DATA,
				  PK11_GetMechanism(lhs));
}

PK11SymKey *concat_bytes_symkey(const void *lhs, size_t sizeof_lhs,
				PK11SymKey *rhs)
{
	/* copy the existing KEY's type (mechanism).  */
	CK_MECHANISM_TYPE target = PK11_GetMechanism(rhs);
	return merge_symkey_bytes("result", rhs, lhs, sizeof_lhs,
				  CKM_CONCATENATE_DATA_AND_BASE,
				  target);
}

chunk_t concat_chunk_symkey(const char *name, chunk_t lhs, PK11SymKey *rhs)
{
	chunk_t rhs_chunk = chunk_from_symkey(name, rhs);
	chunk_t new = clone_chunk_chunk(lhs, rhs_chunk, name);
	freeanychunk(rhs_chunk);
	return new;
}

PK11SymKey *concat_symkey_chunk(PK11SymKey *lhs, chunk_t rhs)
{
	return concat_symkey_bytes(lhs, rhs.ptr, rhs.len);
}

PK11SymKey *concat_symkey_byte(PK11SymKey *lhs, uint8_t rhs)
{
	return concat_symkey_bytes(lhs, &rhs, sizeof(rhs));
}

chunk_t concat_chunk_bytes(const char *name, chunk_t lhs,
			   const void *rhs, size_t sizeof_rhs)
{
	size_t len = lhs.len + sizeof_rhs;
	chunk_t cat = {
		.len = len,
		.ptr = alloc_things(uint8_t, len, name),
	};
	memcpy(cat.ptr, lhs.ptr, lhs.len);
	memcpy(cat.ptr + lhs.len, rhs, sizeof_rhs);
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
	chunk_t new = clone_chunk_chunk(*lhs, rhs, name);
	freeanychunk(*lhs);
	*lhs = new;
}

void append_chunk_bytes(const char *name, chunk_t *lhs,
			const void *rhs, size_t sizeof_rhs)
{
	chunk_t new = concat_chunk_bytes(name, *lhs, rhs, sizeof_rhs);
	freeanychunk(*lhs);
	*lhs = new;
}

void append_chunk_symkey(const char *name, chunk_t *lhs, PK11SymKey *rhs)
{
	chunk_t new = concat_chunk_symkey(name, *lhs, rhs);
	freeanychunk(*lhs);
	*lhs = new;
}

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as a PRF key.
 *
 * Offset into the SYMKEY is in BYTES.
 */

PK11SymKey *prf_key_from_symkey_bytes(const char *name,
				      const struct prf_desc *prf,
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
	 *
	 * XXX: this function should be part of prf_ops.
	 */
	CK_FLAGS flags;
	CK_MECHANISM_TYPE mechanism;
	if (prf->nss.mechanism == 0) {
		flags = 0;
		mechanism = CKM_VENDOR_DEFINED;
	} else {
		flags = CKF_SIGN;
		mechanism = prf->nss.mechanism;
	}
	return symkey_from_symkey(name, source_key, mechanism, flags,
				  symkey_start_byte, sizeof_symkey);
}

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ENCRYPTER key
 * (i.e., can be used to encrypt/decrypt data using ENCRYPTER).
 *
 * Offset into the SYMKEY is in BYTES.
 */

PK11SymKey *encrypt_key_from_symkey_bytes(const char *name,
					  const struct encrypt_desc *encrypt,
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
	 *
	 * XXX: This function should be part of encrypt_ops.
	 */
	CK_FLAGS flags;
	CK_MECHANISM_TYPE mechanism;
	if (encrypt->nss.mechanism == 0) {
		flags = 0;
		mechanism = CKM_VENDOR_DEFINED;
	} else {
		flags = CKF_ENCRYPT | CKF_DECRYPT;
		mechanism = encrypt->nss.mechanism;
	}
	return symkey_from_symkey(name, source_key, mechanism, flags,
				  symkey_start_byte, sizeof_symkey);
}

PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, size_t sizeof_key)
{
	return symkey_from_symkey("result", source_key,
				  CKM_EXTRACT_KEY_FROM_KEY,
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
	return merge_symkey_bytes("result", lhs, rhs.ptr, rhs.len,
				  CKM_XOR_BASE_AND_DATA,
				  CKM_CONCATENATE_BASE_AND_DATA);
}
