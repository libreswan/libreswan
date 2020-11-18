/*
 * SYMKEY manipulation functions, for libreswan
 *
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_symkey.h"
#include "lswfips.h"
#include "lswnss.h"

#define SPACES "    "

static PK11SymKey *ephemeral_symkey;

void init_crypt_symkey(struct logger *logger)
{
	/* get a secret key */
	PK11SlotInfo *slot = PK11_GetBestSlot(CKM_AES_KEY_GEN,
					      lsw_nss_get_password_context(logger));
	if (slot == NULL) {
		char error[LOG_WIDTH];
		struct jambuf buf[1] = { ARRAY_AS_JAMBUF(error), };
		jam(buf, "NSS: ephemeral slot error: ");
		jam_nss_error(buf);
		fatal(PLUTO_EXIT_FAIL, logger, "%s", error);
	}
	ephemeral_symkey = PK11_KeyGen(slot, CKM_AES_KEY_GEN,
				       NULL, 128/8, NULL);
	PK11_FreeSlot(slot); /* reference counted */
	if (DBGP(DBG_CRYPT)) {
		DBG_symkey(logger, SPACES, "ephemeral", ephemeral_symkey);
	}
}

void release_symkey(const char *prefix, const char *name,
		    PK11SymKey **key)
{
	if (*key != NULL) {
		DBGF(DBG_REFCNT, "%s: delref %s-key@%p",
		     prefix, name, *key);
		PK11_FreeSymKey(*key);
	} else {
		DBGF(DBG_REFCNT, "%s: delref %s-key@NULL",
		     prefix, name);
	}
	*key = NULL;
}

PK11SymKey *reference_symkey(const char *prefix, const char *name,
			     PK11SymKey *key)
{
	if (key != NULL) {
		DBGF(DBG_REFCNT, "%s: addref %s-key@%p",
		     prefix, name, key);
		PK11_ReferenceSymKey(key);
	} else {
		DBGF(DBG_REFCNT, "%s: addref %s-key@NULL",
		     prefix, name);
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

void jam_symkey(struct jambuf *buf, const char *name, PK11SymKey *key)
{
	if (key == NULL) {
		/*
		 * For instance, when a zero-length key gets extracted
		 * from an existing key.
		 */
		jam(buf, "%s-key@NULL", name);
	} else {
		jam(buf, "%s-key@%p (%zd-bytes, ",
		    name, key, sizeof_symkey(key));
		jam_nss_ckm(buf, PK11_GetMechanism(key));
		jam(buf, ")");
	}
}

void DBG_symkey(struct logger *logger, const char *prefix, const char *name, PK11SymKey *key)
{
	LOG_JAMBUF(DEBUG_STREAM, logger, buf) {
		jam(buf, "%s: ", prefix);
		jam_symkey(buf, name, key);
	}
#if 0
	if (DBGP(DBG_CRYPT)) {
		if (libreswan_fipsmode()) {
			DBG_log("%s secured by FIPS", prefix);
		} else {
			chunk_t bytes = chunk_from_symkey(prefix, key, logger);
			/* NULL suppresses the dump header */
			DBG_dump_hunk(NULL, bytes);
			free_chunk_content(&bytes);
		}
	}
#endif
}

PK11SymKey *crypt_derive(PK11SymKey *base_key, CK_MECHANISM_TYPE derive, SECItem *params,
			 const char *target_name, CK_MECHANISM_TYPE target_mechanism,
			 CK_ATTRIBUTE_TYPE operation,
			 int key_size, CK_FLAGS flags,
			 where_t where, struct logger *logger)
{
#define DBG_DERIVE()							\
	LOG_JAMBUF(DEBUG_STREAM, logger, buf) {				\
		jam_nss_ckm(buf, derive);				\
		jam_string(buf, ":");					\
	}								\
	LOG_JAMBUF(DEBUG_STREAM, logger, buf) {				\
		jam_string(buf, SPACES"target: ");			\
		jam_nss_ckm(buf, target_mechanism);			\
	}								\
	if (flags != 0) {						\
		LOG_JAMBUF(DEBUG_STREAM, logger, buf) {			\
			jam_string(buf, SPACES"flags: ");		\
			jam_nss_ckf(buf, flags);			\
		}							\
	}								\
	if (key_size != 0) {						\
		LOG_JAMBUF(DEBUG_STREAM, logger, buf) {			\
			jam(buf, SPACES "key_size: %d-bytes",		\
			    key_size);					\
		}							\
	}								\
	LOG_JAMBUF(DEBUG_STREAM, logger, buf) {				\
		jam_string(buf, SPACES"base: ");			\
		jam_symkey(buf, "base", base_key);			\
	}								\
	if (operation != CKA_DERIVE) {					\
		LOG_JAMBUF(DEBUG_STREAM, logger, buf) {			\
			jam_string(buf, SPACES"operation: ");		\
			jam_nss_cka(buf, operation);			\
		}							\
	}								\
	if (params != NULL) {						\
		LOG_JAMBUF(DEBUG_STREAM, logger, buf) {			\
			jam(buf, SPACES "params: %d-bytes@%p",		\
			    params->len, params->data);			\
		}							\
	}

	if (DBGP(DBG_CRYPT)) {
		DBG_DERIVE();
	}

	PK11SymKey *target_key = PK11_DeriveWithFlags(base_key, derive,
						      params, target_mechanism,
						      operation, key_size, flags);

	if (target_key == NULL) {
		JAMBUF(buf) {
			jam_string(buf, "NSS: ");
			jam_nss_ckm(buf, derive);
			jam_string(buf, " failed: ");
			jam_nss_error(buf);
			/* XXX: hack - double copy */
			pexpect_fail(logger, HERE, PRI_SHUNK, pri_shunk(jambuf_as_shunk(buf)));
		}
		DBG_DERIVE();
	} else if (DBGP(DBG_REFCNT)) {
		LOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, SPACES"result: newref ");
			jam_symkey(buf, target_name, target_key);
			jam(buf, PRI_WHERE, pri_where(where));
		}
	}
	return target_key;
#undef DBG_DERIVE
}

/*
 * Merge a symkey and an array of bytes into a new SYMKEY using
 * DERIVE.
 *
 * derive: the operation that is to be performed; target: the
 * mechanism/type of the resulting symkey.
 */
static PK11SymKey *merge_symkey_bytes(const char *result_name,
				      PK11SymKey *base_key,
				      const void *data, size_t sizeof_data,
				      CK_MECHANISM_TYPE derive,
				      CK_MECHANISM_TYPE target,
				      struct logger *logger)
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

	return crypt_derive(base_key, derive, &data_param,
			    result_name, target,
			    operation, key_size, /*flags*/0,
			    HERE, logger);
}

/*
 * Merge two SYMKEYs into a new SYMKEY using DERIVE.
 *
 * derive: the operation to be performed; target: the mechanism/type
 * of the resulting symkey.
 */

static PK11SymKey *merge_symkey_symkey(const char *result_name,
				       PK11SymKey *base_key,
				       PK11SymKey *key,
				       CK_MECHANISM_TYPE derive,
				       CK_MECHANISM_TYPE target,
				       struct logger *logger)
{
	CK_OBJECT_HANDLE key_handle = PK11_GetSymKeyHandle(key);
	SECItem key_param = {
		.data = (unsigned char*)&key_handle,
		.len = sizeof(key_handle)
	};
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;
	return crypt_derive(base_key, derive, &key_param,
			    result_name, target,
			    operation, key_size, /*flags*/0,
			    HERE, logger);
}

/*
 * Extract a SYMKEY from an existing SYMKEY.
 */
static PK11SymKey *symkey_from_symkey(const char *result_name,
				      PK11SymKey *base_key,
				      CK_MECHANISM_TYPE target,
				      CK_FLAGS flags,
				      size_t key_offset, size_t key_size,
				      where_t where, struct logger *logger)
{
	/* spell out all the parameters */
	CK_EXTRACT_PARAMS bs = key_offset * BITS_PER_BYTE;
	SECItem param = {
		.data = (unsigned char*)&bs,
		.len = sizeof(bs),
	};
	CK_MECHANISM_TYPE derive = CKM_EXTRACT_KEY_FROM_KEY;
	CK_ATTRIBUTE_TYPE operation = CKA_FLAGS_ONLY;

	if (DBGP(DBG_CRYPT)) {
		DBG_log(SPACES "key-offset: %zd, key-size: %zd",
			key_offset, key_size);
	}

	return crypt_derive(base_key, derive, &param,
			    result_name, target,
			    operation, key_size, flags,
			    where, logger);
}


/*
 * For on-wire algorithms.
 */
chunk_t chunk_from_symkey(const char *name, PK11SymKey *symkey,
			  struct logger *logger)
{
	SECStatus status;
	if (symkey == NULL) {
		DBGF(DBG_CRYPT, "%s NULL key has no bytes", name);
		return EMPTY_CHUNK;
	}

	size_t sizeof_bytes = sizeof_symkey(symkey);
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s extracting all %zd bytes of key@%p",
			name, sizeof_bytes, symkey);
		DBG_symkey(logger, name, "symkey", symkey);
	}

	/* get a secret key */
	PK11SymKey *ephemeral_key = ephemeral_symkey;

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
		passert(slot_key != NULL);
	}
	if (DBGP(DBG_REFCNT)) {
	    if (slot_key == symkey) {
		    /* output should mimic reference_symkey() */
		    DBG_log("%s: slot-key@%p: addref sym-key@%p",
			    name, slot_key, symkey);
	    } else {
		    DBG_symkey(logger, name, "newref slot", slot_key);
	    }
	}

	SECItem wrapped_key;
	/* Round up the wrapped key length to a 16-byte boundary.  */
	wrapped_key.len = (sizeof_bytes + 15) & ~15;
	wrapped_key.data = alloc_bytes(wrapped_key.len, name);
	DBGF(DBG_CRYPT, "sizeof bytes %d", wrapped_key.len);
	status = PK11_WrapSymKey(CKM_AES_ECB, NULL, ephemeral_key, slot_key,
				 &wrapped_key);
	passert(status == SECSuccess);
	if (DBGP(DBG_CRYPT)) {
		LOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "wrapper: ");
			jam_nss_secitem(buf, &wrapped_key);
		}
	}

	void *bytes = alloc_bytes(wrapped_key.len, name);
	unsigned int out_len = 0;
	status = PK11_Decrypt(ephemeral_key, CKM_AES_ECB, NULL,
			      bytes, &out_len, wrapped_key.len,
			      wrapped_key.data, wrapped_key.len);
	pfreeany(wrapped_key.data);
	release_symkey(name, "slot-key", &slot_key);
	passert(status == SECSuccess);
	passert(out_len >= sizeof_bytes);

	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s extracted len %d bytes at %p", name, out_len, bytes);
		DBG_dump("unwrapped:", bytes, out_len);
	}

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

PK11SymKey *symkey_from_bytes(const char *name,
			      const uint8_t *bytes, size_t sizeof_bytes,
			      struct logger *logger)
{
	if (sizeof_bytes == 0) {
		/* hopefully caller knows what they are doing */
		return NULL;
	}

	PK11SymKey *scratch = ephemeral_symkey;
	PK11SymKey *tmp = merge_symkey_bytes(name, scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY,
					     logger);
	passert(tmp != NULL);
	/*
	 * Something of an old code hack.  Keys fed to the hasher, for
	 * instance, get this type.
	 */
	CK_FLAGS flags = 0;
	CK_MECHANISM_TYPE target = CKM_EXTRACT_KEY_FROM_KEY;
	PK11SymKey *key = symkey_from_symkey(name, tmp, target, flags,
					     0, sizeof_bytes, HERE, logger);
	passert(key != NULL);
	release_symkey(name, "tmp", &tmp);
	return key;
}

PK11SymKey *encrypt_key_from_bytes(const char *name,
				   const struct encrypt_desc *encrypt,
				   const uint8_t *bytes, size_t sizeof_bytes,
				   where_t where, struct logger *logger)
{
	PK11SymKey *scratch = ephemeral_symkey;
	PK11SymKey *tmp = merge_symkey_bytes(name, scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY,
					     logger);
	passert(tmp != NULL);
	PK11SymKey *key = encrypt_key_from_symkey_bytes(name, encrypt,
							0, sizeof_bytes,
							tmp, where, logger);
	passert(key != NULL);
	release_symkey(name, "tmp", &tmp);
	return key;
}

PK11SymKey *prf_key_from_bytes(const char *name, const struct prf_desc *prf,
			       const uint8_t *bytes, size_t sizeof_bytes,
			       where_t where, struct logger *logger)
{
	PK11SymKey *scratch = ephemeral_symkey;
	PK11SymKey *tmp = merge_symkey_bytes(name, scratch, bytes, sizeof_bytes,
					     CKM_CONCATENATE_DATA_AND_BASE,
					     CKM_EXTRACT_KEY_FROM_KEY,
					     logger);
	passert(tmp != NULL);
	PK11SymKey *key = prf_key_from_symkey_bytes(name, prf,
						    0, sizeof_bytes,
						    tmp, where, logger);
	passert(key != NULL);
	release_symkey(name, "tmp", &tmp);
	return key;
}

/*
 * Append new keying material to an existing key; replace the existing
 * key with the result.
 *
 * Use this to chain a series of concat operations.
 */

void append_symkey_symkey(PK11SymKey **lhs, PK11SymKey *rhs,
			  struct logger *logger)
{
	PK11SymKey *newkey = merge_symkey_symkey("result", *lhs, rhs,
						 CKM_CONCATENATE_BASE_AND_KEY,
						 PK11_GetMechanism(*lhs),
						 logger);
	release_symkey(__func__, "lhs", lhs);
	*lhs = newkey;
}

void append_symkey_bytes(const char *name,
			 PK11SymKey **lhs, const void *rhs,
			 size_t sizeof_rhs,
			 struct logger *logger)
{
	PK11SymKey *newkey = merge_symkey_bytes(name, *lhs, rhs, sizeof_rhs,
						CKM_CONCATENATE_BASE_AND_DATA,
						PK11_GetMechanism(*lhs),
						logger);
	release_symkey(__func__, "lhs", lhs);
	*lhs = newkey;
}

void prepend_bytes_to_symkey(const char *result,
			     const void *lhs, size_t sizeof_lhs,
			     PK11SymKey **rhs,
			     struct logger *logger)
{
	/* copy the existing KEY's type (mechanism).  */
	PK11SymKey *newkey = merge_symkey_bytes(result, *rhs, lhs, sizeof_lhs,
						CKM_CONCATENATE_DATA_AND_BASE,
						PK11_GetMechanism(*rhs),
						logger);
	release_symkey(__func__, "rhs", rhs);
	*rhs = newkey;
}

void append_symkey_byte(PK11SymKey **lhs, uint8_t rhs,
			struct logger *logger)
{
	append_symkey_bytes("result", lhs, &rhs, sizeof(rhs), logger);
}

void append_chunk_bytes(const char *name, chunk_t *lhs,
			const void *rhs, size_t sizeof_rhs)
{
	size_t len = lhs->len + sizeof_rhs;
	chunk_t new = alloc_chunk(len, name);
	memcpy(new.ptr, lhs->ptr, lhs->len);
	memcpy(new.ptr + lhs->len, rhs, sizeof_rhs);
	free_chunk_content(lhs);
	*lhs = new;
}

void append_chunk_symkey(const char *name, chunk_t *lhs, PK11SymKey *rhs,
			 struct logger *logger)
{
	chunk_t rhs_chunk = chunk_from_symkey(name, rhs, logger);
	chunk_t new = clone_chunk_chunk(*lhs, rhs_chunk, name);
	free_chunk_content(&rhs_chunk);
	free_chunk_content(lhs);
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
				      PK11SymKey *source_key,
				      where_t where, struct logger *logger)
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
				  symkey_start_byte, sizeof_symkey,
				  where, logger);
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
					  PK11SymKey *source_key,
					  where_t where, struct logger *logger)
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
				  symkey_start_byte, sizeof_symkey,
				  where, logger);
}

PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, size_t sizeof_key,
				  where_t where, struct logger *logger)
{
	if (sizeof_key == 0) {
		return NULL;
	} else {
		return symkey_from_symkey("result", source_key,
					  CKM_EXTRACT_KEY_FROM_KEY,
					  0, next_byte, sizeof_key,
					  where, logger);
	}
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
PK11SymKey *xor_symkey_chunk(PK11SymKey *lhs, chunk_t rhs, struct logger *logger)
{
	return merge_symkey_bytes("result", lhs, rhs.ptr, rhs.len,
				  CKM_XOR_BASE_AND_DATA,
				  CKM_CONCATENATE_BASE_AND_DATA,
				  logger);
}
