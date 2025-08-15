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
#include "fips_mode.h"
#include "lswnss.h"
#include "ike_alg_encrypt.h"		/* for ike_alg_encrypt_null */

#define SPACES "    "

static PK11SymKey *ephemeral_symkey;

void init_crypt_symkey(struct logger *logger)
{
	/* get a secret key */
	PK11SlotInfo *slot = PK11_GetBestSlot(CKM_AES_KEY_GEN,
					      lsw_nss_get_password_context(logger));
	if (slot == NULL) {
		LLOG_FATAL_JAMBUF(PLUTO_EXIT_FAIL, logger, buf) {
			jam(buf, "NSS: ephemeral slot error: ");
			jam_nss_error_code(buf, PR_GetError());
		}
	}
	ephemeral_symkey = PK11_KeyGen(slot, CKM_AES_KEY_GEN,
				       NULL, 128/8, NULL);
	PK11_FreeSlot(slot); /* reference counted */
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_symkey(logger, SPACES, "ephemeral", ephemeral_symkey);
	}
}

void symkey_delref_where(const struct logger *logger, const char *name,
			 PK11SymKey **key, where_t where)
{
	ldbg_delref_where(logger, name, (*key), where);
	if (*key != NULL) {
		PK11_FreeSymKey(*key);
	}
	*key = NULL;
}

PK11SymKey *symkey_addref_where(struct logger *logger, const char *name,
				PK11SymKey *key, where_t where)
{
	ldbg_addref_where(logger, name, key, where);
	if (key != NULL) {
		PK11_ReferenceSymKey(key);
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

void LDBG_symkey(struct logger *logger, const char *prefix, const char *name, PK11SymKey *key)
{
	LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
		jam(buf, "%s: ", prefix);
		jam_symkey(buf, name, key);
	}
#if 0
	if (LDBGP(DBG_CRYPT, logger)) {
		if (is_fips_mode()) {
			LDBG_log(logger, "%s secured by FIPS", prefix);
		} else {
			chunk_t bytes = chunk_from_symkey(prefix, key, logger);
			/* NULL suppresses the dump header */
			LDBG_hunk(logger, bytes);
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
	LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {			\
		jam_nss_ckm(buf, derive);				\
		jam_string(buf, ":");					\
	}								\
	LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {			\
		jam_string(buf, SPACES"target: ");			\
		jam_nss_ckm(buf, target_mechanism);			\
	}								\
	if (flags != 0) {						\
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {		\
			jam_string(buf, SPACES"flags: ");		\
			jam_nss_ckf(buf, flags);			\
		}							\
	}								\
	if (key_size != 0) {						\
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {		\
			jam(buf, SPACES "key_size: %d-bytes",		\
			    key_size);					\
		}							\
	}								\
	LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {			\
		jam_string(buf, SPACES"base: ");			\
		jam_symkey(buf, "base", base_key);			\
	}								\
	if (operation != CKA_DERIVE) {					\
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {		\
			jam_string(buf, SPACES"operation: ");		\
			jam_nss_cka(buf, operation);			\
		}							\
	}								\
	if (params != NULL) {						\
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {		\
			jam(buf, SPACES "params: %d-bytes@%p",		\
			    params->len, params->data);			\
		}							\
	}

	if (LDBGP(DBG_CRYPT, logger)) {
		DBG_DERIVE();
	}

	PK11SymKey *target_key = PK11_DeriveWithFlags(base_key, derive,
						      params, target_mechanism,
						      operation, key_size, flags);

	if (target_key == NULL) {
		LLOG_PEXPECT_JAMBUF(logger, HERE, buf) {
			jam_string(buf, "NSS: ");
			jam_nss_ckm(buf, derive);
			jam_string(buf, " failed: ");
			jam_nss_error_code(buf, PR_GetError());
		}
		DBG_DERIVE();
	} else if (LDBGP(DBG_REFCNT, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, SPACES"result: newref ");
			jam_symkey(buf, target_name, target_key);
			jam_where(buf, where);
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
	CK_EXTRACT_PARAMS bs = key_offset * BITS_IN_BYTE;
	SECItem param = {
		.data = (unsigned char*)&bs,
		.len = sizeof(bs),
	};
	CK_MECHANISM_TYPE derive = CKM_EXTRACT_KEY_FROM_KEY;
	CK_ATTRIBUTE_TYPE operation = CKA_FLAGS_ONLY;

	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, SPACES "key-offset: %zd, key-size: %zd",
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
		ldbgf(DBG_CRYPT, logger,
		      "%s NULL key has no bytes", name);
		return EMPTY_CHUNK;
	}

	size_t sizeof_bytes = sizeof_symkey(symkey);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s extracting all %zd bytes of key@%p",
			 name, sizeof_bytes, symkey);
		LDBG_symkey(logger, name, "symkey", symkey);
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
	if (LDBGP(DBG_REFCNT, logger)) {
	    if (slot_key == symkey) {
		    /* output should mimic symkey_addref() */
		    LDBG_log(logger, "%s: slot-key@%p: addref sym-key@%p",
			     name, slot_key, symkey);
	    } else {
		    LDBG_symkey(logger, name, "newref slot", slot_key);
	    }
	}

	SECItem wrapped_key;
	/* Round up the wrapped key length to a 16-byte boundary. */
	wrapped_key.len = (sizeof_bytes + 15) & ~15;
	wrapped_key.data = alloc_bytes(wrapped_key.len, name);
	ldbgf(DBG_CRYPT, logger, "sizeof bytes %d", wrapped_key.len);
	status = PK11_WrapSymKey(CKM_AES_ECB, NULL, ephemeral_key, slot_key,
				 &wrapped_key);
	passert(status == SECSuccess);
	if (LDBGP(DBG_CRYPT, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
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
	symkey_delref(logger, "slot-key", &slot_key);
	passert(status == SECSuccess);
	passert(out_len >= sizeof_bytes);

	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s extracted len %d bytes at %p; unwrapped", name, out_len, bytes);
		LDBG_dump(logger, bytes, out_len);
	}

	return (chunk_t) {
		.ptr = bytes,
		.len = sizeof_bytes,
	};
}

chunk_t chunk_from_symkey_bytes(const char *prefix, PK11SymKey *symkey,
				size_t chunk_start, size_t sizeof_chunk,
				struct logger *logger, where_t where)
{
	PK11SymKey *slice = key_from_symkey_bytes(prefix, symkey,
						  chunk_start, sizeof_chunk,
						  where, logger);
	chunk_t chunk = chunk_from_symkey("initiator salt", slice, logger);
	symkey_delref(logger, "slice", &slice);
	return chunk;
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
	symkey_delref(logger, "tmp", &tmp);
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
	symkey_delref(logger, "tmp", &tmp);
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
	symkey_delref(logger, "tmp", &tmp);
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
	symkey_delref(logger, "lhs", lhs);
	*lhs = newkey;
}

void append_symkey_bytes(const char *name,
			 PK11SymKey **lhs, const void *rhs,
			 size_t sizeof_rhs,
			 struct logger *logger)
{
	if (sizeof_rhs == 0) {
		/* no change required; stops nss crash */
		return;
	}

	PK11SymKey *newkey = merge_symkey_bytes(name, *lhs, rhs, sizeof_rhs,
						CKM_CONCATENATE_BASE_AND_DATA,
						PK11_GetMechanism(*lhs),
						logger);
	symkey_delref(logger, "lhs", lhs);
	*lhs = newkey;
}

void prepend_bytes_to_symkey(const char *result,
			     const void *lhs, size_t sizeof_lhs,
			     PK11SymKey **rhs,
			     struct logger *logger)
{
	/* copy the existing KEY's type (mechanism). */
	PK11SymKey *newkey = merge_symkey_bytes(result, *rhs, lhs, sizeof_lhs,
						CKM_CONCATENATE_DATA_AND_BASE,
						PK11_GetMechanism(*rhs),
						logger);
	symkey_delref(logger, "rhs", rhs);
	*rhs = newkey;
}

void append_symkey_byte(PK11SymKey **lhs, uint8_t rhs,
			struct logger *logger)
{
	append_symkey_bytes("result", lhs, &rhs, sizeof(rhs), logger);
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
	 * NSS throws a hissy fit when asked to extract 0 bytes.
	 */
	if (sizeof_symkey == 0) {
		PASSERT(logger, encrypt == &ike_alg_encrypt_null);
		PASSERT(logger, impair.allow_null_none);
		return NULL;
	}
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

PK11SymKey *key_from_symkey_bytes(const char *result_name,
				  PK11SymKey *source_key,
				  size_t next_byte, size_t sizeof_key,
				  where_t where, struct logger *logger)
{
	if (sizeof_key == 0) {
		return NULL;
	} else {
		return symkey_from_symkey(result_name, source_key,
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
 * hasher-to-ckm mapped hasher->common.alg_id to CMK vis: OAKLEY_MD5 ->
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

PK11SymKey *cipher_symkey(const char *name,
			  const struct encrypt_desc *cipher,
			  unsigned bits,
			  struct logger *logger,
			  where_t where)
{
	bool valid_key_length = false;
	FOR_EACH_ELEMENT(key, cipher->key_bit_lengths) {
		if (*key == bits) {
			valid_key_length = true;
			break;
		}
	}
	PASSERT(logger, valid_key_length);
	PASSERT(logger, cipher->nss.key_gen != 0);

	PK11SlotInfo *slot = PK11_GetBestSlot(cipher->nss.key_gen,
					      lsw_nss_get_password_context(logger));
	PK11SymKey *symkey = PK11_KeyGen(slot, cipher->nss.key_gen,
					 /*param*/NULL, BYTES_FOR_BITS(bits),
					 /*wincx*/NULL);

	ldbg_alloc(logger, name, symkey, where);
	return symkey;
}
