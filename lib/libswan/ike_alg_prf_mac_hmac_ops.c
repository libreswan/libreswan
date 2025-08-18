/*
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
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

#include <stdlib.h>

#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "crypt_hash.h"
#include "ike_alg_prf_mac_ops.h"

struct prf_context {
	const char *name;
	const struct prf_desc *desc;
	/* intermediate values */
	struct crypt_mac key;
	struct crypt_hash *inner;
	struct logger *logger;
};

/*
 * 2. Definition of HMAC
 *
 *   The definition of HMAC requires a cryptographic hash function,
 *   which we denote by H, and a secret key K. We assume H to be a
 *   cryptographic hash function where data is hashed by iterating a
 *   basic compression function on blocks of data.  We denote by B the
 *   byte-length of such blocks (B=64 for all the above mentioned
 *   examples of hash functions), and by L the byte-length of hash
 *   outputs (L=16 for MD5, L=20 for SHA-1).  The authentication key K
 *   can be of any length up to B, the block length of the hash
 *   function.  Applications that use keys longer than B bytes will
 *   first hash the key using H and then use the resultant L byte
 *   string as the actual key to HMAC. In any case the minimal
 *   recommended length for K is L bytes (as the hash output
 *   length). See section 3 for more information on keys.
 *
 * B=prf->hasher->hash_block_size
 * L=prf->hasher->hash_digest_size;
 */

static struct crypt_mac hmac_prf_key_from_bytes(const struct prf_desc *prf,
						const char *key_name, const void *key_ptr, size_t key_len,
						struct logger *logger)
{
	struct crypt_mac key = { .len = prf->hasher->hash_block_size, };
	PASSERT(logger, sizeof(key.ptr) <= prf->hasher->hash_block_size);

	if (key_len <= prf->hasher->hash_block_size) {
		/*
		 * If necessary, pad the key to size with zeroes
		 * (above zeroed entire key making it unnecessary).
		 */
		ldbgf(DBG_CRYPT, logger, "%s() key %s %zd<=%zd, padding with zeros",
		      __func__, key_name, key_len, prf->hasher->hash_block_size);
		memcpy(key.ptr/*array*/, key_ptr, key_len);
	} else {
		ldbgf(DBG_CRYPT, logger, "%s() key %s %zd>%zd is too big, rehashing to %zu size",
		      __func__, key_name, key_len,
		      prf->hasher->hash_block_size,
		      prf->hasher->hash_block_size);
		/*
		 * The key is too big, hash it down to digest size
		 * (leaving upto block size zero) using the HASH that
		 * the PRF's HMAC is built from.
		 */
		struct crypt_hash *hasher = crypt_hash_init("MAC(KEY)", prf->hasher, logger);
		crypt_hash_digest_bytes(hasher, "key", key_ptr, key_len);
		crypt_hash_final_bytes(&hasher, key.ptr/*array*/, prf->hasher->hash_digest_size);
	}

	return key;
}

/*
 * Create a PRF ready to consume data.
 */

static struct prf_context *prf_init(const struct prf_desc *prf_desc,
				    const char *name, struct logger *logger)
{
	struct prf_context prf = {
		.name = name,
		.desc = prf_desc,
		.logger = logger,
	};
	return clone_thing(prf, name);
}

static struct prf_context *init_bytes(const struct prf_desc *prf_desc,
				      const char *name,
				      const char *key_name,
				      const uint8_t *key_ptr, size_t key_len,
				      struct logger *logger)
{
	struct prf_context *prf = prf_init(prf_desc, name, logger);

	/*
	 *    (1) append zeros to the end of K to create a B byte string
	 *        (e.g., if K is of length 20 bytes and B=64, then K will be
	 *         appended with 44 zero bytes 0x00)
	 */
	prf->key = hmac_prf_key_from_bytes(prf->desc,
					   key_name, key_ptr, key_len,
					   prf->logger);
	passert(prf->key.len == prf->desc->hasher->hash_block_size);

	/*
	 * Prepare for update phase (accumulate seed material).
	 */
	prf->inner = crypt_hash_init("HMAC-inner", prf->desc->hasher, prf->logger);
	/*
	 *    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
	 *        (1) with ipad
	 */
	struct crypt_mac ipad = { .len = prf->key.len, };
	for (unsigned i = 0; i < prf->key.len; i++) {
		ipad.ptr[i] = prf->key.ptr[i] ^ HMAC_IPAD;
	}
	crypt_hash_digest_hunk(prf->inner, "key^IPAD", ipad);
	return prf;
}

static struct prf_context *init_symkey(const struct prf_desc *prf_desc,
				       const char *name,
				       const char *key_name, PK11SymKey *key,
				       struct logger *logger)
{
	/* Don't assume the key is the correct size. */
	chunk_t raw_key = chunk_from_symkey(key_name, key, logger);
	struct prf_context *prf = init_bytes(prf_desc, name, key_name, raw_key.ptr, raw_key.len, logger);
	free_chunk_content(&raw_key);
	return prf;
}

/*
 *    (3) append the stream of data 'text' to the B byte string resulting
 *        from step (2)
 */

static void digest_symkey(struct prf_context *prf,
			  const char *name,
			  PK11SymKey *symkey)
{
	passert(digest_symkey == prf->desc->prf_mac_ops->digest_symkey);
	crypt_hash_digest_symkey(prf->inner, name, symkey);
}

static void digest_bytes(struct prf_context *prf, const char *name,
			 const uint8_t *bytes, size_t sizeof_bytes)
{
	passert(digest_bytes == prf->desc->prf_mac_ops->digest_bytes);
	crypt_hash_digest_bytes(prf->inner, name, bytes, sizeof_bytes);
}

/*
 * Finally.
 */

static struct crypt_hash *compute_outer(struct prf_context *prf)
{
	passert(prf->inner != NULL);
	/*
	 *    (4) apply H to the stream generated in step (3)
	 */
	struct crypt_mac hashed_inner = crypt_hash_final_mac(&prf->inner);

	/*
	 *    (5) XOR (bitwise exclusive-OR) the B byte string computed in
	 *        step (1) with opad
	 */
	struct crypt_mac opad = { .len = prf->key.len, };
	for (unsigned i = 0; i < prf->key.len; i++) {
		opad.ptr[i] = prf->key.ptr[i] ^ HMAC_OPAD;
	}

	/*
	 *    (6) append the H result from step (4) to the B byte string
	 *        resulting from step (5)
	 */
	struct crypt_hash *outer = crypt_hash_init("outer", prf->desc->hasher,
						   prf->logger);
	crypt_hash_digest_hunk(outer, "key^OPAD", opad);
	crypt_hash_digest_hunk(outer, "inner", hashed_inner);
	return outer;
}

static PK11SymKey *final_symkey(struct prf_context **prfp)
{
	passert(final_symkey == (*prfp)->desc->prf_mac_ops->final_symkey);
	struct crypt_hash *outer = compute_outer(*prfp);
	/*
	 *    (7) apply H to the stream generated in step (6) and output
	 *        the result
	 */
	struct crypt_mac outer_mac = crypt_hash_final_mac(&outer);
	if (LDBGP(DBG_CRYPT, (*prfp)->logger)) {
		LDBG_log((*prfp)->logger, " hashed-outer");
		LDBG_hunk((*prfp)->logger, outer_mac);
	}
	PK11SymKey *hmac = symkey_from_hunk("HMAC", outer_mac, (*prfp)->logger);
	pfreeany(*prfp);
	return hmac;
}

static void final_bytes(struct prf_context **prfp,
			uint8_t *bytes, size_t sizeof_bytes)
{
	passert(final_bytes == (*prfp)->desc->prf_mac_ops->final_bytes);
	struct crypt_hash *outer = compute_outer(*prfp);
	/*
	 *    (7) apply H to the stream generated in step (6) and output
	 *        the result
	 */
	crypt_hash_final_bytes(&outer, bytes, sizeof_bytes);
	if (LDBGP(DBG_CRYPT, (*prfp)->logger)) {
		LDBG_log((*prfp)->logger, " hashed-outer");
		LDBG_dump((*prfp)->logger, bytes, sizeof_bytes);
	}
	pfreeany(*prfp);
}

static void hmac_prf_check(const struct prf_desc *prf, struct logger *logger)
{
	const struct ike_alg *alg = &prf->common;
	pexpect_ike_alg(logger, alg, prf->hasher != NULL);
}

const struct prf_mac_ops ike_alg_prf_mac_hmac_ops = {
	"native(HMAC)",
	hmac_prf_check,
	init_symkey,
	init_bytes,
	digest_symkey,
	digest_bytes,
	final_symkey,
	final_bytes,
};
