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
	PK11SymKey *key;
	PK11SymKey *inner;
	struct logger *logger;
};

static void prf_update(struct prf_context *prf);

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
				      const char *key_name UNUSED,
				      const uint8_t *key, size_t sizeof_key,
				      struct logger *logger)
{
	struct prf_context *prf = prf_init(prf_desc, name, logger);
	/* XXX: use an untyped key */
	prf->key = symkey_from_bytes(name, key, sizeof_key, prf->logger);
	prf_update(prf);
	return prf;
}

static struct prf_context *init_symkey(const struct prf_desc *prf_desc,
				       const char *name,
				       const char *key_name UNUSED, PK11SymKey *key,
				       struct logger *logger)
{
	struct prf_context *prf = prf_init(prf_desc, name, logger);
	prf->key = symkey_addref(prf->logger, name, key);
	prf_update(prf);
	return prf;
}

/*
 * Prepare for update phase (accumulate seed material).
 */
static void prf_update(struct prf_context *prf)
{
	/* create the prf key from KEY. */
	passert(prf->key != NULL);

	passert(prf->desc->hasher->hash_block_size <= MAX_HMAC_BLOCKSIZE);

	if (sizeof_symkey(prf->key) > prf->desc->hasher->hash_block_size) {
		/*
		 * The key is too big, hash it down to size using the
		 * HASH that the PRF's HMAC is built from.
		 */
		PK11SymKey *new = crypt_hash_symkey("prf hash to size:",
						    prf->desc->hasher,
						    "raw key", prf->key,
						    prf->logger);
		symkey_delref(prf->logger, "key", &prf->key);
		prf->key = new;
	} else if (sizeof_symkey(prf->key) < prf->desc->hasher->hash_block_size) {
		/*
		 * The key is too small, pad it with zeros to block
		 * size.
		 */
		static /*const*/ unsigned char z[MAX_HMAC_BLOCKSIZE] = { 0 };
		append_symkey_bytes("trimmed key", &prf->key, z,
				    prf->desc->hasher->hash_block_size - sizeof_symkey(prf->key),
				    prf->logger);
	}
	passert(prf->key != NULL);

	/* Start forming the inner hash input: (key^IPAD)|... */
	passert(prf->inner == NULL);
	unsigned char ip[MAX_HMAC_BLOCKSIZE];
	memset(ip, HMAC_IPAD, prf->desc->hasher->hash_block_size);
	chunk_t hmac_ipad = { ip, prf->desc->hasher->hash_block_size };
	prf->inner = xor_symkey_chunk(prf->key, hmac_ipad, prf->logger);
}

/*
 * Accumulate data.
 */

static void digest_symkey(struct prf_context *prf, const char *name UNUSED,
			  PK11SymKey *update)
{
	passert(digest_symkey == prf->desc->prf_mac_ops->digest_symkey);
	append_symkey_symkey(&(prf->inner), update, prf->logger);
}

static void digest_bytes(struct prf_context *prf, const char *name,
			 const uint8_t *bytes, size_t sizeof_bytes)
{
	passert(digest_bytes == prf->desc->prf_mac_ops->digest_bytes);
	append_symkey_bytes(name, &(prf->inner), bytes, sizeof_bytes,
			    prf->logger);
}

/*
 * Finally.
 */

static PK11SymKey *compute_outer(struct prf_context *prf)
{
	passert(prf->inner != NULL);
	/* run that through hasher */
	PK11SymKey *hashed_inner = crypt_hash_symkey("PRF HMAC inner hash",
						     prf->desc->hasher,
						     "inner", prf->inner,
						     prf->logger);
	symkey_delref(prf->logger, "inner", &prf->inner);

	/* Input to outer hash: (key^OPAD)|hashed_inner. */
	passert(prf->desc->hasher->hash_block_size <= MAX_HMAC_BLOCKSIZE);
	unsigned char op[MAX_HMAC_BLOCKSIZE];
	memset(op, HMAC_OPAD, prf->desc->hasher->hash_block_size);
	chunk_t hmac_opad = { op, prf->desc->hasher->hash_block_size };
	PK11SymKey *outer = xor_symkey_chunk(prf->key, hmac_opad, prf->logger);
	append_symkey_symkey(&outer, hashed_inner, prf->logger);
	symkey_delref(prf->logger, "hashed-inner", &hashed_inner);
	symkey_delref(prf->logger, "key", &prf->key);

	return outer;
}

static PK11SymKey *final_symkey(struct prf_context **prfp)
{
	passert(final_symkey == (*prfp)->desc->prf_mac_ops->final_symkey);
	PK11SymKey *outer = compute_outer(*prfp);
	/* Finally hash that */
	PK11SymKey *hashed_outer = crypt_hash_symkey("PRF HMAC outer hash",
						     (*prfp)->desc->hasher,
						     "outer", outer,
						     (*prfp)->logger);
	symkey_delref((*prfp)->logger, "outer", &outer);
	if (LDBGP(DBG_CRYPT, (*prfp)->logger)) {
		LDBG_symkey((*prfp)->logger, "    ", " hashed-outer", hashed_outer);
	}
	pfree(*prfp);
	*prfp = NULL;
	return hashed_outer;
}

static void final_bytes(struct prf_context **prfp,
			uint8_t *bytes, size_t sizeof_bytes)
{
	passert(final_bytes == (*prfp)->desc->prf_mac_ops->final_bytes);
	PK11SymKey *outer = compute_outer(*prfp);
	/* Finally hash that */
	struct crypt_hash *hash = crypt_hash_init("PRF HMAC outer hash",
						  (*prfp)->desc->hasher,
						  (*prfp)->logger);
	crypt_hash_digest_symkey(hash, "outer", outer);
	crypt_hash_final_bytes(&hash, bytes, sizeof_bytes);
	symkey_delref((*prfp)->logger, "outer", &outer);
	pfree(*prfp);
	*prfp = NULL;
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
