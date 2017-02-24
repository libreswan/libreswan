/*
 * Copyright (C) 2016-2017 Andrew Cagney <cagney@gnu.org>
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

#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "crypto.h"
#include "crypt_hash.h"

struct prf_context {
	const char *name;
	lset_t debug;
	const struct prf_desc *desc;
	/* Did we allocate KEY? */
	bool we_own_key;
	/* intermediate values */
	PK11SymKey *key;
	PK11SymKey *inner;
};

static void prf_update(struct prf_context *prf);

/*
 * Update KEY marking it as ours.  Only call with a KEY we created.
 */
static void update_key(struct prf_context *prf, PK11SymKey *key)
{
	if (prf->we_own_key) {
		release_symkey(prf->name, "(we-own)key", &prf->key);
	}
	prf->we_own_key = TRUE;
	prf->key = key;
}

/*
 * Create a PRF ready to consume data.
 */

static struct prf_context *prf_init(const struct prf_desc *prf_desc,
				    const char *name, lset_t debug)
{
	struct prf_context *prf = alloc_thing(struct prf_context, name);
	DBG(DBG_CRYPT, DBG_log("%s prf %s: init %p",
			       name, prf_desc->common.name, prf));
	*prf = (struct prf_context) {
		.debug = debug,
		.name = name,
		.desc = prf_desc,
	};
	return prf;
}

static struct prf_context *init_bytes(const struct prf_desc *prf_desc,
				      const char *name, lset_t debug,
				      const char *key_name,
				      const u_int8_t *key, size_t sizeof_key)
{
	struct prf_context *prf = prf_init(prf_desc, name, debug);
	DBG(debug, DBG_log("%s prf: init %s-bytes@%p (length %zd)",
			   name, key_name, key, sizeof_key));
	/* XXX: use an untyped key */
	prf->key = symkey_from_bytes(name, debug, NULL, key, sizeof_key);
	prf->we_own_key = TRUE;
	prf_update(prf);
	return prf;
}


static struct prf_context *init_symkey(const struct prf_desc *prf_desc,
				       const char *name, lset_t debug,
				       const char *key_name, PK11SymKey *key)
{
	struct prf_context *prf = prf_init(prf_desc, name, debug);
	DBG(debug, DBG_log("%s prf: init %s-key@%p (size %zd)",
			   prf->name, key_name, key, sizeof_symkey(key)));
	prf->we_own_key = FALSE;
	prf->key = key;
	prf_update(prf);
	return prf;
}

/*
 * Prepare for update phase (accumulate seed material).
 */
static void prf_update(struct prf_context *prf)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: update", prf->name));
	/* create the prf key from KEY.  */
	passert(prf->key != NULL);

	passert(prf->desc->hasher->hash_block_size <= MAX_HMAC_BLOCKSIZE);

	/* If the key is too big, re-hash it down to size. */
	if (sizeof_symkey(prf->key) > prf->desc->hasher->hash_block_size) {
		update_key(prf, crypt_hash_symkey(prf->desc->hasher,
						  "prf hash to size:", DBG_CRYPT,
						  "raw key", prf->key));
	}

	/* If the key is too small, pad it. */
	if (sizeof_symkey(prf->key) < prf->desc->hasher->hash_block_size) {
		/* pad it to block_size. */
		static /*const*/ unsigned char z[MAX_HMAC_BLOCKSIZE] = { 0 };
		chunk_t hmac_pad_prf = { z,
					 prf->desc->hasher->hash_block_size - sizeof_symkey(prf->key) };

		update_key(prf, concat_symkey_chunk(prf->desc->hasher, prf->key,
						    hmac_pad_prf));
	}
	passert(prf->key != NULL);

	/* Start forming the inner hash input: (key^IPAD)|... */
	passert(prf->inner == NULL);
	unsigned char ip[MAX_HMAC_BLOCKSIZE];
	memset(ip, HMAC_IPAD, prf->desc->hasher->hash_block_size);
	chunk_t hmac_ipad = { ip, prf->desc->hasher->hash_block_size };
	prf->inner = xor_symkey_chunk(prf->key, hmac_ipad);
}

/*
 * Accumulate data.
 */

static void digest_symkey(struct prf_context *prf,
			  const char *name, PK11SymKey *update)
{
	passert(digest_symkey == prf->desc->prf_ops->digest_symkey);
	DBG(DBG_CRYPT, DBG_log("%s prf: update %s-key@%p (size %zd)",
			       prf->name, name, update,
			       sizeof_symkey(update)));
	append_symkey_symkey(prf->desc->hasher, &(prf->inner), update);
}

static void digest_bytes(struct prf_context *prf, const char *name,
			 const u_int8_t *bytes, size_t sizeof_bytes)
{
	passert(digest_bytes == prf->desc->prf_ops->digest_bytes);
	DBG(DBG_CRYPT, DBG_log("%s prf: update %s-bytes@%p (length %zd)",
			       prf->name, name, bytes, sizeof_bytes));
	append_symkey_bytes(prf->desc->hasher, &(prf->inner), bytes, sizeof_bytes);
}

/*
 * Finally.
 */

static PK11SymKey *compute_outer(struct prf_context *prf)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: final", prf->name));

	passert(prf->inner != NULL);
	/* run that through hasher */
	PK11SymKey *hashed_inner = crypt_hash_symkey(prf->desc->hasher,
						     "prf inner hash:", DBG_CRYPT,
						     "inner", prf->inner);
	release_symkey(prf->name, "inner", &prf->inner);

	/* Input to outer hash: (key^OPAD)|hashed_inner.  */
	passert(prf->desc->hasher->hash_block_size <= MAX_HMAC_BLOCKSIZE);
	unsigned char op[MAX_HMAC_BLOCKSIZE];
	memset(op, HMAC_OPAD, prf->desc->hasher->hash_block_size);
	chunk_t hmac_opad = { op, prf->desc->hasher->hash_block_size };
	PK11SymKey *outer = xor_symkey_chunk(prf->key, hmac_opad);
	append_symkey_symkey(prf->desc->hasher, &outer, hashed_inner);
	release_symkey(prf->name, "hashed-inner", &hashed_inner);
	if (prf->we_own_key) {
		release_symkey(prf->name, "(we-own)key", &prf->key);
	}

	return outer;
}

static PK11SymKey *final_symkey(struct prf_context **prfp)
{
	passert(final_symkey == (*prfp)->desc->prf_ops->final_symkey);
	PK11SymKey *outer = compute_outer(*prfp);
	/* Finally hash that */
	PK11SymKey *hashed_outer = crypt_hash_symkey((*prfp)->desc->hasher,
						     "prf outer hash", DBG_CRYPT,
						     "outer", outer);
	release_symkey((*prfp)->name, "outer", &outer);
	DBG(DBG_CRYPT, DBG_symkey((*prfp)->name, "hashed-outer", hashed_outer));
	pfree(*prfp);
	*prfp = NULL;
	return hashed_outer;
}

static void final_bytes(struct prf_context **prfp,
			u_int8_t *bytes, size_t sizeof_bytes)
{
	passert(final_bytes == (*prfp)->desc->prf_ops->final_bytes);
	PK11SymKey *outer = compute_outer(*prfp);
	/* Finally hash that */
	struct crypt_hash *hash = crypt_hash_init((*prfp)->desc->hasher,
						  "prf outer hash",
						  (*prfp)->debug);
	crypt_hash_digest_symkey(hash, "outer", outer);
	crypt_hash_final_bytes(&hash, bytes, sizeof_bytes);
	release_symkey((*prfp)->name, "outer", &outer);
	DBG(DBG_CRYPT, DBG_dump("prf final bytes", bytes, sizeof_bytes));
	pfree(*prfp);
	*prfp = NULL;
}

const struct prf_ops ike_alg_hmac_prf_ops = {
	init_symkey,
	init_bytes,
	digest_symkey,
	digest_bytes,
	final_symkey,
	final_bytes,
};
