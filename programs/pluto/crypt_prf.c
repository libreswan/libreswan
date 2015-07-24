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
#include "crypt_symkey.h"
#include "crypt_dbg.h"
#include "crypto.h"

struct crypt_prf {
	const char *name;
	const struct hash_desc *hasher;
	/* for converting chunks to symkeys */
	PK11SymKey *scratch;
	/* Did we allocate KEY? */
	bool we_own_key;
	/* intermediate values */
	PK11SymKey *key;
	PK11SymKey *inner;
};

/*
 * During the init phase, accumulate the key material in KEY.
 */
struct crypt_prf *crypt_prf_init(const char *name, const struct hash_desc *hasher,
				 PK11SymKey *scratch)
{
	struct crypt_prf *prf = alloc_bytes(sizeof(struct crypt_prf), name);
	DBG(DBG_CRYPT, DBG_log("%s prf: init %p", name, prf));
	prf->name = name;
	prf->hasher = hasher;
	prf->scratch = scratch;
	prf->we_own_key = FALSE;
	prf->key = NULL;
	prf->inner = NULL;
	return prf;
}

/*
 * Update KEY marking it as ours.  Only call with a KEY we created.
 */
static void update_key(struct crypt_prf *prf, PK11SymKey *key)
{
	if (prf->we_own_key) {
		free_any_symkey(__func__, &prf->key);
	}
	prf->we_own_key = TRUE;
	prf->key = key;
}

void crypt_prf_init_symkey(const char *name, struct crypt_prf *prf, PK11SymKey *key)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: init symkey %s %p (length %d)",
			       prf->name, name, key, PK11_GetKeyLength(key)));
	if (prf->key == NULL) {
		prf->we_own_key = FALSE;
		prf->key = key;
	} else {
		update_key(prf, concat_symkey_symkey(prf->hasher, prf->key, key));
	}
}

void crypt_prf_init_chunk(const char *name, struct crypt_prf *prf, chunk_t key)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: init chunk %s %p (length %zd)",
			       prf->name, name, key.ptr, key.len));
	if (prf->key == NULL) {
		prf->key = symkey_from_chunk(prf->scratch, key);
		prf->we_own_key = TRUE;
	} else {
		update_key(prf, concat_symkey_chunk(prf->hasher, prf->key, key));
	}
}

/*
 * Prepare for update phase (accumulate seed material).
 */
void crypt_prf_update(struct crypt_prf *prf)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: update", prf->name));
	/* create the prf key from KEY.  */
	passert(prf->key != NULL);

	passert(prf->hasher->hash_block_size <= MAX_HMAC_BLOCKSIZE);

	/* If the key is too big, re-hash it down to size. */
	if (PK11_GetKeyLength(prf->key) > prf->hasher->hash_block_size) {
		update_key(prf, hash_symkey_to_symkey("prf hash to size:",
						      prf->hasher, prf->key));
	}

	/* If the key is too small, pad it. */
	if (PK11_GetKeyLength(prf->key) < prf->hasher->hash_block_size) {
		/* pad it to block_size. */
		static /*const*/ unsigned char z[MAX_HMAC_BLOCKSIZE] = { 0 };
		chunk_t hmac_pad_prf = { z,
			prf->hasher->hash_block_size - PK11_GetKeyLength(prf->key) };

		update_key(prf, concat_symkey_chunk(prf->hasher, prf->key,
						    hmac_pad_prf));
	}
	passert(prf->key != NULL);

	/* Start forming the inner hash input: (key^IPAD)|... */
	passert(prf->inner == NULL);
	unsigned char ip[MAX_HMAC_BLOCKSIZE];
	memset(ip, HMAC_IPAD, prf->hasher->hash_block_size);
	chunk_t hmac_ipad = { ip, prf->hasher->hash_block_size };
	prf->inner = xor_symkey_chunk(prf->key, hmac_ipad);
}

void crypt_prf_update_chunk(const char *name, struct crypt_prf *prf,
			    chunk_t update)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: update chunk %s %p (length %zd)",
			       prf->name, name, update.ptr, update.len));
	append_symkey_chunk(prf->hasher, &(prf->inner), update);
}

void crypt_prf_update_symkey(const char *name, struct crypt_prf *prf,
			     PK11SymKey *update)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: update symkey %s %p (length %d)",
			       prf->name, name, update,
			       PK11_GetKeyLength(update)));
	append_symkey_symkey(prf->hasher, &(prf->inner), update);
}

void crypt_prf_update_byte(const char *name, struct crypt_prf *prf,
			   uint8_t update)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: update byte %s", prf->name, name));
	append_symkey_byte(prf->hasher, &(prf->inner), update);
}

void crypt_prf_update_bytes(const char *name, struct crypt_prf *prf,
			    const void *update, size_t sizeof_update)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: update bytes %s %p (length %zd)",
			       prf->name, name, update, sizeof_update));
	append_symkey_bytes(prf->hasher, &(prf->inner), update, sizeof_update);
}

static PK11SymKey *compute_outer(struct crypt_prf *prf)
{
	DBG(DBG_CRYPT, DBG_log("%s prf: final", prf->name));

	passert(prf->inner != NULL);
	/* run that through hasher */
	PK11SymKey *hashed_inner = hash_symkey_to_symkey("prf inner hash:",
							 prf->hasher, prf->inner);
	free_any_symkey("prf inner:", &prf->inner);

	/* Input to outer hash: (key^OPAD)|hashed_inner.  */
	passert(prf->hasher->hash_block_size <= MAX_HMAC_BLOCKSIZE);
	unsigned char op[MAX_HMAC_BLOCKSIZE];
	memset(op, HMAC_OPAD, prf->hasher->hash_block_size);
	chunk_t hmac_opad = { op, prf->hasher->hash_block_size };
	PK11SymKey *outer = xor_symkey_chunk(prf->key, hmac_opad);
	append_symkey_symkey(prf->hasher, &outer, hashed_inner);
	free_any_symkey("prf hashed inner:", &hashed_inner);
	if (prf->we_own_key) {
		free_any_symkey("prf key", &prf->key);
	}

	return outer;
}

PK11SymKey *crypt_prf_final(struct crypt_prf *prf)
{
	PK11SymKey *outer = compute_outer(prf);
	/* Finally hash that */
	PK11SymKey *hashed_outer = hash_symkey_to_symkey("prf outer hash",
							 prf->hasher, outer);
	free_any_symkey("prf outer", &outer);
	pfree(prf);
	DBG(DBG_CRYPT, DBG_dump_symkey("prf final result", hashed_outer));
	return hashed_outer;
}

void crypt_prf_final_bytes(struct crypt_prf *prf,
			   void *bytes, size_t sizeof_bytes)
{
	PK11SymKey *outer = compute_outer(prf);
	/* Finally hash that */
	hash_symkey_to_bytes("prf outer hash", prf->hasher, outer, bytes, sizeof_bytes);
	free_any_symkey("prf outer", &outer);
	pfree(prf);
	DBG(DBG_CRYPT, DBG_dump("prf final bytes", bytes, sizeof_bytes));
}
