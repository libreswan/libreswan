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
#include "crypto.h"

struct crypt_prf {
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
struct crypt_prf *crypt_prf_init(const struct hash_desc *hasher,
				 PK11SymKey *scratch)
{
	struct crypt_prf *prf = alloc_bytes(sizeof(struct crypt_prf), "crypt_prf");
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
		PK11_FreeSymKey(prf->key);
	}
	prf->we_own_key = TRUE;
	prf->key = key;
}

void crypt_prf_init_symkey(struct crypt_prf *prf, PK11SymKey *key)
{
	if (prf->key == NULL) {
		prf->we_own_key = FALSE;
		prf->key = key;
	} else {
		update_key(prf, concat_symkey_symkey(prf->hasher, prf->key, key));
	}
}

void crypt_prf_init_chunk(struct crypt_prf *prf, chunk_t key)
{
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
	/* create the prf key from KEY.  */
	passert(prf->key != NULL);
	/* If the key is too big, re-hash it down to size. */
	if (PK11_GetKeyLength(prf->key) > prf->hasher->hash_block_size) {
		update_key(prf, hash_symkey(prf->hasher, prf->key));
	}
	/* If the key is too small, pad it. */
	if (PK11_GetKeyLength(prf->key) < prf->hasher->hash_block_size) {
		/* pad it to block_size. */
		chunk_t hmac_pad_prf = hmac_pads(0x00,
						 (prf->hasher->hash_block_size -
						  PK11_GetKeyLength(prf->key)));
		update_key(prf, concat_symkey_chunk(prf->hasher, prf->key,
						    hmac_pad_prf));
		freeanychunk(hmac_pad_prf);
	}
	passert(prf->key != NULL);
	DBG(DBG_CRYPT,
	    dbg_dump_symkey("crypt prf padded key", prf->key));

	/* Start forming the inner hash input: (key^IPAD)|... */
	passert(prf->inner == NULL);
	chunk_t hmac_ipad = hmac_pads(HMAC_IPAD, prf->hasher->hash_block_size);
	prf->inner = xor_symkey_chunk(prf->key, hmac_ipad);
	freeanychunk(hmac_ipad);
}

void crypt_prf_update_chunk(struct crypt_prf *prf,
			    chunk_t update)
{
	append_symkey_chunk(prf->hasher, &(prf->inner), update);
}

void crypt_prf_update_symkey(struct crypt_prf *prf,
			     PK11SymKey *update)
{
	append_symkey_symkey(prf->hasher, &(prf->inner), update);
}

void crypt_prf_update_byte(struct crypt_prf *prf,
			   uint8_t update)
{
	append_symkey_byte(prf->hasher, &(prf->inner), update);
}

PK11SymKey *crypt_prf_final(struct crypt_prf *prf)
{
	passert(prf->inner != NULL);
	/* run that through hasher */
	PK11SymKey *hashed_inner = hash_symkey(prf->hasher, prf->inner);
	PK11_FreeSymKey(prf->inner);
	prf->inner = NULL; /* help debug */

	/* Input to outer hash: (key^OPAD)|hashed_inner.  */
	chunk_t hmac_opad = hmac_pads(HMAC_OPAD, prf->hasher->hash_block_size);
	PK11SymKey *outer = xor_symkey_chunk(prf->key, hmac_opad);
	freeanychunk(hmac_opad);
	append_symkey_symkey(prf->hasher, &outer, hashed_inner);
	PK11_FreeSymKey(hashed_inner);

	/* Finally hash that */
	PK11SymKey *hashed_outer = hash_symkey(prf->hasher, outer);
	PK11_FreeSymKey(outer);

	if (prf->we_own_key) {
		PK11_FreeSymKey(prf->key);
	}
	prf->key = NULL; /* help debug */
	pfree(prf);

	return hashed_outer;
}
