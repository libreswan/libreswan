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
