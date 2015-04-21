/*
 * prf and keying material helper functions, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#ifndef crypt_prf_h
#define crypt_prf_h

#include <pk11pub.h>

struct hash_desc;

/*
 * Primitives implementing PRF described in rfc2104.
 *
 * This implementation tries to keep all the input and output material
 * secure inside SymKeys.  To that end, it should be good for
 * generating keying material.
 *
 * The slightly clunky, nterface expects a call sequence like:
 *
 *   struct crypt_prf *prf = crypt_prf_init(hasher)
 *   crypt_prf_init_XXX(prf, key) ...
 *   crypt_prf_update(prf)
 *   crypt_prf_update_XXX(prf, data)...
 *   key = crypt_prf_final(prf)
 *
 * where the crypt_prf_init_XXX calls feed the PRF the key (some calls
 * need to assemble the key from several pieces of data); and the
 * crypt_prf_update_XXX calls feed the PRF the corresponding data
 * (a.k.a., text, and seed).

 * hmac.c contains an alternative, less flexible interface.  However,
 * one that deals better with data intended for the wire - it isn't as
 * good at keeping stuff secure in PK11SymKeys.
 *
 * What is really needed is for NSS to implement an interface that
 * provides the best of both worlds.
 */

struct crypt_prf;

struct crypt_prf *crypt_prf_init(const struct hash_desc *hasher,
				 PK11SymKey *scratch);
void crypt_prf_init_symkey(struct crypt_prf *prf, PK11SymKey *key);
void crypt_prf_init_chunk(struct crypt_prf *prf, chunk_t key);
#if 0
void crypt_prf_init_bytes(struct crypt_prf *prf, void *key, size_t sizeof_key);
#endif

void crypt_prf_update(struct crypt_prf *prf);
void crypt_prf_update_chunk(struct crypt_prf *prf, chunk_t update);
void crypt_prf_update_symkey(struct crypt_prf *prf, PK11SymKey *update);
void crypt_prf_update_byte(struct crypt_prf *prf, uint8_t byte);
#if 0
void crypt_prf_update_bytes(struct crypt_prf *prf, void *bytes, size_t count);
#endif

PK11SymKey *crypt_prf_final(struct crypt_prf *prf);

#endif
