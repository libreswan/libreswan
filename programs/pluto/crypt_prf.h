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
 * Implement PRF described in rfc2104.
 */

PK11SymKey *crypt_prf(const struct hash_desc *hasher,
		      PK11SymKey *key, PK11SymKey *seed);

/*
 * Primitives implementing PRF described in rfc2104.
 *
 * The interface is chunky; but then so are some calls.  Currently
 * things are not the most efficient.
 *
 * prf = crypt_prf_init(hasher)
 * crypt_prf_init_XXX(prf, key)+
 * crypt_prf_update(prf)
 * crypt_prf_update_xxxx(prf, material)+
 * key = crypt_prf_final(prf)
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
