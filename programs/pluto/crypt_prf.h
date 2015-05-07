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
struct crypt_prf;

/*
 * Primitives implementing PRF described in rfc2104.
 *
 * This implementation tries to keep all the input and output material
 * secure inside SymKeys.  To that end, it should be good for
 * generating keying material.
 *
 * The slightly clunky, interface is described in-line below.
 */

/*
 * Call this first; always.
 *
 * SCRATCH is used as a secure starting point when the key is formed
 * from raw bytes (or memory).
 */
struct crypt_prf *crypt_prf_init(const char *name,
				 const struct hash_desc *hasher,
				 PK11SymKey *scratch);

/*
 * Next load up the raw-key by calling one or more of the following.
 * Multiple calls concatenate the key.
 *
 * Even when SCRATCH above was passed the KEY, the below must be
 * called.
 */
void crypt_prf_init_symkey(const char *name, struct crypt_prf *prf, PK11SymKey *key);
void crypt_prf_init_chunk(const char *name, struct crypt_prf *prf,
			  chunk_t key);
void crypt_prf_init_bytes(const char *name, struct crypt_prf *prf,
			  const void *key, size_t sizeof_key);

/*
 * Then call this to flip to seed/data/text mode; always.
 */
void crypt_prf_update(struct crypt_prf *prf);

/*
 * Call these to accumulate the seed/data/text.
 */
void crypt_prf_update_chunk(const char *name, struct crypt_prf *prf,
			    chunk_t update);
void crypt_prf_update_symkey(const char *name, struct crypt_prf *prf,
			     PK11SymKey *update);
void crypt_prf_update_byte(const char *name, struct crypt_prf *prf, uint8_t byte);
void crypt_prf_update_bytes(const char *name, struct crypt_prf *prf,
			    const void *bytes, size_t count);

/*
 * Finally ...
 *
 * This will free PRF.
 */
PK11SymKey *crypt_prf_final(struct crypt_prf *prf);
void crypt_prf_final_bytes(struct crypt_prf *prf,
			   void *bytes, size_t sizeof_bytes);

#endif
