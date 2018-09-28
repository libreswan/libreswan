/*
 * Hash algorithms, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#ifndef crypt_hash_h
#define crypt_hash_h

#include <pk11pub.h>

#include "chunk.h"

struct hash_desc;
struct crypt_hash;

/*
 * Initialization.
 */
struct crypt_hash *crypt_hash_init(const struct hash_desc *hash_desc,
				   const char *name, lset_t debug);

/*
 * Digest the body
 */
void crypt_hash_digest_chunk(struct crypt_hash *hash,
			     const char *name, chunk_t chunk);
void crypt_hash_digest_symkey(struct crypt_hash *hash,
			      const char *name, PK11SymKey *symkey);
void crypt_hash_digest_byte(struct crypt_hash *hash,
			    const char *name, uint8_t byte);
void crypt_hash_digest_bytes(struct crypt_hash *hash,
			     const char *name, const void *bytes,
			     size_t sizeof_bytes);

/*
 * Finally ...
 *
 * This will free HASH and blat the pointer.
 */
void crypt_hash_final_bytes(struct crypt_hash **hashp,
			    uint8_t *bytes, size_t sizeof_bytes);

chunk_t crypt_hash_final_chunk(struct crypt_hash **hashp, const char *what);

/*
 * FIPS short cut for symkeys.
 */
PK11SymKey *crypt_hash_symkey(const struct hash_desc *hash_desc,
			      const char *name, lset_t debug,
			      const char *symkey_name, PK11SymKey *symkey);

#endif
