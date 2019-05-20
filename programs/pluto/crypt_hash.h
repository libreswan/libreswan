/*
 * Hash algorithms, for libreswan
 *
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

#ifndef crypt_hash_h
#define crypt_hash_h

#include <pk11pub.h>

#include "chunk.h"

struct hash_desc;
struct crypt_hash;

/*
 * Initialization.
 */
struct crypt_hash *crypt_hash_init(const char *hash_name,
				   const struct hash_desc *hash_desc);

/*
 * Digest the body
 */
void crypt_hash_digest_chunk(struct crypt_hash *hash,
			     const char *chunk_name, chunk_t chunk);
void crypt_hash_digest_symkey(struct crypt_hash *hash,
			      const char *symkey_name, PK11SymKey *symkey);
void crypt_hash_digest_byte(struct crypt_hash *hash,
			    const char *byte_name, uint8_t byte);
void crypt_hash_digest_bytes(struct crypt_hash *hash,
			     const char *bytes_name, const void *bytes,
			     size_t sizeof_bytes);

/*
 * Finally ...
 *
 * This will free HASH and blat the pointer.
 */
void crypt_hash_final_bytes(struct crypt_hash **hashp,
			    uint8_t *bytes, size_t sizeof_bytes);

chunk_t crypt_hash_final_chunk(struct crypt_hash **hashp);

/*
 * FIPS short cut for symkeys.
 */
PK11SymKey *crypt_hash_symkey(const char *hash_name,
			      const struct hash_desc *hash_desc,
			      const char *symkey_name, PK11SymKey *symkey);

#endif
