/*
 * SYMKEY manipulation functions, for libreswan
 *
 * Copyright (C) 2015, 2016 Andrew Cagney <cagney@gnu.org>
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

#ifndef crypt_symkey_h
#define crypt_symkey_h

#include <stdio.h>
#include <pk11pub.h>
#include "lswalloc.h"

struct ike_alg;
struct hash_desc;
struct encrypt_desc;

/*
 * Log some information on a SYMKEY.
 */
void DBG_symkey(const char *prefix, PK11SymKey *key);

/*
 * Free any symkey and then stomp on the pointer.
 */
void free_any_symkey(const char *prefix, PK11SymKey **key);

/*
 * Length of a symkey in bytes.
 *
 * If KEY is NULL, return 0 (and hopefully not dump core).  (if we're
 * not allowed to know the length of the key then this will also
 * return 0).
 */
size_t sizeof_symkey(PK11SymKey *key);

/*
 * Use SCRATCH key as a secure starting point for creating the key
 * from the raw bytes, or chunk.
 */

PK11SymKey *symkey_from_bytes(PK11SymKey *scratch, const void *bytes,
			      size_t sizeof_bytes);

PK11SymKey *symkey_from_chunk(PK11SymKey *scratch, chunk_t chunk);

/*
 * Concatenate two pieces of keying material creating a
 * new SYMKEY object.
 */
PK11SymKey *concat_symkey_symkey(const struct hash_desc *hasher,
				 PK11SymKey *lhs, PK11SymKey *rhs);
PK11SymKey *concat_symkey_bytes(const struct hash_desc *hasher,
				PK11SymKey *lhs, const void *rhs,
				size_t sizeof_rhs);
PK11SymKey *concat_symkey_chunk(const struct hash_desc *hasher,
				PK11SymKey *lhs, chunk_t rhs);
PK11SymKey *concat_symkey_byte(const struct hash_desc *hasher,
			       PK11SymKey *lhs, uint8_t rhs);
chunk_t concat_chunk_chunk(const char *name, chunk_t lhs, chunk_t rhs);

/*
 * Append new keying material to an existing key; replace the existing
 * key with the result.
 *
 * Use this to chain a series of concat operations.
 */
void append_symkey_symkey(const struct hash_desc *hasher,
			  PK11SymKey **lhs, PK11SymKey *rhs);
void append_symkey_bytes(const struct hash_desc *hasher,
			 PK11SymKey **lhs, const void *rhs,
			 size_t sizeof_rhs);
void append_symkey_chunk(const struct hash_desc *hasher,
			 PK11SymKey **lhs, chunk_t rhs);
void append_symkey_byte(const struct hash_desc *hasher,
			PK11SymKey **lhs, uint8_t rhs);
void append_chunk_chunk(const char *name, chunk_t *lhs, chunk_t rhs);

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ALG key (i.e.,
 * can be used to implement ALG).
 *
 * For instance, an encryption key needs to have a type matching the
 * NSS encryption algorithm.
 *
 * Offset into the SYMKEY is in BYTES.
 */
PK11SymKey *symkey_from_symkey_bytes(const char *name, lset_t debug,
				     const struct ike_alg *symkey_alg,
				     size_t symkey_start_byte, size_t sizeof_symkey,
				     PK11SymKey *source_key);

/*
 * Extract wire material from a symkey.
 *
 * Used to avoid interface issues with NSS.
 */
chunk_t chunk_from_symkey(const char *prefix, lset_t debug,
			  PK11SymKey *symkey);

/*
 * Extract SIZEOF_KEY bytes of keying material as a KEY.
 *
 * Good for extracting hash or other keys that don't yet have an NSS
 * type.
 *
 * Offset into the SYMKEY is in BYTES.
 */
PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, size_t sizeof_key);

/*
 * Hash a symkey using HASHER to either bytes or a SYMKEY.
 *
 * This gets used by the PRF code.
 */
PK11SymKey *hash_symkey_to_symkey(const char *prefix,
				  const struct hash_desc *hasher,
				  PK11SymKey *base_key);

void *hash_symkey_to_bytes(const char *prefix,
			   const struct hash_desc *hasher,
			   PK11SymKey *base_key,
			   void *bytes, size_t sizeof_bytes);

/*
 * XOR a symkey with a chunk.
 */
PK11SymKey *xor_symkey_chunk(PK11SymKey *lhs, chunk_t rhs);

#endif
