/*
 * SYMKEY manipulation functions, for libreswan
 *
 * Copyright (C) 2015, 2016 Andrew Cagney <cagney@gnu.org>
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

#ifndef crypt_symkey_h
#define crypt_symkey_h

#include <stdio.h>
#include <pk11pub.h>

#include "chunk.h"

struct ike_alg;
struct hash_desc;
struct encrypt_desc;
struct prf_desc;

/*
 * Log some information on a SYMKEY.
 *
 * The format is <PREFIX><NAME>-key@...
 */
void DBG_symkey(const char *prefix, const char *name, PK11SymKey *key);

/*
 * Add/delete references to a reference-countered PK11SymKey.
 */
void release_symkey(const char *prefix, const char *name, PK11SymKey **key);
PK11SymKey *reference_symkey(const char *prefix, const char *name, PK11SymKey *key);

/*
 * Length of a symkey in bytes.
 *
 * If KEY is NULL, return 0 (and we hope not dump core).  (If we're
 * not allowed to know the length of the key then this will also
 * return 0).
 */
size_t sizeof_symkey(PK11SymKey *key);

/*
 * Concatenate two pieces of keying material creating a
 * new SYMKEY object.
 */
PK11SymKey *concat_symkey_symkey(PK11SymKey *lhs, PK11SymKey *rhs);
PK11SymKey *concat_symkey_bytes(PK11SymKey *lhs, const void *rhs,
				size_t sizeof_rhs);
PK11SymKey *concat_bytes_symkey(const void *lhs, size_t sizeof_lhs,
				PK11SymKey *rhs);
PK11SymKey *concat_symkey_chunk(PK11SymKey *lhs, chunk_t rhs);
PK11SymKey *concat_symkey_byte(PK11SymKey *lhs, uint8_t rhs);
chunk_t concat_chunk_symkey(const char *name, chunk_t lhs, PK11SymKey *rhs);
chunk_t concat_chunk_bytes(const char *name, chunk_t lhs,
			   const void *rhs, size_t sizeof_rhs);

/*
 * Append new keying material to an existing key; replace the existing
 * key with the result.
 *
 * Use this to chain a series of concat operations.
 */
void append_symkey_symkey(PK11SymKey **lhs, PK11SymKey *rhs);
void append_symkey_bytes(PK11SymKey **lhs, const void *rhs,
			 size_t sizeof_rhs);
void append_bytes_symkey(const void *lhs, size_t sizeof_lhs,
			 PK11SymKey **rhs);
void append_symkey_chunk(PK11SymKey **lhs, chunk_t rhs);
void append_symkey_byte(PK11SymKey **lhs, uint8_t rhs);
void append_chunk_chunk(const char *name, chunk_t *lhs, chunk_t rhs);
void append_chunk_bytes(const char *name, chunk_t *lhs, const void *rhs,
			size_t sizeof_rhs);
void append_chunk_symkey(const char *name, chunk_t *lhs, PK11SymKey *rhs);

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ALG key (i.e.,
 * can be used to implement ALG).
 *
 * For instance, an encryption key needs to have a type matching the
 * NSS encryption algorithm.
 *
 * Offset into the SYMKEY is in BYTES.
 */
PK11SymKey *prf_key_from_symkey_bytes(const char *name,
				      const struct prf_desc *prf,
				      size_t symkey_start_byte, size_t sizeof_symkey,
				      PK11SymKey *source_key);

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ALG key (i.e.,
 * can be used to implement ALG).
 *
 * For instance, an encryption key needs to have a type matching the
 * NSS encryption algorithm.
 *
 * Offset into the SYMKEY is in BYTES.
 */
PK11SymKey *encrypt_key_from_symkey_bytes(const char *name,
					  const struct encrypt_desc *encrypt,
					  size_t symkey_start_byte, size_t sizeof_symkey,
					  PK11SymKey *source_key);

/*
 * Extract wire material from a symkey.
 *
 * Used to avoid interface issues with NSS.  If ALG is null then the
 * key has a generic mechanism type.
 */
chunk_t chunk_from_symkey(const char *prefix,
			  PK11SymKey *symkey);
chunk_t chunk_from_symkey_bytes(const char *prefix,
				PK11SymKey *symkey,
				size_t chunk_start, size_t sizeof_chunk);

/*
 * Create a key suitable for ALG.
 *
 * Used to avoid interface issues with NSS.
 */
PK11SymKey *symkey_from_bytes(const char *name,
			      const uint8_t *bytes, size_t sizeof_bytes);
PK11SymKey *symkey_from_chunk(const char *name,
			      chunk_t chunk);
PK11SymKey *encrypt_key_from_bytes(const char *name,
				   const struct encrypt_desc *encrypt,
				   const uint8_t *bytes, size_t sizeof_bytes);
PK11SymKey *prf_key_from_bytes(const char *name,
			       const struct prf_desc *prf,
			       const uint8_t *bytes, size_t sizeof_bytes);

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
 * XOR a symkey with a chunk.
 */
PK11SymKey *xor_symkey_chunk(PK11SymKey *lhs, chunk_t rhs);

#endif
