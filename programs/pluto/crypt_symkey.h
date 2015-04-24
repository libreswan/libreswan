/*
 * SYMKEY manipulation functions, for libreswan
 *
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

#ifndef crypt_symkey_h
#define crypt_symkey_h

#include <stdio.h>
#include <pk11pub.h>
#include "lswalloc.h"

struct hash_desc;
struct encrypt_desc;

/*
 * Use SCRATCH key as a secure starting point for creating the key
 * from the raw bytes, or chunk.
 */

PK11SymKey *symkey_from_bytes(PK11SymKey *scratch, const void *bytes,
			      size_t sizeof_bytes);
  
PK11SymKey *symkey_from_chunk(PK11SymKey *scratch, chunk_t chunk);

void dbg_dump_symkey(const char *prefix, PK11SymKey *key);

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

/*
 * Extract SIZEOF_CHUNK raw-bytes from a SYMKEY.
 *
 * Offset into the SYMKEY is in either BITS or BYTES.
 */
chunk_t chunk_from_symkey_bits(const char *name, PK11SymKey *source_key,
			       size_t next_bit, size_t sizeof_chunk);
chunk_t chunk_from_symkey_bytes(const char *name, PK11SymKey *source_key,
				size_t next_byte, size_t sizeof_chunk);
chunk_t chunk_from_symkey(const char *name, PK11SymKey *source_key);

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ENCRYPTER key
 * (i.e., can be used to encrypt/decrypt data using ENCRYPTER).
 *
 * Offset into the SYMKEY is in either BITS or BYTES.
 */
PK11SymKey *encrypt_key_from_symkey_bytes(PK11SymKey *source_key,
					  const struct encrypt_desc *encrypter,
					  size_t next_byte, size_t sizeof_symkey);
PK11SymKey *encrypt_key_from_symkey_bits(PK11SymKey *source_key,
					 const struct encrypt_desc *encrypter,
					 size_t next_bit, size_t sizeof_symkey);

/*
 * Extract SIZEOF_KEY bytes of keying material as a KEY.  It inherits
 * the BASE_KEYs type.  Good for hash keys.
 *
 * Offset into the SYMKEY is in either BITS or BYTES.
 */
PK11SymKey *key_from_symkey_bits(PK11SymKey *base_key,
				 size_t next_bit, int key_size);
PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, int sizeof_key);

/*
 * Hash a symkey using HASHER.
 *
 * This gets used by the PRF when the BASE_KEY is too long.
 */
PK11SymKey *hash_symkey(const struct hash_desc *hasher,
			PK11SymKey *base_key);

/*
 * XOR a symkey with a chunk.
 */
PK11SymKey *xor_symkey_chunk(PK11SymKey *lhs, chunk_t rhs);

#endif
