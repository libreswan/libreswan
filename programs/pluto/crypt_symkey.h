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
 * Log the details of a SYMKEY.
 *
 * PREFIX should include an explicit colon - it's passed to DBG_dump /
 * DBG_dump_chunk and they do not add a colon.
 *
 * DBG_dump_symkey, when allowed, dumps the contents of the symkey
 * (DBG_PRIVATE and not FIPS).
 */
void DBG_symkey(const char *prefix, PK11SymKey *key);
void DBG_dump_symkey(const char *prefix, PK11SymKey *key);

/*
 * Free any symkey and then stomp on the pointer.
 */
void free_any_symkey(const char *prefix, PK11SymKey **key);

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
 * Extract SIZEOF_SYMKEY bytes of keying material as an ENCRYPTER key
 * (i.e., can be used to encrypt/decrypt data using ENCRYPTER).
 *
 * Offset into the SYMKEY is in BYTES.
 */
PK11SymKey *encrypt_key_from_symkey_bytes(PK11SymKey *source_key,
					  const struct encrypt_desc *encrypter,
					  size_t next_byte, size_t sizeof_symkey);

/*
 * Extract SIZEOF_KEY bytes of keying material as a KEY.  It inherits
 * the BASE_KEYs type.  Good for hash keys.
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


/*
 * Low level primitives.
 */
PK11SymKey *merge_symkey_bytes(const char *prefix,
			       PK11SymKey *base_key,
			       const void *bytes, size_t sizeof_bytes,
			       CK_MECHANISM_TYPE derive,
			       CK_MECHANISM_TYPE target);
PK11SymKey *merge_symkey_symkey(const char *prefix,
			       PK11SymKey *base_key, PK11SymKey *key,
				CK_MECHANISM_TYPE derive,
				CK_MECHANISM_TYPE target);
PK11SymKey *symkey_from_symkey(const char *prefix,
			       PK11SymKey *base_key,
			       CK_MECHANISM_TYPE target, CK_FLAGS flags,
			       size_t next_byte, size_t key_size);

#endif
