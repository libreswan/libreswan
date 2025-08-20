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
#include "where.h"

struct jambuf;
struct ike_alg;
struct hash_desc;
struct encrypt_desc;
struct prf_desc;
struct logger;

void init_crypt_symkey(struct logger *logger);

/*
 * Log some information on a SYMKEY.
 *
 * The format is <PREFIX>: <NAME>-key@...
 */
void LDBG_symkey(struct logger *logger, const char *prefix, const char *name, PK11SymKey *key);
void jam_symkey(struct jambuf *buf, const char *name, PK11SymKey *key);

/*
 * Add/delete references to a reference-countered PK11SymKey.
 */

PK11SymKey *symkey_addref_where(struct logger *logger, const char *name,
				PK11SymKey *key, where_t where);
void symkey_delref_where(const struct logger *logger, const char *name,
			 PK11SymKey **key, where_t where);

#define symkey_addref(LOGGER, NAME, KEY) symkey_addref_where(LOGGER, NAME, KEY, HERE)
#define symkey_delref(LOGGER, NAME, KEY) symkey_delref_where(LOGGER, NAME, KEY, HERE)

/*
 * Length of a symkey in bytes.
 *
 * If KEY is NULL, return 0 (and we hope not dump core).  (If we're
 * not allowed to know the length of the key then this will also
 * return 0).
 */
size_t sizeof_symkey(PK11SymKey *key);

/*
 * Append new keying material to an existing key forming a new key;
 * unreference the old key, replacing it with the new one.
 *
 * Use this to chain a series of concat operations.
 */
void append_symkey_symkey(PK11SymKey **lhs, PK11SymKey *rhs,
			  struct logger *logger);

void append_symkey_bytes(const char *result,
			 PK11SymKey **lhs,
			 const void *rhs, size_t sizeof_rhs,
			 struct logger *logger);
#define append_symkey_hunk(NAME, LHS, RHS, LOGGER)			\
	append_symkey_bytes(NAME, LHS, (RHS).ptr, (RHS).len, LOGGER)

void prepend_bytes_to_symkey(const char *result,
			     const void *lhs, size_t sizeof_lhs,
			     PK11SymKey **rhs,
			     struct logger *logger);
#define prepend_hunk_to_symkey(NAME, LHS, RHS)			\
	append_bytes_symkey(NAME, (LHS).ptr, (LHS).len, RHS)

void append_symkey_byte(PK11SymKey **lhs, uint8_t rhs,
			struct logger *logger);

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ALG key (i.e.,
 * can be used to implement ALG).
 *
 * For instance, an encryption key needs to have a type matching the
 * NSS encryption algorithm.
 *
 * Offset into the SYMKEY is in BYTES.
 */
PK11SymKey *prf_key_from_symkey_bytes(const char *result_name,
				      const struct prf_desc *prf,
				      size_t symkey_start_byte, size_t sizeof_symkey,
				      PK11SymKey *source_key,
				      where_t where, struct logger *logger);

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as an ALG key (i.e.,
 * can be used to implement ALG).
 *
 * For instance, an encryption key needs to have a type matching the
 * NSS encryption algorithm.
 *
 * Offset into the SYMKEY is in BYTES.
 */
PK11SymKey *encrypt_key_from_symkey_bytes(const char *result_name,
					  const struct encrypt_desc *encrypt,
					  size_t symkey_start_byte, size_t sizeof_symkey,
					  PK11SymKey *source_key,
					  where_t where, struct logger *logger);

/*
 * Extract wire material from a symkey.
 *
 * Used to avoid interface issues with NSS.  If ALG is null then the
 * key has a generic mechanism type.
 */
chunk_t chunk_from_symkey(const char *prefix, PK11SymKey *symkey,
			  struct logger *logger);
chunk_t chunk_from_symkey_bytes(const char *prefix, PK11SymKey *symkey,
				size_t chunk_start, size_t sizeof_chunk,
				struct logger *logger, where_t where);

PK11SymKey *cipher_symkey(const char *name,
			  const struct encrypt_desc *encrypt,
			  unsigned size,
			  struct logger *logger,
			  where_t where);

/*
 * Create a key suitable for ALG.
 *
 * Used to avoid interface issues with NSS.
 */
PK11SymKey *symkey_from_bytes(const char *name,
			      const uint8_t *bytes, size_t sizeof_bytes,
			      struct logger *logger);
#define symkey_from_hunk(NAME, HUNK, LOGGER)		\
	symkey_from_bytes(NAME, (HUNK).ptr, (HUNK).len, LOGGER)

PK11SymKey *symkey_from_symkey(const char *result_name,
			       PK11SymKey *base_key,
			       CK_MECHANISM_TYPE target,
			       CK_FLAGS flags,
			       size_t key_offset, size_t key_size,
			       where_t where, struct logger *logger);

PK11SymKey *encrypt_key_from_bytes(const char *name,
				   const struct encrypt_desc *encrypt,
				   const uint8_t *bytes, size_t sizeof_bytes,
				   where_t where, struct logger *logger);
/* XXX: can't pass HERE aka '{,}' to macros */
#define encrypt_key_from_hunk(NAME, ENCRYPT, HUNK, LOGGER)		\
	encrypt_key_from_bytes(NAME, ENCRYPT, (HUNK).ptr, (HUNK).len, HERE, LOGGER)


PK11SymKey *prf_key_from_bytes(const char *name,
			       const struct prf_desc *prf,
			       const uint8_t *bytes, size_t sizeof_bytes,
			       where_t where, struct logger *logger);
/* XXX: can't pass HERE aka '{,}' to macros */
#define prf_key_from_hunk(NAME, PRF, HUNK, LOGGER)			\
	prf_key_from_bytes(NAME, PRF, (HUNK).ptr, (HUNK).len, HERE, LOGGER)

/*
 * Extract SIZEOF_KEY bytes of keying material as a KEY.
 *
 * Good for extracting hash or other keys that don't yet have an NSS
 * type.
 *
 * Offset into the SYMKEY is in BYTES.
 */
PK11SymKey *key_from_symkey_bytes(const char *result_name,
				  PK11SymKey *source_key,
				  size_t next_byte, size_t sizeof_key,
				  where_t where, struct logger *logger);

/*
 * Generic operation.
 */
PK11SymKey *crypt_derive(PK11SymKey *base_key, CK_MECHANISM_TYPE derive, SECItem *params,
			 const char *target_name, CK_MECHANISM_TYPE target_mechanism,
			 CK_ATTRIBUTE_TYPE operation,
			 int key_size, CK_FLAGS flags, where_t where,
			 struct logger *logger);

#endif
