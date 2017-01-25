/*
 * Hash algorithms, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include <stdlib.h>

//#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_hash.h"
#include "crypt_symkey.h"

struct crypt_hash {
	struct hash_context *context;
	const struct hash_ops *ops;
};

struct crypt_hash *crypt_hash_init(const struct hash_desc *hash_desc,
				   const char *name, lset_t debug)
{
	struct hash_context *context =
		hash_desc->hash_ops->init(hash_desc, name, debug);
	if (context == NULL) {
		return NULL;
	}
	struct crypt_hash *hash = alloc_thing(struct crypt_hash, name);
	*hash = (struct crypt_hash) {
		.context = context,
		.ops = hash_desc->hash_ops,
	};
	return hash;
}

void crypt_hash_digest_chunk(struct crypt_hash *hash,
			     const char *name, chunk_t chunk)
{
	hash->ops->digest_bytes(hash->context, name, chunk.ptr, chunk.len);
}

void crypt_hash_digest_symkey(struct crypt_hash *hash,
			      const char *name, PK11SymKey *symkey)
{
	hash->ops->digest_symkey(hash->context, name, symkey);
}

void crypt_hash_digest_byte(struct crypt_hash *hash,
			    const char *name, uint8_t byte)
{
	hash->ops->digest_bytes(hash->context, name, &byte, 1);
}

void crypt_hash_digest_bytes(struct crypt_hash *hash,
			     const char *name, const void *bytes,
			     size_t sizeof_bytes)
{
	hash->ops->digest_bytes(hash->context, name, bytes, sizeof_bytes);
}

void crypt_hash_final_bytes(struct crypt_hash **hashp,
			    u_int8_t *bytes, size_t sizeof_bytes)
{
	(*hashp)->ops->final_bytes(&(*hashp)->context, bytes, sizeof_bytes);
	pfree(*hashp);
	*hashp = NULL;
}

void crypt_hash_final_chunk(struct crypt_hash **hashp, chunk_t chunk)
{
	crypt_hash_final_bytes(hashp, chunk.ptr, chunk.len);
}

PK11SymKey *crypt_hash_symkey(const struct hash_desc *hash_desc,
			      const char *name, lset_t debug,
			      const char *symkey_name, PK11SymKey *symkey)
{
	return hash_desc->hash_ops->symkey_to_symkey(hash_desc, name, debug,
						     symkey_name, symkey);
}
