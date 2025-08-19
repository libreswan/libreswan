/*
 * Hash algorithms, for libreswan
 *
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <stdlib.h>

#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_hash_ops.h"
#include "crypt_hash.h"
#include "crypt_symkey.h"

struct crypt_hash {
	struct hash_context *context;
	const char *name;
	const struct hash_desc *desc;
	struct logger *logger;
};

struct crypt_hash *crypt_hash_init(const char *name, const struct hash_desc *hash_desc,
				   struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "%s hash %s init",
	      name, hash_desc->common.fqn);
	struct hash_context *context =
		hash_desc->hash_ops->init(hash_desc, name);
	if (context == NULL) {
		return NULL;
	}
	struct crypt_hash hash = {
		.context = context,
		.name = name,
		.desc = hash_desc,
		.logger = logger,
	};
	return clone_thing(hash, name);
}

void crypt_hash_digest_symkey(struct crypt_hash *hash,
			      const char *name, PK11SymKey *symkey)
{
	if (LDBGP(DBG_CRYPT, hash->logger)) {
		LDBG_log(hash->logger, "%s hash %s digest %s-key@%p (size %zu)",
			 hash->name, hash->desc->common.fqn,
			 name, symkey, sizeof_symkey(symkey));
		LDBG_symkey(hash->logger, hash->name, name, symkey);
	}
	hash->desc->hash_ops->digest_symkey(hash->context, name, symkey);
}

void crypt_hash_digest_byte(struct crypt_hash *hash,
			    const char *name, uint8_t byte)
{
	if (LDBGP(DBG_CRYPT, hash->logger)) {
		LDBG_log(hash->logger, "%s hash %s digest %s 0x%"PRIx8" (%"PRIu8")",
			 hash->name, hash->desc->common.fqn,
			 name, byte, byte);
		LDBG_thing(hash->logger, byte);
	}
	hash->desc->hash_ops->digest_bytes(hash->context, name, &byte, 1);
}

void crypt_hash_digest_bytes(struct crypt_hash *hash,
			     const char *name,
			     const void *bytes,
			     size_t sizeof_bytes)
{
	if (LDBGP(DBG_CRYPT, hash->logger)) {
		/*
		 * XXX: don't log BYTES using @POINTER syntax as it
		 * might be bogus - confusing refcnt.awk.
		 */
		LDBG_log(hash->logger, "%s hash %s digest %s (%p length %zu)",
			 hash->name, hash->desc->common.fqn,
			 name, bytes, sizeof_bytes);
		LDBG_dump(hash->logger, bytes, sizeof_bytes);
	}
	hash->desc->hash_ops->digest_bytes(hash->context, name, bytes, sizeof_bytes);
}

void crypt_hash_final_bytes(struct crypt_hash **hashp,
			    uint8_t *bytes, size_t sizeof_bytes)
{
	struct crypt_hash *hash = *hashp;
	/* Must be correct, else hash code can crash. */
	passert(sizeof_bytes == hash->desc->hash_digest_size);
	hash->desc->hash_ops->final_bytes(&hash->context, bytes, sizeof_bytes);
	if (LDBGP(DBG_CRYPT, hash->logger)) {
		LDBG_log(hash->logger, "%s hash %s final bytes@%p (length %zu)",
			 hash->name, hash->desc->common.fqn,
			 bytes, sizeof_bytes);
		LDBG_dump(hash->logger, bytes, sizeof_bytes);
	}
	pfree(*hashp);
	*hashp = hash = NULL;
}

struct crypt_mac crypt_hash_final_mac(struct crypt_hash **hashp)
{
	struct crypt_hash *hash = *hashp;
	struct crypt_mac output = { .len = hash->desc->hash_digest_size, };
	passert(output.len <= sizeof(output.ptr/*array*/));
	hash->desc->hash_ops->final_bytes(&hash->context, output.ptr, output.len);
	if (LDBGP(DBG_CRYPT, hash->logger)) {
		LDBG_log(hash->logger, "%s hash %s final length %zu",
			 hash->name, hash->desc->common.fqn, output.len);
		LDBG_hunk(hash->logger, output);
	}
	pfree(*hashp);
	*hashp = hash = NULL;
	return output;
}
