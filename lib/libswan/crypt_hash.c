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

PRINTF_LIKE(2)
static bool ldbg_hash(const struct crypt_hash *hash, const char *msg, ...)
{
	if (!LDBGP(DBG_CRYPT, hash->logger)) {
		return false;
	}
	LLOG_JAMBUF(DEBUG_STREAM, hash->logger, buf) {
		jam_string(buf, hash->name);
		jam_string(buf, " ");
		jam_string(buf, hash->desc->common.fqn);
		jam_string(buf, " HASH");
		if (hash->context != NULL) {
			jam(buf, " at %p", hash->context);
		}
		jam_string(buf, ": ");
		va_list ap;
		va_start(ap, msg);
		jam_va_list(buf, msg, ap);
		va_end(ap);
	}
	return true;
}

struct crypt_hash *crypt_hash_init(const char *hash_name,
				   const struct hash_desc *hash_desc,
				   struct logger *logger)
{
	struct hash_context *context = hash_desc->hash_ops->init(hash_desc, hash_name);
	if (context == NULL) {
		return NULL;
	}
	struct crypt_hash *hash = alloc_thing(struct crypt_hash, hash_name);
	hash->context = context;
	hash->name = hash_name;
	hash->desc = hash_desc;
	hash->logger = logger;
	ldbg_hash(hash, "init");
	return hash;
}

void crypt_hash_digest_symkey(struct crypt_hash *hash,
			      const char *name, PK11SymKey *symkey)
{
	if (ldbg_hash(hash, "digest symkey %s@%p (size %zu)",
		      name, symkey, sizeof_symkey(symkey))) {
		LDBG_symkey(hash->logger, hash->name, name, symkey);
	}
	hash->desc->hash_ops->digest_symkey(hash->context, name, symkey);
}

void crypt_hash_digest_byte(struct crypt_hash *hash,
			    const char *name, uint8_t byte)
{
	if (ldbg_hash(hash, "digest byte %s 0x%"PRIx8" (%"PRIu8")",
		      name, byte, byte)) {
		LDBG_thing(hash->logger, byte);
	}
	hash->desc->hash_ops->digest_bytes(hash->context, name, &byte, 1);
}

void crypt_hash_digest_bytes(struct crypt_hash *hash,
			     const char *name,
			     const void *bytes,
			     size_t sizeof_bytes)
{
	/*
	 * XXX: don't log BYTES using @POINTER syntax as it might be
	 * bogus - confusing refcnt.awk.
	 */
	if (ldbg_hash(hash, "digest hunk %s (%p length %zu)",
		      name, bytes, sizeof_bytes)) {
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
	if (ldbg_hash(hash, "final bytes@%p (length %zu)",
		      bytes, sizeof_bytes)) {
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
	if (ldbg_hash(hash, "final mac length %zu", output.len)) {
		LDBG_hunk(hash->logger, &output);
	}
	pfree(*hashp);
	*hashp = hash = NULL;
	return output;
}
