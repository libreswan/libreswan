/*
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

#include <stdlib.h>

#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "ike_alg_hash_ops.h"
#include "crypt_symkey.h"
#include "fips_mode.h"
#include "lswnss.h"

/*
 * These probably fail in FIPS mode.
 */
struct hash_context {
	const char *name;
	PK11Context *context;
	const struct hash_desc *desc;
};

static struct hash_context *init(const struct hash_desc *hash_desc,
				 const char *name)
{
	struct hash_context *hash = alloc_thing(struct hash_context, "hasher");
	*hash = (struct hash_context) {
		.context = PK11_CreateDigestContext(hash_desc->nss.oid_tag),
		.name = name,
		.desc = hash_desc,
	};
	passert(hash->context);
	SECStatus rc = PK11_DigestBegin(hash->context);
	passert(rc == SECSuccess);
	return hash;
}

static void digest_symkey(struct hash_context *hash,
			  const char *name UNUSED,
			  PK11SymKey *symkey)
{
	passert(digest_symkey == hash->desc->hash_ops->digest_symkey);
	SECStatus rc = PK11_DigestKey(hash->context, symkey);
	passert(rc == SECSuccess);
}

static void digest_bytes(struct hash_context *hash,
			 const char *name UNUSED,
			 const uint8_t *bytes, size_t sizeof_bytes)
{
	passert(digest_bytes == hash->desc->hash_ops->digest_bytes);
	SECStatus rc = PK11_DigestOp(hash->context, bytes, sizeof_bytes);
	passert(rc == SECSuccess);
}

static void final_bytes(struct hash_context **hashp,
			uint8_t *bytes, size_t sizeof_bytes)
{
	passert(final_bytes == (*hashp)->desc->hash_ops->final_bytes);
	unsigned out_len = 0;
	passert(sizeof_bytes == (*hashp)->desc->hash_digest_size);
	SECStatus rc = PK11_DigestFinal((*hashp)->context, bytes,
					&out_len, sizeof_bytes);
	passert(rc == SECSuccess);
	passert(out_len <= sizeof_bytes);
	PK11_DestroyContext((*hashp)->context, PR_TRUE);
	pfree(*hashp);
	*hashp = NULL;
}

static void nss_hash_check(const struct hash_desc *hash, struct logger *logger)
{
	const struct ike_alg *alg = &hash->common;
	// pexpect_ike_alg(alg, hash->common.nss_mechanism == 0);
	pexpect_ike_alg(logger, alg, hash->nss.oid_tag > 0);
	pexpect_ike_alg(logger, alg, hash->nss.derivation_mechanism > 0);
}

const struct hash_ops ike_alg_hash_nss_ops = {
	"NSS",
	nss_hash_check,
	init,
	digest_symkey,
	digest_bytes,
	final_bytes,
};
