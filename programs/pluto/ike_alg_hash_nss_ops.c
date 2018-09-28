/*
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_symkey.h"
#include "crypto.h"
#include "lswfips.h"
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
	DBGF(DBG_CRYPT_LOW, "%s %s hasher: context %p",
	     name, hash_desc->common.name, hash->context);
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
	DBG(DBG_CRYPT_LOW, DBG_dump((*hashp)->name, bytes, sizeof_bytes));
	pfree(*hashp);
	*hashp = NULL;
}

static PK11SymKey *symkey_to_symkey(const struct hash_desc *hash_desc,
				    const char *name,
				    const char *symkey_name, PK11SymKey *symkey)
{
	CK_MECHANISM_TYPE derive = hash_desc->nss.derivation_mechanism;
	SECItem *param = NULL;
	CK_MECHANISM_TYPE target = CKM_CONCATENATE_BASE_AND_KEY; /* bogus */
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	int key_size = 0;

	if DBGP(DBG_CRYPT_LOW) {
		LSWLOG_DEBUG(buf) {
			lswlogf(buf, "%s hash(%s) symkey %s(%p) to symkey - derive:",
				name, hash_desc->common.name,
				symkey_name, symkey);
			lswlog_nss_ckm(buf, derive);
		}
		DBG_symkey(name, symkey_name, symkey);
	}
	PK11SymKey *result = PK11_Derive(symkey, derive, param, target,
					 operation, key_size);
	DBG(DBG_CRYPT_LOW, DBG_symkey("    result: ", name, result));
	return result;
}

static void nss_hash_check(const struct hash_desc *hash)
{
	const struct ike_alg *alg = &hash->common;
	// pexpect_ike_alg(alg, hash->common.nss_mechanism == 0);
	pexpect_ike_alg(alg, hash->nss.oid_tag > 0);
	pexpect_ike_alg(alg, hash->nss.derivation_mechanism > 0);
}

const struct hash_ops ike_alg_hash_nss_ops = {
	nss_hash_check,
	init,
	digest_symkey,
	digest_bytes,
	final_bytes,
	symkey_to_symkey,
};
