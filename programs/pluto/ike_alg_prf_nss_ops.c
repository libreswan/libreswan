/*
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

#include <stdio.h>
#include <stdlib.h>

#include <prmem.h>
#include <prerror.h>

#include "libreswan.h"

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_prf_nss_ops.h"
#include "crypt_symkey.h"

struct prf_context {
	const char *name;
	const struct prf_desc *desc;
	PK11Context *context;
};

/*
 * Create a PRF ready to consume data.
 */

static struct prf_context *init(const struct prf_desc *prf_desc,
				const char *name,
				const char *key_name, PK11SymKey *key)

{
	passert(prf_desc->nss.mechanism > 0);
	/* lame, screwed up old compilers what this */
	SECItem ignore = {
		.len = 0,
	};
	PK11Context *context = PK11_CreateContextBySymKey(prf_desc->nss.mechanism,
							  CKA_SIGN,
							  key, &ignore);
	if (context == NULL) {
		LSWLOG(buf) {
			lswlogf(buf, "NSS: %s create %s context from key %s(%p) failed",
				name, prf_desc->common.name,
				key_name, key);
			lswlog_nss_error(buf);
		}
		return NULL;
	}
	DBGF(DBG_CRYPT_LOW, "%s prf: created %s context %p from %s-key@%p",
	     name, prf_desc->common.name,
	     context, key_name, key);

	SECStatus rc = PK11_DigestBegin(context);
	if (rc) {
		libreswan_log("NSS: %s digest begin failed for %s (%x)\n",
			      name, prf_desc->common.name, rc);
		PK11_DestroyContext(context, PR_TRUE);
		return NULL;
	}
	DBGF(DBG_CRYPT_LOW, "%s prf: begin %s with context %p from %s-key@%p",
	     name, prf_desc->common.name,
	     context, key_name, key);

	struct prf_context *prf = alloc_thing(struct prf_context, name);
	*prf = (struct prf_context) {
		.name = name,
		.desc = prf_desc,
		.context = context,
	};
	return prf;
}

static struct prf_context *init_symkey(const struct prf_desc *prf_desc,
				       const char *name,
				       const char *key_name, PK11SymKey *key)
{
	/*
	 * Need a key of the correct type.
	 *
	 * This key has both the mechanism and flags set.
	 */
	PK11SymKey *clone = prf_key_from_symkey_bytes("clone", prf_desc,
						      0, sizeof_symkey(key),
						      key);
	struct prf_context *prf = init(prf_desc, name,
				       key_name, clone);
	release_symkey(name, "clone", &clone);
	return prf;
}

static struct prf_context *init_bytes(const struct prf_desc *prf_desc,
				      const char *name,
				      const char *key_name,
				      const u_int8_t *key, size_t sizeof_key)
{
	/*
	 * Need a key of the correct type.
	 *
	 * This key has both the mechanism and flags set.
	 */
	PK11SymKey *clone = prf_key_from_bytes(key_name, prf_desc,
					       key, sizeof_key);
	struct prf_context *prf = init(prf_desc, name,
				       key_name, clone);
	release_symkey(name, "clone", &clone);
	return prf ;
}

/*
 * Accumulate data.
 */

static void digest_symkey(struct prf_context *prf,
			  const char *symkey_name UNUSED, PK11SymKey *symkey)
{
	/*
	 * Feed the key's raw bytes to the digest function.  NSS's
	 * PK11_DigestKey() doesn't work with HMAC (only simple MAC),
	 * and there is no NSS HMAC Derive mechansism.
	 */
#if 0
	SECStatus rc = PK11_DigestKey(prf->context, symkey);
	fprintf(stderr, "symkey update %x\n", rc);
#endif
	chunk_t chunk = chunk_from_symkey("nss hmac digest hack", symkey);
	SECStatus rc = PK11_DigestOp(prf->context, chunk.ptr, chunk.len);
	freeanychunk(chunk);
	passert(rc == SECSuccess);
}

static void digest_bytes(struct prf_context *prf, const char *name UNUSED,
			 const u_int8_t *bytes, size_t sizeof_bytes)
{
	SECStatus rc = PK11_DigestOp(prf->context, bytes, sizeof_bytes);
	passert(rc == SECSuccess);
}

static void final(struct prf_context *prf, void *bytes, size_t sizeof_bytes)
{
	unsigned bytes_out;
	SECStatus rc = PK11_DigestFinal(prf->context, bytes,
					&bytes_out, sizeof_bytes);
	passert(rc == SECSuccess);
	pexpect(bytes_out == sizeof_bytes);
	PK11_DestroyContext(prf->context, PR_TRUE);
	prf->context = NULL;
}

static void final_bytes(struct prf_context **prf, u_int8_t *bytes, size_t sizeof_bytes)
{
	final(*prf, bytes, sizeof_bytes);
	pfree(*prf);
	*prf = NULL;
}

static PK11SymKey *final_symkey(struct prf_context **prf)
{
	size_t sizeof_bytes = (*prf)->desc->prf_output_size;
	u_int8_t *bytes = alloc_things(u_int8_t, sizeof_bytes, "bytes");
	final(*prf, bytes, sizeof_bytes);
	PK11SymKey *final = symkey_from_bytes("final", bytes, sizeof_bytes);
	pfree(bytes);
	pfree(*prf); *prf = NULL;
	return final;
}

static void nss_prf_check(const struct prf_desc *prf)
{
	const struct ike_alg *alg = &prf->common;
	passert_ike_alg(alg, prf->nss.mechanism > 0);
}

const struct prf_ops ike_alg_prf_nss_ops = {
	nss_prf_check,
	init_symkey,
	init_bytes,
	digest_symkey,
	digest_bytes,
	final_symkey,
	final_bytes,
};
