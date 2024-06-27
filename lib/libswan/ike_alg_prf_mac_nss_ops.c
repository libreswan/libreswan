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

#include <stdio.h>
#include <stdlib.h>

#include <prmem.h>
#include <prerror.h>


#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_prf_mac_ops.h"
#include "crypt_symkey.h"

struct prf_context {
	const char *name;
	const struct prf_desc *desc;
	PK11Context *context;
	struct logger *logger;
};

/*
 * Create a PRF ready to consume data.
 */

static struct prf_context *init(const struct prf_desc *prf_desc,
				const char *name,
				const char *key_name, PK11SymKey *key,
				struct logger *logger)

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
		pexpect_nss_error(logger, HERE,
				  "%s create %s context from key %s(%p) failed ",
				  name, prf_desc->common.fqn,
				  key_name, key);
		return NULL;
	}
	ldbgf(DBG_CRYPT, logger,
	      "%s prf: created %s context %p from %s-key@%p",
	      name, prf_desc->common.fqn,
	      context, key_name, key);

	SECStatus rc = PK11_DigestBegin(context);
	if (rc) {
		pexpect_nss_error(logger, HERE, "%s digest begin failed for %s (%x)\n",
				  name, prf_desc->common.fqn, rc);
		PK11_DestroyContext(context, PR_TRUE);
		return NULL;
	}
	ldbgf(DBG_CRYPT, logger,
	      "%s prf: begin %s with context %p from %s-key@%p",
	      name, prf_desc->common.fqn,
	      context, key_name, key);

	struct prf_context prf = {
		.name = name,
		.desc = prf_desc,
		.context = context,
		.logger = logger,
	};
	return clone_thing(prf, name);
}

static struct prf_context *init_symkey(const struct prf_desc *prf_desc,
				       const char *name,
				       const char *key_name, PK11SymKey *key,
				       struct logger *logger)
{
	/*
	 * Need a key of the correct type.
	 *
	 * This key has both the mechanism and flags set.
	 */
	PK11SymKey *clone = prf_key_from_symkey_bytes("clone", prf_desc,
						      0, sizeof_symkey(key),
						      key, HERE, logger);
	struct prf_context *prf = init(prf_desc, name, key_name, clone, logger);
	symkey_delref(prf->logger, "clone", &clone);
	return prf;
}

static struct prf_context *init_bytes(const struct prf_desc *prf_desc,
				      const char *name,
				      const char *key_name,
				      const uint8_t *key, size_t sizeof_key,
				      struct logger *logger)
{
	/*
	 * Need a key of the correct type.
	 *
	 * This key has both the mechanism and flags set.
	 */
	PK11SymKey *clone = prf_key_from_bytes(key_name, prf_desc,
					       key, sizeof_key, HERE, logger);
	struct prf_context *prf = init(prf_desc, name, key_name, clone, logger);
	symkey_delref(prf->logger, "clone", &clone);
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
	chunk_t chunk = chunk_from_symkey("nss hmac digest hack", symkey,
					  prf->logger);
	SECStatus rc = PK11_DigestOp(prf->context, chunk.ptr, chunk.len);
	free_chunk_content(&chunk);
	passert(rc == SECSuccess);
}

static void digest_bytes(struct prf_context *prf, const char *name UNUSED,
			 const uint8_t *bytes, size_t sizeof_bytes)
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

static void final_bytes(struct prf_context **prf, uint8_t *bytes, size_t sizeof_bytes)
{
	final(*prf, bytes, sizeof_bytes);
	pfree(*prf);
	*prf = NULL;
}

static PK11SymKey *final_symkey(struct prf_context **prf)
{
	size_t sizeof_bytes = (*prf)->desc->prf_output_size;
	uint8_t *bytes = alloc_things(uint8_t, sizeof_bytes, "bytes");
	final(*prf, bytes, sizeof_bytes);
	PK11SymKey *final = symkey_from_bytes("final", bytes, sizeof_bytes,
					      (*prf)->logger);
	pfree(bytes);
	pfree(*prf); *prf = NULL;
	return final;
}

static void nss_prf_check(const struct prf_desc *prf, struct logger *logger)
{
	const struct ike_alg *alg = &prf->common;
	pexpect_ike_alg(logger, alg, prf->nss.mechanism > 0);
}

const struct prf_mac_ops ike_alg_prf_mac_nss_ops = {
	"NSS",
	nss_prf_check,
	init_symkey,
	init_bytes,
	digest_symkey,
	digest_bytes,
	final_symkey,
	final_bytes,
};
