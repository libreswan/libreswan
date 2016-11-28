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

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_nss_prf_ops.h"
#include "crypt_symkey.h"

struct prf_context {
	const char *name;
	lset_t debug;
	const struct prf_desc *desc;
	PK11Context *context;
};

/*
 * Create a PRF ready to consume data.
 */

static struct prf_context *init(const struct prf_desc *prf_desc,
				const char *name, lset_t debug,
				const char *key_name, PK11SymKey *key)

{
	passert(prf_desc->common.nss_mechanism > 0);
	/* lame, screwed up old compilers what this */
	SECItem ignore = {
		.len = 0,
	};
	PK11Context *context = PK11_CreateContextBySymKey(prf_desc->common.nss_mechanism,
							  CKA_SIGN,
							  key, &ignore);
	if (context == NULL) {
		libreswan_log("NSS: %s create %s context from key %s(%p) failed (%x)\n",
			      name, prf_desc->common.name,
			      key_name, key,
			      PR_GetError());
		return NULL;
	}
	if (DBGP(debug)) {
		DBG_log("%s prf: created %s context %p from key %s(%p)",
			name, prf_desc->common.name,
			context, key_name, key);
	}

	SECStatus rc = PK11_DigestBegin(context);
	if (rc) {
		libreswan_log("NSS: %s digest begin failed for %s (%x)\n",
			      name, prf_desc->common.name, rc);
		PK11_DestroyContext(context, PR_TRUE);
		return NULL;
	}
	if (DBGP(debug)) {
		DBG_log("%s prf: begin %s with context %p from key %s(%p)",
			name, prf_desc->common.name,
			context,
			key_name, key);
	}

	struct prf_context *prf = alloc_thing(struct prf_context, name);
	*prf = (struct prf_context) {
		.debug = debug,
		.name = name,
		.desc = prf_desc,
		.context = context,
	};
	DBG(DBG_CRYPT, DBG_log("%s prf %s: init %p",
			       name, prf_desc->common.name, prf));
	return prf;
}

static struct prf_context *init_symkey(const struct prf_desc *prf_desc,
				       const char *name, lset_t debug,
				       const char *key_name, PK11SymKey *key)
{
	/*
	 * Need a key of the correct type.
	 *
	 * This key has both the mechanism and flags set.
	 */
	PK11SymKey *clone = symkey_from_symkey_bytes("clone", debug,
						     &prf_desc->common,
						     0, sizeof_symkey(key),
						     key);
	struct prf_context *prf = init(prf_desc, name, debug,
				       key_name, clone);
	free_any_symkey("clone", &clone);
	return prf;
}

static struct prf_context *init_bytes(const struct prf_desc *prf_desc,
				      const char *name, lset_t debug,
				      const char *key_name,
				      const u_int8_t *key, size_t sizeof_key)
{
	/*
	 * Need a key of the correct type.
	 *
	 * This key has both the mechanism and flags set.
	 */
	PK11SymKey *clone = symkey_from_bytes(key_name, DBG_CRYPT,
					      &prf_desc->common,
					      key, sizeof_key);
	struct prf_context *prf = init(prf_desc, name, debug,
				       key_name, clone);
	free_any_symkey("clone", &clone);
	return prf ;
}

/*
 * Accumulate data.
 */

static void digest_symkey(struct prf_context *prf,
			  const char *symkey_name, PK11SymKey *symkey)
{
	if (DBGP(prf->debug)) {
		DBG_log("%s prf: update symkey %s %p (size %zd)",
			prf->name, symkey_name, symkey,
			sizeof_symkey(symkey));
	}
#if 0
	/*
	 * PK11_DigestKey() is not supported with HMAC.
	 */
	SECStatus rc = PK11_DigestKey(prf->context, symkey);
	fprintf(stderr, "symkey update %x\n", rc);
#endif
	chunk_t chunk = chunk_from_symkey("hack", prf->debug,
					  symkey);
	SECStatus rc = PK11_DigestOp(prf->context, chunk.ptr, chunk.len);
	passert(rc == SECSuccess);
}

static void digest_bytes(struct prf_context *prf,
			 const char *name, const u_int8_t *bytes, size_t sizeof_bytes)
{
	if (DBGP(prf->debug)) {
		DBG_log("%s prf: update bytes %s %p (length %zd)",
			prf->name, name, bytes, sizeof_bytes);
	}
	SECStatus rc = PK11_DigestOp(prf->context, bytes, sizeof_bytes);
	passert(rc == SECSuccess);
}

static void final(struct prf_context *prf, void *bytes, size_t sizeof_bytes)
{
	if (DBGP(prf->debug)) {
		DBG_log("%s prf: final %p (length %zd)",
			prf->name, bytes, sizeof_bytes);
	}
	unsigned bytes_out;
	SECStatus rc = PK11_DigestFinal(prf->context, bytes,
					&bytes_out, sizeof_bytes);
	passert(rc == SECSuccess);
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
	PK11SymKey *final = symkey_from_bytes("final", (*prf)->debug, NULL,
					      bytes, sizeof_bytes);
	pfree(bytes);
	pfree(*prf); *prf = NULL;
	return final;
}

const struct prf_ops ike_alg_nss_prf_ops = {
	init_symkey,
	init_bytes,
	digest_symkey,
	digest_bytes,
	final_symkey,
	final_bytes,
};
