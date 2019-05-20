/*
 * PRF helper functions, for libreswan
 *
 * Copyright (C) 2007-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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

//#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "crypto.h"

size_t crypt_prf_fips_key_size_min(const struct prf_desc *prf)
{
	/*
	 * FIPS 198 Section 3 CRYPTOGRAPHIC KEYS requires keys to be
	 * >= "L/2" (where L is the block-size in bytes of the hash
	 * function).
	 *
	 * FIPS 198-1 Section 3 instead cites SP 800-107 which dictates
	 * requirements in Section 5.4.3
	 */
	return prf->prf_key_size / 2;
}

size_t crypt_prf_fips_key_size_floor(void)
{
	static size_t key_size_floor = 0;
	if (key_size_floor == 0) {
		key_size_floor = SIZE_MAX;
		for (const struct prf_desc **prfp = next_prf_desc(NULL);
		     prfp != NULL; prfp = next_prf_desc(prfp)) {
			if ((*prfp)->common.fips) {
				key_size_floor = min(key_size_floor,
					     crypt_prf_fips_key_size_min(*prfp));
			}
		}
	}
	return key_size_floor;
}

struct crypt_prf {
	struct prf_context *context;
	const char *name;
	const struct prf_desc *desc;
};

static struct crypt_prf *wrap(const struct prf_desc *prf_desc,
			      const char *name,
			      struct prf_context *context)
{
	struct crypt_prf *prf = NULL;
	if (context != NULL) {
		prf = alloc_thing(struct crypt_prf, name);
		*prf = (struct crypt_prf) {
			.context = context,
			.name = name,
			.desc = prf_desc,
		};
	}
	DBGF(DBG_CRYPT, "%s PRF %s crypt-prf@%p",
	     name, prf_desc->common.name, prf);
	return prf;
}

struct crypt_prf *crypt_prf_init_chunk(const char *name,
				       const struct prf_desc *prf_desc,
				       const char *chunk_name, chunk_t chunk)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s init %s-chunk@%p (length %zd)",
			name, prf_desc->common.name,
			chunk_name, chunk.ptr, chunk.len);
		DBG_dump_chunk(NULL, chunk);
	}
	return wrap(prf_desc, name,
		    prf_desc->prf_ops->init_bytes(prf_desc, name,
						  chunk_name, chunk.ptr, chunk.len));
}

struct crypt_prf *crypt_prf_init_symkey(const char *name,
					const struct prf_desc *prf_desc,
					const char *key_name, PK11SymKey *key)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s init %s-key@%p (size %zd)",
			name, prf_desc->common.name,
			key_name, key, sizeof_symkey(key));
		DBG_symkey(name, key_name, key);
	}
	return wrap(prf_desc, name,
		    prf_desc->prf_ops->init_symkey(prf_desc, name,
						   key_name, key));
}

/*
 * Accumulate data.
 */

void crypt_prf_update_chunk(struct crypt_prf *prf,
			    const char *name, chunk_t update)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s update %s-chunk@%p (length %zd)",
			prf->name, prf->desc->common.name,
			name, update.ptr, update.len);
		DBG_dump_chunk(NULL, update);
	}
	prf->desc->prf_ops->digest_bytes(prf->context, name, update.ptr, update.len);
}

void crypt_prf_update_symkey(struct crypt_prf *prf,
			     const char *name, PK11SymKey *update)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s update %s-key@%p (size %zd)",
			prf->name, prf->desc->common.name,
			name, update, sizeof_symkey(update));
		DBG_symkey(prf->name, name, update);
	}
	prf->desc->prf_ops->digest_symkey(prf->context, name, update);
}

void crypt_prf_update_byte(struct crypt_prf *prf,
			   const char *name, uint8_t update)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s update %s-byte@0x%x (%u)",
			prf->name, prf->desc->common.name,
			name, update, update);
		DBG_dump(NULL, &update, sizeof(update));
	}
	prf->desc->prf_ops->digest_bytes(prf->context, name, &update, 1);
}

void crypt_prf_update_bytes(struct crypt_prf *prf,
			    const char *name, const void *update, size_t sizeof_update)
{
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s update %s-bytes@%p (length %zd)",
			prf->name, prf->desc->common.name,
			name, update, sizeof_update);
		DBG_dump(NULL, update, sizeof_update);
	}
	prf->desc->prf_ops->digest_bytes(prf->context, name, update, sizeof_update);
}

PK11SymKey *crypt_prf_final_symkey(struct crypt_prf **prfp)
{
	struct crypt_prf *prf = *prfp;
	PK11SymKey *tmp = prf->desc->prf_ops->final_symkey(&prf->context);
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s final-key@%p (size %zu)",
			(*prfp)->name, (*prfp)->desc->common.name,
			tmp, sizeof_symkey(tmp));
		DBG_symkey((*prfp)->name, "key", tmp);
	}
	pfree(*prfp);
	*prfp = prf = NULL;
	return tmp;
}

void crypt_prf_final_bytes(struct crypt_prf **prfp,
			   void *bytes, size_t sizeof_bytes)
{
	struct crypt_prf *prf = *prfp;
	prf->desc->prf_ops->final_bytes(&prf->context, bytes, sizeof_bytes);
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s final-bytes@%p (length %zu)",
			(*prfp)->name, (*prfp)->desc->common.name,
			bytes, sizeof_bytes);
		DBG_dump(NULL, bytes, sizeof_bytes);
	}
	pfree(*prfp);
	*prfp = prf = NULL;
}

chunk_t crypt_prf_final_chunk(struct crypt_prf **prfp)
{
	struct crypt_prf *prf = *prfp;
	chunk_t chunk = alloc_chunk(prf->desc->prf_output_size, prf->name);
	prf->desc->prf_ops->final_bytes(&prf->context, chunk.ptr, chunk.len);
	if (DBGP(DBG_CRYPT)) {
		DBG_log("%s PRF %s final-chunk@%p (length %zu)",
			(*prfp)->name, (*prfp)->desc->common.name,
			chunk.ptr, chunk.len);
		DBG_dump_chunk(NULL, chunk);
	}
	pfree(*prfp);
	*prfp = prf = NULL;
	return chunk;
}
