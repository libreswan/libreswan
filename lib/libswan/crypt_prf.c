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

#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "ike_alg_prf_mac_ops.h"

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
			if ((*prfp)->common.fips.approved) {
				key_size_floor = min(key_size_floor,
					     crypt_prf_fips_key_size_min(*prfp));
			}
		}
	}
	return key_size_floor;
}

struct crypt_prf {
	struct prf_context *context;
	const char *prf_name;
	const char *key_name;
	const struct prf_desc *desc;
	struct logger *logger;
};

PRINTF_LIKE(2)
static bool ldbg_prf(const struct crypt_prf *prf, const char *msg, ...)
{
	if (!LDBGP(DBG_CRYPT, prf->logger)) {
		return false;
	}
	LLOG_JAMBUF(DEBUG_STREAM, prf->logger, buf) {
		jam_string(buf, prf->prf_name);
		jam_string(buf, " ");
		jam_string(buf, prf->desc->common.fqn);
		jam_string(buf, " PRF(");
		jam_string(buf, prf->key_name);
		jam_string(buf, ")");
		if (prf->context != NULL) {
			jam(buf, " at %p", prf->context);
		}
		jam_string(buf, ": ");
		va_list ap;
		va_start(ap, msg);
		jam_va_list(buf, msg, ap);
		va_end(ap);
	}
	return true;
}

static struct crypt_prf *wrap(const char *prf_name,
			      const struct prf_desc *prf_desc,
			      const char *key_name,
			      struct logger *logger,
			      struct prf_context *context)
{
	if (context == NULL) {
		return NULL;
	}

	struct crypt_prf *prf = alloc_thing(struct crypt_prf, prf_name);
	prf->context = context;
	prf->prf_name = prf_name;
	prf->key_name = key_name;
	prf->desc = prf_desc;
	prf->logger = logger;
	return prf;
}

struct crypt_prf *crypt_prf_init_bytes(const char *prf_name,
				       const struct prf_desc *prf_desc,
				       const char *key_name,
				       const void *key, size_t key_size,
				       struct logger *logger)
{
	struct crypt_prf *prf = wrap(prf_name, prf_desc, key_name, logger,
				     prf_desc->prf_mac_ops->init_bytes(prf_desc, prf_name,
								       key_name, key, key_size,
								       logger));
	if (prf == NULL) {
		return NULL;
	}
	if (ldbg_prf(prf, "init hunk %p (length %zd)", key, key_size)) {
		LDBG_dump(logger, key, key_size);
	}
	return prf;
}

struct crypt_prf *crypt_prf_init_symkey(const char *prf_name,
					const struct prf_desc *prf_desc,
					const char *key_name, PK11SymKey *key,
					struct logger *logger)
{
	struct crypt_prf *prf = wrap(prf_name, prf_desc, key_name, logger,
				     prf_desc->prf_mac_ops->init_symkey(prf_desc, prf_name,
									key_name, key,
									logger));
	if (ldbg_prf(prf, "init symkey %p (length %zd)", key, sizeof_symkey(key))) {
		LDBG_symkey(logger, prf_name, key_name, key);
	}
	return prf;
}

/*
 * Accumulate data.
 */

void crypt_prf_update_symkey(struct crypt_prf *prf,
			     const char *update_name, PK11SymKey *update)
{
	if (ldbg_prf(prf, "update symkey %s@%p (size %zd)",
		     update_name, update, sizeof_symkey(update))) {
		LDBG_symkey(prf->logger, prf->prf_name, update_name, update);
	}
	prf->desc->prf_mac_ops->digest_symkey(prf->context, update_name, update);
}

void crypt_prf_update_byte(struct crypt_prf *prf,
			   const char *update_name, uint8_t update)
{
	if (ldbg_prf(prf, "update byte %s 0x%"PRIx8" (%"PRIu8")",
		     update_name, update, update)) {
		LDBG_thing(prf->logger, update);
	}
	prf->desc->prf_mac_ops->digest_bytes(prf->context, update_name, &update, 1);
}

void crypt_prf_update_bytes(struct crypt_prf *prf,
			    const char *update_name, const void *update, size_t sizeof_update)
{
		/*
		 * XXX: don't log UPDATE using @POINTER syntax as it
		 * might be bogus - confusing refcnt.awk.
		 */
	if (ldbg_prf(prf, "update hunk %s at %p (size %zu)",
		     update_name, update, sizeof_update)) {
		LDBG_dump(prf->logger, update, sizeof_update);
	}
	prf->desc->prf_mac_ops->digest_bytes(prf->context, update_name, update, sizeof_update);
}

PK11SymKey *crypt_prf_final_symkey(struct crypt_prf **prfp)
{
	struct crypt_prf *prf = *prfp;
	struct logger *logger = (*prfp)->logger;
	PK11SymKey *tmp = prf->desc->prf_mac_ops->final_symkey(&prf->context);
	if (ldbg_prf(prf, "final key@%p (size %zu)",
		     tmp, sizeof_symkey(tmp))) {
		LDBG_symkey(logger, prf->prf_name, "key", tmp);
	}
	pfree(*prfp);
	*prfp = prf = NULL;
	return tmp;
}

void crypt_prf_final_bytes(struct crypt_prf **prfp,
			   void *bytes, size_t sizeof_bytes)
{
	struct crypt_prf *prf = *prfp;
	prf->desc->prf_mac_ops->final_bytes(&prf->context, bytes, sizeof_bytes);
	if (ldbg_prf(prf, "final bytes@%p (length %zu)",
		     bytes, sizeof_bytes)) {
		LDBG_dump(prf->logger, bytes, sizeof_bytes);
	}
	pfree(*prfp);
	*prfp = prf = NULL;
}

struct crypt_mac crypt_prf_final_mac(struct crypt_prf **prfp, const struct integ_desc *integ)
{
	struct crypt_prf *prf = *prfp;
	/* get the MAC's length, INTEG trumps PRF */
	struct crypt_mac output;
	if (integ != NULL) {
		/* integ derived from prf */
		passert(integ->prf == prf->desc);
		/* truncating */
		passert(integ->integ_output_size <= prf->desc->prf_output_size);
		output = (struct crypt_mac) { .len = integ->integ_output_size, };
	} else {
		output = (struct crypt_mac) { .len = prf->desc->prf_output_size, };
	}
	/* extract it, note that PRF's size must be passed in */
	passert(prf->desc->prf_output_size <= sizeof(output.ptr/*array*/));
	prf->desc->prf_mac_ops->final_bytes(&prf->context, output.ptr,
					    prf->desc->prf_output_size);
	if (ldbg_prf(prf, "final mac length %zu", output.len)) {
		LDBG_hunk(prf->logger, output);
	}
	/* clean up */
	pfree(*prfp);
	*prfp = prf = NULL;
	return output;
}

/*
 * Extract SIZEOF_SYMKEY bytes of keying material as a PRF key.
 *
 * Offset into the SYMKEY is in BYTES.
 */

PK11SymKey *prf_key_from_symkey_bytes(const char *name,
				      const struct prf_desc *prf,
				      size_t symkey_start_byte, size_t sizeof_symkey,
				      PK11SymKey *source_key,
				      where_t where, struct logger *logger)
{
	/*
	 * NSS expects a key's mechanism to match the NSS algorithm
	 * the key is intended for.  If this is wrong then the
	 * operation fails.
	 *
	 * Unfortunately, some algorithms are not implemented by NSS,
	 * so the correct key type can't always be specified.  For
	 * those specify CKM_VENDOR_DEFINED.
	 *
	 * XXX: this function should be part of prf_ops.
	 */
	CK_FLAGS flags;
	CK_MECHANISM_TYPE mechanism;
	if (prf->prf_mac_ops->bespoke) {
		flags = 0;
		mechanism = CKM_VENDOR_DEFINED;
	} else {
		flags = CKF_SIGN;
		mechanism = prf->nss.mechanism;
	}
	return symkey_from_symkey(name, source_key, mechanism, flags,
				  symkey_start_byte, sizeof_symkey,
				  where, logger);
}
