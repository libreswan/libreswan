/*
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

#include "chunk.h"
#include "lswlog.h"
#include "lswalloc.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_prf_mac_ops.h"
#include "crypt_symkey.h"
#include "crypt_prf.h"
#include "lswnss.h"

struct prf_context {
	const char *name;
	const struct prf_desc *desc;
	PK11SymKey *key;
	chunk_t bytes;
	struct logger *logger;
};

static struct crypt_mac xcbc_mac(const struct prf_desc *prf, PK11SymKey *key,
				 shunk_t bytes, struct logger *logger);

static PK11SymKey *xcbc_key_from_mac(const struct prf_desc *prf,
				     const char *key_name, const struct crypt_mac *mac,
				     struct logger *logger)
{
	PASSERT(logger, mac->len == prf->prf_key_size);
	PK11SymKey *draft_key = symkey_from_bytes("draft-key", mac->ptr, mac->len, logger);
	PK11SymKey *key = symkey_from_symkey(key_name, draft_key,
					     prf->nss.mechanism, CKF_SIGN,
					     0, prf->prf_key_size,
					     HERE, logger);
	symkey_delref(logger, "draft-key", &draft_key);
	return key;
}

static PK11SymKey *xcbc_prf_key_from_bytes(const struct prf_desc *prf,
					   const char *key_name, const void *key_ptr, size_t key_len,
					   struct logger *logger)
{
	/*
	 * Build a key of the correct size.
	 */
	struct crypt_mac raw_key = { .len = prf->prf_key_size, };

	if (key_len <= prf->prf_key_size) {
		/*
		 * The key is too small, pad it to size with zeroes.
		 */
		ldbgf(DBG_CRYPT, logger, "%s() key %s %zd<%zd, padding with zeros",
		      __func__, key_name, key_len, prf->prf_key_size);
		memcpy(raw_key.ptr/*array*/, key_ptr, key_len);
	} else {
		ldbgf(DBG_CRYPT, logger, "%s() key %s %zd>%zd is too big, rehashing to size",
		      __func__, key_name, key_len, prf->prf_key_size);
		/*
		 * The key is too big, hash it down to size using the
		 * HASH that the PRF's HMAC is built from.
		 *
		 * XXX: XCBC needs the zero key used to do the hashing
		 * to have the correct mechanism and flags (usage).
		 */
		struct crypt_mac zero_mac = { .len = prf->prf_key_size, };
		PK11SymKey *zeros = xcbc_key_from_mac(prf, "raw-zeros",
						      &zero_mac, logger);
		raw_key = xcbc_mac(prf, zeros, shunk2(key_ptr, key_len), logger);
		symkey_delref(logger, "raw-zeros", &zeros);
	}

	return xcbc_key_from_mac(prf, key_name, &raw_key, logger);
}

static void encrypt(const char *name,
		    struct crypt_mac *out, const struct crypt_mac *in,
		    const struct prf_desc *prf, PK11SymKey *key,
		    struct logger *logger)
{
	unsigned int out_size = 0;
	SECStatus status = PK11_Encrypt(key, prf->nss.mechanism, NULL,
					out->ptr, &out_size, in->len,
					in->ptr, in->len);
	if (status != SECSuccess) {
		passert_nss_error(logger, HERE, "encryption %s failed: ", name);
	}
	PASSERT(logger, out_size == in->len);
	out->len = in->len;
}

static struct crypt_mac derive_ki(const struct prf_desc *prf,
				  PK11SymKey *key, int ki,
				  struct logger *logger)
{
	struct crypt_mac in = { .len = prf->prf_key_size, };
	for (unsigned i = 0; i < prf->prf_key_size; i++) {
		in.ptr[i] = ki;
	}
	struct crypt_mac out;
	encrypt("K([123])", &out, &in, prf, key, logger);
	return out;
}

static struct crypt_mac xcbc_mac(const struct prf_desc *prf, PK11SymKey *key,
				 shunk_t bytes, struct logger *logger)
{
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "XCBC: data:");
		LDBG_hunk(logger, bytes);
		chunk_t k = chunk_from_symkey("K", key, logger);
		LDBG_log(logger, "XCBC: K:");
		LDBG_hunk(logger, k);
		free_chunk_content(&k);
	}

	struct crypt_mac k1t = derive_ki(prf, key, 1, logger);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "XCBC: K1:");
		LDBG_hunk(logger, k1t);
	}
	PK11SymKey *k1 = xcbc_key_from_mac(prf, "k1", &k1t, logger);

	/*
	 * (2)  Define E[0] = 0x00000000000000000000000000000000
	 */
	struct crypt_mac e = { .len = prf->prf_key_size, };

	/*
	 * (3)  For each block M[i], where i = 1 ... n-1:
	 *      XOR M[i] with E[i-1], then encrypt the result with Key K1,
	 *      yielding E[i].
	 */
	int n = (bytes.len + prf->prf_key_size - 1) / prf->prf_key_size;
	shunk_t m = shunk2(bytes.ptr, prf->prf_key_size);
	for (int i = 1; i <= n - 1; i++) {
		struct crypt_mac t = { .len = prf->prf_key_size, };
		for (unsigned j = 0; j < prf->prf_key_size; j++) {
			const uint8_t *m_ptr = m.ptr;
			t.ptr[j] = m_ptr[j] ^ e.ptr[j];
		}
		encrypt("XCBC: K1(M[i]^E[i-1])", &e, &t, prf, k1, logger);
		m.ptr += prf->prf_key_size;
	}

	/*
	 * (4)  For block M[n]:
	 *
	 *   NOTE1: If M is the empty string, pad and encrypt as in (4)(b) to
	 *   create M[1] and E[1].  This will never be the case for ESP or AH, but
	 *   is included for completeness sake.
	 */
	m.len = bytes.ptr + bytes.len - m.ptr;
	if (m.len == prf->prf_key_size) {
		struct crypt_mac k2 = derive_ki(prf, key, 2, logger);
		if (LDBGP(DBG_CRYPT, logger)) {
			LDBG_log(logger, "XCBC: Computing E[%d] using K2", n);
			LDBG_log(logger, "XCBC: K2:"); LDBG_hunk(logger, k2);
			LDBG_log(logger, "XCBC: E[n-1]"); LDBG_hunk(logger, e);
			LDBG_log(logger, "XCBC: M[n]:"); LDBG_hunk(logger, m);
		}
		/*
		 *      a)  If the blocksize of M[n] is 128 bits:
		 *          XOR M[n] with E[n-1] and Key K2, then encrypt the result with
		 *          Key K1, yielding E[n].
		 */
		struct crypt_mac t = { .len = prf->prf_key_size, };
		for (unsigned j = 0; j < prf->prf_key_size; j++) {
			const uint8_t *m_ptr = m.ptr;
			t.ptr[j] = m_ptr[j] ^ e.ptr[j] ^ k2.ptr[j];
		}
		if (LDBGP(DBG_CRYPT, logger)) {
			LDBG_log(logger, "XCBC: M[n]^E[n-1]^K2:"); LDBG_hunk(logger, t);
		}
		encrypt("K1(M[n]^E[n-1]^K2)", &e, &t, prf, k1, logger);
	} else {
		struct crypt_mac k3 = derive_ki(prf, key, 3, logger);
		if (LDBGP(DBG_CRYPT, logger)) {
			LDBG_log(logger, "Computing E[%d] using K3", n);
			LDBG_log(logger, "XCBC: K3"); LDBG_hunk(logger, k3);
			LDBG_log(logger, "XCBC: E[n-1]:"); LDBG_hunk(logger, e);
			LDBG_log(logger, "XCBC: M[n]:"); LDBG_hunk(logger, m);
		}
		/*
		 *      b)  If the blocksize of M[n] is less than 128 bits:
		 *
		 *         i)  Pad M[n] with a single "1" bit, followed by the number of
		 *             "0" bits (possibly none) required to increase M[n]'s
		 *             blocksize to 128 bits.
		 *         ii) XOR M[n] with E[n-1] and Key K3, then encrypt the result
		 *             with Key K1, yielding E[n].
		 */
		unsigned j = 0;
		struct crypt_mac t = { .len = prf->prf_key_size, };
		for (; j < m.len; j++) {
			const uint8_t *m_ptr = m.ptr;
			t.ptr[j] = m_ptr[j] ^ e.ptr[j] ^ k3.ptr[j];
		}
		t.ptr[j] = 0x80 ^ e.ptr[j] ^ k3.ptr[j];
		j++;
		for (; j < prf->prf_key_size; j++) {
			t.ptr[j] = 0x00 ^ e.ptr[j] ^ k3.ptr[j];
		}
		if (LDBGP(DBG_CRYPT, logger)) {
			LDBG_log(logger, "XCBC: M[n]:"); LDBG_hunk(logger, m);
			LDBG_log(logger, "XCBC: M[n]:80...^E[n-1]^K3:"); LDBG_hunk(logger, t);
		}
		encrypt("K1(M[n]^E[n-1]^K2)", &e, &t, prf, k1, logger);
	}

	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "XCBC: MAC:");
		LDBG_hunk(logger, e);
	}

	symkey_delref(logger, "k1", &k1);
	return e;
}

/*
 * Create a PRF ready to consume data.
 */

static struct prf_context *nss_xcbc_init_bytes(const struct prf_desc *prf_desc,
					       const char *name,
					       const char *key_name, const uint8_t *key_ptr, size_t key_len,
					       struct logger *logger)
{
	/*
	 * Need a key of the correct type and size.
	 *
	 * This key has both the mechanism and flags set.
	 */
	struct prf_context context = {
		.key = xcbc_prf_key_from_bytes(prf_desc,
					       key_name, key_ptr, key_len,
					       logger),
		.name = name,
		.desc = prf_desc,
		.logger = logger,
	};
	return clone_thing(context, name);
}

static struct prf_context *nss_xcbc_init_symkey(const struct prf_desc *prf_desc,
						const char *name,
						const char *key_name, PK11SymKey *key,
						struct logger *logger)
{
	/* Don't assume the key is the correct size. */
	chunk_t raw_key = chunk_from_symkey(key_name, key, logger);
	struct prf_context *context = nss_xcbc_init_bytes(prf_desc, name,
							  key_name, raw_key.ptr, raw_key.len,
							  logger);
	free_chunk_content(&raw_key);
	return context;
}

/*
 * Accumulate data.
 */

static void nss_xcbc_digest_symkey(struct prf_context *prf,
				  const char *symkey_name, PK11SymKey *symkey)
{
	chunk_t symkey_chunk = chunk_from_symkey(symkey_name, symkey, prf->logger);
	append_chunk_hunk(symkey_name, &prf->bytes, symkey_chunk);
	free_chunk_content(&symkey_chunk);
}

static void nss_xcbc_digest_bytes(struct prf_context *prf, const char *name,
				  const uint8_t *bytes, size_t sizeof_bytes)
{
	append_chunk_bytes(name, &prf->bytes, bytes, sizeof_bytes);
}

static void nss_xcbc_final_bytes(struct prf_context **prf,
				 uint8_t *bytes, size_t sizeof_bytes)
{
	struct crypt_mac mac = xcbc_mac((*prf)->desc, (*prf)->key,
					HUNK_AS_SHUNK((*prf)->bytes),
					(*prf)->logger);
	memcpy(bytes, mac.ptr, sizeof_bytes);
	free_chunk_content(&(*prf)->bytes);
	symkey_delref((*prf)->logger, "key", &(*prf)->key);
	pfree(*prf);
}

static PK11SymKey *nss_xcbc_final_symkey(struct prf_context **prf)
{
	struct crypt_mac mac = xcbc_mac((*prf)->desc, (*prf)->key,
					HUNK_AS_SHUNK((*prf)->bytes),
					(*prf)->logger);
	PK11SymKey *key = symkey_from_hunk("xcbc", mac, (*prf)->logger);
	free_chunk_content(&(*prf)->bytes);
	symkey_delref((*prf)->logger, "key", &(*prf)->key);
	pfree(*prf);
	return key;
}

static void nss_xcbc_check(const struct prf_desc *prf, struct logger *logger)
{
	const struct ike_alg *alg = &prf->common;
	pexpect_ike_alg(logger, alg, prf->nss.mechanism > 0);
}

const struct prf_mac_ops ike_alg_prf_mac_nss_xcbc_ops = {
	"native(XCBC)",
	/*bespoke*/true,
	nss_xcbc_check,
	nss_xcbc_init_symkey,
	nss_xcbc_init_bytes,
	nss_xcbc_digest_symkey,
	nss_xcbc_digest_bytes,
	nss_xcbc_final_symkey,
	nss_xcbc_final_bytes,
};
