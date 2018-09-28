/*
 * Copyright (C) 2016-2017 Andrew Cagney
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

#include "libreswan.h"
#include "chunk.h"
#include "lswlog.h"
#include "lswalloc.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_prf_nss_xcbc_ops.h"
#include "ike_alg_prf_nss_ops.h"
#include "crypt_symkey.h"
#include "lswnss.h"

struct prf_context {
	const char *name;
	const struct prf_desc *desc;
	PK11SymKey *key;
	chunk_t bytes;
};

static void encrypt(const char *name, chunk_t out, chunk_t in,
		    const struct prf_desc *prf, PK11SymKey *key)
{
	unsigned int out_size = 0;
	SECStatus status = PK11_Encrypt(key, prf->nss.mechanism, NULL,
					out.ptr, &out_size, out.len,
					in.ptr, in.len);
	if (status != SECSuccess) {
		LSWLOG_PASSERT(buf) {
			lswlogf(buf, "encryption %s failed: ",
				name);
			lswlog_nss_error(buf);
		}
	}
}

static chunk_t derive_ki(const struct prf_desc *prf,
			 PK11SymKey *key, int ki)
{
	chunk_t in = alloc_chunk(prf->prf_key_size, "ki in");
	chunk_t out = alloc_chunk(prf->prf_key_size, "ki out");
	for (unsigned i = 0; i < prf->prf_key_size; i++) {
		in.ptr[i] = ki;
	}
	encrypt("K([123])", out, in, prf, key);
	freeanychunk(in);
	return out;
}

static chunk_t xcbc_mac(const struct prf_desc *prf, PK11SymKey *key,
			chunk_t bytes)
{
	DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: data", bytes));

	chunk_t k = chunk_from_symkey("K", key);
	DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: K:", k));
	freeanychunk(k);

	chunk_t k1t = derive_ki(prf, key, 1);
	DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: K1", k1t));
	PK11SymKey *k1 = prf_key_from_bytes("k1", prf, k1t.ptr, k1t.len);
	freeanychunk(k1t);

	/*
	 * (2)  Define E[0] = 0x00000000000000000000000000000000
	 */
	chunk_t e = alloc_chunk(prf->prf_key_size, "e");

	/*
	 * (3)  For each block M[i], where i = 1 ... n-1:
	 *      XOR M[i] with E[i-1], then encrypt the result with Key K1,
	 *      yielding E[i].
	 */
	chunk_t t = alloc_chunk(prf->prf_key_size, "t");
	int n = (bytes.len + prf->prf_key_size - 1) / prf->prf_key_size;
	chunk_t m = chunk(bytes.ptr, prf->prf_key_size);
	for (int i = 1; i <= n - 1; i++) {
		for (unsigned j = 0; j < prf->prf_key_size; j++) {
			t.ptr[j] = m.ptr[j] ^ e.ptr[j];
		}
		encrypt("XCBC: K1(M[i]^E[i-1])", e, t, prf, k1);
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
		chunk_t k2 = derive_ki(prf, key, 2);
		DBGF(DBG_CRYPT_LOW, "XCBC: Computing E[%d] using K2", n);
		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: K2", k2));
		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: E[n-1]", e));
		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: M[n]", m));
		/*
		 *      a)  If the blocksize of M[n] is 128 bits:
		 *          XOR M[n] with E[n-1] and Key K2, then encrypt the result with
		 *          Key K1, yielding E[n].
		 */
		for (unsigned j = 0; j < prf->prf_key_size; j++) {
			t.ptr[j] = m.ptr[j] ^ e.ptr[j] ^ k2.ptr[j];
		}
		freeanychunk(k2);
		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: M[n]^E[n-1]^K2", t));
	} else {
		chunk_t k3 = derive_ki(prf, key, 3);
		DBGF(DBG_CRYPT_LOW, "Computing E[%d] using K3", n);
		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: K3", k3));
		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: E[n-1]", e));
		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: M[n]", m));
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
		for (; j < m.len; j++) {
			t.ptr[j] = m.ptr[j] ^ e.ptr[j] ^ k3.ptr[j];
		}
		t.ptr[j] = 0x80 ^ e.ptr[j] ^ k3.ptr[j];
		j++;
		for (; j < prf->prf_key_size; j++) {
			t.ptr[j] = 0x00 ^ e.ptr[j] ^ k3.ptr[j];
		}

		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: M[n]", m));
		freeanychunk(k3);
		DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: M[n]:80...^E[n-1]^K3", t));
	}

	encrypt("K1(M[n]^E[n-1]^K2)", e, t, prf, k1);
	DBG(DBG_CRYPT_LOW, DBG_dump_chunk("XCBC: MAC", e));

	release_symkey("xcbc", "k1", &k1);
	freeanychunk(t);
	return e;
}

/*
 * Create a PRF ready to consume data.
 */

static struct prf_context *nss_xcbc_init_symkey(const struct prf_desc *prf_desc,
						const char *name,
						const char *key_name, PK11SymKey *draft_key)
{
	/*
	 * Need to turn the key into something of the right size.
	 */
	PK11SymKey *key;
	if (sizeof_symkey(draft_key) < prf_desc->prf_key_size) {
		DBGF(DBG_CRYPT_LOW, "XCBC: Key %zd<%zd too small, padding with zeros",
		     sizeof_symkey(draft_key), prf_desc->prf_key_size);
		/*
		 * right pad with zeros
		 */
		chunk_t zeros = alloc_chunk(prf_desc->prf_key_size - sizeof_symkey(draft_key),
					    "zeros");
		PK11SymKey *tmp = concat_symkey_chunk(draft_key, zeros);
		freeanychunk(zeros);
		key = prf_key_from_symkey_bytes(name, prf_desc,
						0, prf_desc->prf_key_size, tmp);
		release_symkey(name, "tmp", &tmp);
	} else if (sizeof_symkey(draft_key) > prf_desc->prf_key_size) {
		DBGF(DBG_CRYPT_LOW, "XCBC: Key %zd>%zd too big, rehashing to size",
		     sizeof_symkey(draft_key), prf_desc->prf_key_size);
		/*
		 * put the key through the mac with a zero key
		 */
		chunk_t zeros = alloc_chunk(prf_desc->prf_key_size, "zeros");
		PK11SymKey *zero_key = prf_key_from_bytes(key_name, prf_desc,
							  zeros.ptr, zeros.len);
		freeanychunk(zeros);
		chunk_t draft_chunk = chunk_from_symkey(key_name, draft_key);
		chunk_t key_chunk = xcbc_mac(prf_desc, zero_key, draft_chunk);
		freeanychunk(draft_chunk);
		key = prf_key_from_bytes(key_name, prf_desc,
					 key_chunk.ptr, key_chunk.len);
		freeanychunk(key_chunk);
	} else {
		DBGF(DBG_CRYPT_LOW, "XCBC: Key %zd=%zd just right",
		     sizeof_symkey(draft_key), prf_desc->prf_key_size);
		key = prf_key_from_symkey_bytes(key_name, prf_desc,
						0, prf_desc->prf_key_size,
						draft_key);
	}
	struct prf_context *prf = alloc_thing(struct prf_context, "prf context");
	*prf = (struct prf_context) {
		.key = key,
		.name = name,
		.desc = prf_desc,
	};
	return prf;
}

static struct prf_context *nss_xcbc_init_bytes(const struct prf_desc *prf_desc,
					       const char *name,
					       const char *key_name,
					       const uint8_t *key, size_t sizeof_key)
{
	/*
	 * Need a key of the correct type.
	 *
	 * This key has both the mechanism and flags set.
	 */
	PK11SymKey *clone = symkey_from_bytes(key_name, key, sizeof_key);
	struct prf_context *context = nss_xcbc_init_symkey(prf_desc, name,
							   key_name, clone);
	release_symkey(name, "clone", &clone);
	return context;
}

/*
 * Accumulate data.
 */

static void nss_xcbc_digest_symkey(struct prf_context *prf,
				  const char *symkey_name, PK11SymKey *symkey)
{
	append_chunk_symkey(symkey_name, &prf->bytes, symkey);

}

static void nss_xcbc_digest_bytes(struct prf_context *prf, const char *name,
				  const uint8_t *bytes, size_t sizeof_bytes)
{
	append_chunk_bytes(name, &prf->bytes, bytes, sizeof_bytes);
}

static void nss_xcbc_final_bytes(struct prf_context **prf,
				 uint8_t *bytes, size_t sizeof_bytes)
{
	chunk_t mac = xcbc_mac((*prf)->desc, (*prf)->key, (*prf)->bytes);
	memcpy(bytes, mac.ptr, sizeof_bytes);
	freeanychunk(mac);
	freeanychunk((*prf)->bytes);
	release_symkey((*prf)->name, "key", &(*prf)->key);
	pfree(*prf);
}

static PK11SymKey *nss_xcbc_final_symkey(struct prf_context **prf)
{
	chunk_t mac = xcbc_mac((*prf)->desc, (*prf)->key, (*prf)->bytes);
	PK11SymKey *key = symkey_from_chunk("xcbc", mac);
	freeanychunk(mac);
	freeanychunk((*prf)->bytes);
	release_symkey((*prf)->name, "key", &(*prf)->key);
	pfree(*prf);
	return key;
}

static void nss_xcbc_check(const struct prf_desc *prf)
{
	const struct ike_alg *alg = &prf->common;
	pexpect_ike_alg(alg, prf->nss.mechanism > 0);
}

const struct prf_ops ike_alg_prf_nss_xcbc_ops = {
	nss_xcbc_check,
	nss_xcbc_init_symkey,
	nss_xcbc_init_bytes,
	nss_xcbc_digest_symkey,
	nss_xcbc_digest_bytes,
	nss_xcbc_final_symkey,
	nss_xcbc_final_bytes,
};
