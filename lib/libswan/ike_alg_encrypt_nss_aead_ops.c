/* NSS AEAD for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#include "lswlog.h"
#include "lswnss.h"
#include "prmem.h"
#include "prerror.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt_nss_aead_ops.h"

#if defined(CKM_NSS_CHACHA20_POLY1305)

static bool ike_alg_nss_aead(const struct encrypt_desc *alg,
			     uint8_t *salt, size_t salt_size,
			     uint8_t *wire_iv, size_t wire_iv_size,
			     uint8_t *aad, size_t aad_size,
			     uint8_t *text_and_tag,
			     size_t text_size, size_t tag_size,
			     PK11SymKey *sym_key, bool enc)
{
	/* See pk11aeadtest.c */
	bool ok = true;

	chunk_t salt_chunk = {
		.ptr = salt,
		.len = salt_size,
	};
	chunk_t wire_iv_chunk = {
		.ptr = wire_iv,
		.len = wire_iv_size,
	};
	chunk_t iv = clone_chunk_chunk(salt_chunk, wire_iv_chunk, "IV");

	CK_NSS_AEAD_PARAMS aead_params = {
		.pNonce = iv.ptr,
		.ulNonceLen = iv.len,
		.pAAD = aad,
		.ulAADLen = aad_size,
		.ulTagLen = alg->aead_tag_size,
	};

	SECItem param = {
		.type = siBuffer,
		.data = (void*)&aead_params,
		.len = sizeof aead_params,
	};

	/* Output buffer for transformed data.  */
	size_t text_and_tag_size = text_size + tag_size;
	uint8_t *out_buf = PR_Malloc(text_and_tag_size);
	unsigned int out_len = 0;

	if (enc) {
		SECStatus rv = PK11_Encrypt(sym_key, alg->nss.mechanism,
					    &param, out_buf, &out_len,
					    text_and_tag_size,
					    text_and_tag, text_size);
		if (rv != SECSuccess) {
			LSWLOG(buf) {
				lswlogf(buf, "NSS: AEAD encryption using %s_%u and PK11_Encrypt() failed",
					alg->common.fqn, PK11_GetKeyLength(sym_key) * BITS_PER_BYTE);
				lswlog_nss_error(buf);
			}
			ok = false;
		} else if (out_len != text_and_tag_size) {
			/* should this be a pexpect fail? */
			LSWLOG_RC(RC_LOG_SERIOUS, buf) {
				lswlogf(buf, "NSS: AEAD encryption using %s_%u and PK11_Encrypt() failed (output length of %u not the expected %zd)",
					alg->common.fqn, PK11_GetKeyLength(sym_key) * BITS_PER_BYTE,
					out_len, text_and_tag_size);
				lswlog_nss_error(buf);
			}
			ok = false;
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, alg->nss.mechanism, &param,
					    out_buf, &out_len, text_and_tag_size,
					    text_and_tag, text_and_tag_size);
		if (rv != SECSuccess) {
			LSWLOG(buf) {
				lswlogf(buf, "NSS: AEAD decryption using %s_%u and PK11_Decrypt() failed",
					alg->common.fqn, PK11_GetKeyLength(sym_key) * BITS_PER_BYTE);
				lswlog_nss_error(buf);
			}
			ok = false;
		} else if (out_len != text_size) {
			/* should this be a pexpect fail? */
			LSWLOG_RC(RC_LOG_SERIOUS, buf) {
				lswlogf(buf, "NSS: AEAD decryption using %s_%u and PK11_Decrypt() failed (output length of %u not the expected %zd)",
					alg->common.fqn, PK11_GetKeyLength(sym_key) * BITS_PER_BYTE,
					out_len, text_size);
				lswlog_nss_error(buf);
			}
			ok = false;
		}
	}

	memcpy(text_and_tag, out_buf, out_len);
	PR_Free(out_buf);
	freeanychunk(iv);

	return ok;
}

static void nss_aead_check(const struct encrypt_desc *encrypt)
{
	const struct ike_alg *alg = &encrypt->common;
	pexpect_ike_alg(alg, encrypt->nss.mechanism > 0);
}

const struct encrypt_ops ike_alg_encrypt_nss_aead_ops = {
	.check = nss_aead_check,
	.do_aead = ike_alg_nss_aead,
};

#endif
