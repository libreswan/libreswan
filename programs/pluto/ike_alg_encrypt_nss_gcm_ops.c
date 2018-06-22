/*
 * Copyright (C) 2014,2016 Andrew Cagney <andrew.cagney@gmail.com>
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

#include <libreswan.h>

#include "lswlog.h"
#include "lswnss.h"
#include "prmem.h"
#include "prerror.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt_nss_gcm_ops.h"
#include "crypt_symkey.h"

static bool ike_alg_nss_gcm(const struct encrypt_desc *alg,
			    u_int8_t *salt, size_t salt_size,
			    u_int8_t *wire_iv, size_t wire_iv_size,
			    u_int8_t *aad, size_t aad_size,
			    u_int8_t *text_and_tag,
			    size_t text_size, size_t tag_size,
			    PK11SymKey *sym_key, bool enc)
{
	/* See pk11gcmtest.c */
	bool ok = TRUE;

	chunk_t salt_chunk = {
		.ptr = salt,
		.len = salt_size,
	};
	chunk_t wire_iv_chunk = {
		.ptr = wire_iv,
		.len = wire_iv_size,
	};
	chunk_t iv = concat_chunk_chunk("IV", salt_chunk, wire_iv_chunk);

	CK_GCM_PARAMS gcm_params;
	gcm_params.pIv = iv.ptr;
	gcm_params.ulIvLen = iv.len;
	gcm_params.pAAD = aad;
	gcm_params.ulAADLen = aad_size;
	gcm_params.ulTagBits = tag_size * 8;

	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&gcm_params;
	param.len = sizeof gcm_params;

	/* Output buffer for transformed data.  */
	size_t text_and_tag_size = text_size + tag_size;
	u_int8_t *out_buf = PR_Malloc(text_and_tag_size);
	unsigned int out_len = 0;

	if (enc) {
		SECStatus rv = PK11_Encrypt(sym_key, alg->nss.mechanism,
					    &param, out_buf, &out_len,
					    text_and_tag_size,
					    text_and_tag, text_size);
		if (rv != SECSuccess) {
			LSWLOG(buf) {
				lswlogf(buf, "NSS: AEAD encryption using %s_%zu and PK11_Encrypt() failed",
					alg->common.fqn, sizeof_symkey(sym_key) * BITS_PER_BYTE);
				lswlog_nss_error(buf);
			}
			ok = FALSE;
		} else if (out_len != text_and_tag_size) {
			/* should this be a pexpect fail? */
			loglog(RC_LOG_SERIOUS,
			       "NSS: AEAD encryption using %s_%zu and PK11_Encrypt() failed (output length of %u not the expected %zd)",
			       alg->common.fqn, sizeof_symkey(sym_key) * BITS_PER_BYTE,
			       out_len, text_and_tag_size);
			ok = FALSE;
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_GCM, &param,
					    out_buf, &out_len, text_and_tag_size,
					    text_and_tag, text_and_tag_size);
		if (rv != SECSuccess) {
			LSWLOG(buf) {
				lswlogf(buf, "NSS: AEAD decryption using %s_%zu and PK11_Decrypt() failed",
					alg->common.fqn, sizeof_symkey(sym_key) * BITS_PER_BYTE);
				lswlog_nss_error(buf);
			}
			ok = FALSE;
		} else if (out_len != text_size) {
			/* should this be a pexpect fail? */
			loglog(RC_LOG_SERIOUS,
			       "NSS: AEAD decryption using %s_%zu and PK11_Decrypt() failed (output length of %u not the expected %zd)",
			       alg->common.fqn, sizeof_symkey(sym_key) * BITS_PER_BYTE,
			       out_len, text_size);
			ok = FALSE;
		}
	}

	memcpy(text_and_tag, out_buf, out_len);
	PR_Free(out_buf);
	freeanychunk(iv);

	return ok;
}

static void nss_gcm_check(const struct encrypt_desc *encrypt) {
	const struct ike_alg *alg = &encrypt->common;
	passert_ike_alg(alg, encrypt->nss.mechanism > 0);
}

const struct encrypt_ops ike_alg_encrypt_nss_gcm_ops = {
	.check = nss_gcm_check,
	.do_aead = ike_alg_nss_gcm,
};
