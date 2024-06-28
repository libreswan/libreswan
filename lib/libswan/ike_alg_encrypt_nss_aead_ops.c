/* NSS GCM for libreswan
 *
 * Copyright (C) 2014,2016,2018,2024 Andrew Cagney
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
#include "crypt_cipher.h"
#include "ike_alg_encrypt_ops.h"
#include "rnd.h"
#include "crypt_symkey.h"

struct cipher_op_context {
	PK11SymKey *symkey;
	PK11Context *context;
	enum cipher_op op;
	enum cipher_iv_source iv_source;
	chunk_t salt;
	const struct encrypt_desc *cipher;
};

static struct cipher_op_context *cipher_context_create_aead_nss(const struct encrypt_desc *cipher,
								enum cipher_op op,
								enum cipher_iv_source iv_source,
								PK11SymKey *symkey,
								shunk_t salt,
								struct logger *logger)
{
	CK_ATTRIBUTE_TYPE mode = (op == ENCRYPT ? CKA_ENCRYPT :
				  op == DECRYPT ? CKA_DECRYPT :
				  pexpect(0));
	SECItem dummy = {0};
	PK11Context *context = PK11_CreateContextBySymKey(cipher->nss.mechanism,
							  CKA_NSS_MESSAGE|mode,
							  symkey, &dummy);
	if (context == NULL) {
		enum_buf ckm;
		passert_nss_error(logger, HERE,
				  "%s: PKCS11_CreateContextBySymKey(%s,%s) failed",
				  cipher->common.fqn,
				  str_cipher_op(op),
				  str_nss_ckm(cipher->nss.mechanism, &ckm));
	}

	struct cipher_op_context *aead = alloc_thing(struct cipher_op_context, __func__);
	aead->context = context;
	aead->symkey = symkey_addref(logger, __func__, symkey);
	aead->op = op;
	aead->iv_source = iv_source;
	aead->salt = clone_hunk(salt, __func__);
	aead->cipher = cipher;
	return aead;
}

static bool cipher_context_aead_op_nss(const struct cipher_op_context *aead,
				       chunk_t wire_iv,
				       shunk_t aad,
				       chunk_t text_and_tag,
				       size_t text_len, size_t tag_len,
				       struct logger *logger)
{
	/* must be contigious */
	PASSERT(logger, text_len + tag_len == text_and_tag.len);

	bool ok = true;

	switch (aead->iv_source) {
	case DECRYPT:
		break;
	case ENCRYPT:
		fill_rnd_chunk(wire_iv);
		break;
	default:
		bad_case(aead->op);
	}
	chunk_t iv = clone_hunk_hunk(aead->salt, wire_iv, "IV");

	/* Output buffer for transformed data. */
	uint8_t *out_ptr = PR_Malloc(text_and_tag.len); /* XXX: use normal malloc? */
	int out_len = 0;

	SECStatus rv = PK11_AEADOp(aead->context,
				   CKG_NO_GENERATE/*XXX: should be CKG_GENERATE_RANDOM*/,
				   /*fixedbits*/aead->cipher->salt_size * 8,
				   iv.ptr, iv.len,
				   aad.ptr, aad.len,
				   out_ptr, &out_len,
				   /*maxout*/text_and_tag.len,
				   text_and_tag.ptr + text_len, tag_len,
				   text_and_tag.ptr, text_len);

	if (rv != SECSuccess) {
		llog_nss_error(RC_LOG, logger,
			       "AEAD encryption using %s_%u and PK11_AEADOp() failed",
			       aead->cipher->common.fqn,
			       PK11_GetKeyLength(aead->symkey) * BITS_IN_BYTE);
		ok = false;
	} else if ((unsigned)out_len != text_len) {
		/* should this be a pexpect fail? */
		llog_nss_error(RC_LOG, logger,
			       "AEAD encryption using %s_%u and PK11_AEADOp() failed (output length of %u not the expected %zd)",
			       aead->cipher->common.fqn,
			       PK11_GetKeyLength(aead->symkey) * BITS_IN_BYTE,
			       out_len, text_and_tag.len);
		ok = false;
	}

	memcpy(text_and_tag.ptr, out_ptr, out_len);
	PR_Free(out_ptr);
	free_chunk_content(&iv);

	return ok;
}

static void cipher_context_destroy_aead_nss(struct cipher_op_context **aead,
					    struct logger *logger)
{
	PK11_Finalize((*aead)->context);
	PK11_DestroyContext((*aead)->context, PR_TRUE);
	symkey_delref(logger, __func__, &(*aead)->symkey);
	free_chunk_content(&(*aead)->salt);
	ldbg(logger, "destroyed");
	pfreeany(*aead);
}

static void cipher_check_aead_nss(const struct encrypt_desc *encrypt, struct logger *logger)
{
	const struct ike_alg *alg = &encrypt->common;
	pexpect_ike_alg(logger, alg, encrypt->nss.mechanism > 0);
}

const struct encrypt_ops ike_alg_encrypt_nss_aead_ops = {
	.backend = "NSS(AEAD)",
	.check = cipher_check_aead_nss,
	.context_create = cipher_context_create_aead_nss,
	.context_aead_op = cipher_context_aead_op_nss,
	.context_destroy = cipher_context_destroy_aead_nss,
};
