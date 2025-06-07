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
	PK11Context *context;
	chunk_t random_iv;
	unsigned long count;
};

static struct cipher_op_context *cipher_op_context_create_aead_nss(const struct encrypt_desc *cipher,
								   enum cipher_op op,
								   enum cipher_iv_source iv_source UNUSED,
								   PK11SymKey *symkey,
								   shunk_t salt UNUSED,
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
		name_buf ckm;
		passert_nss_error(logger, HERE,
				  "%s: PKCS11_CreateContextBySymKey(%s,%s) failed",
				  cipher->common.fqn,
				  str_cipher_op(op),
				  str_nss_ckm(cipher->nss.mechanism, &ckm));
	}

	struct cipher_op_context *aead = alloc_thing(struct cipher_op_context, __func__);
	aead->context = context;
	aead->random_iv = alloc_rnd_chunk(cipher->wire_iv_size, "Random-IV");
	aead->count = 0;
	return aead;
}

static bool cipher_op_aead_nss(const struct encrypt_desc *cipher,
			       struct cipher_op_context *aead,
			       enum cipher_op op UNUSED,
			       enum cipher_iv_source iv_source,
			       PK11SymKey *symkey,
			       shunk_t salt,
			       chunk_t wire_iv,
			       shunk_t aad,
			       chunk_t text_and_tag,
			       size_t text_len, size_t tag_len,
			       struct logger *logger)
{
	/* must be contiguous */
	PASSERT(logger, text_len + tag_len == text_and_tag.len);

	CK_GENERATOR_FUNCTION generator;
	chunk_t iv;
	switch (iv_source) {
	case USE_WIRE_IV:
		/*
		 * Presumably the IV has come from the peer.
		 */
		generator = CKG_NO_GENERATE;
		iv = clone_hunk_hunk(salt, wire_iv, "IV");
		break;
	case FILL_WIRE_IV:
		/*
		 * NSS will scribble on this with real IV; need to
		 * copy it back.
		 */
		generator = CKG_GENERATE_COUNTER_XOR;
		iv = clone_hunk_hunk(salt, aead->random_iv, "IV");
		break;
	case USE_IKEv1_IV: /* makes no sense */
	default:
		bad_case(iv_source);
	}

	/* Output buffer for transformed data. */
	uint8_t *out_ptr = PR_Malloc(text_and_tag.len); /* XXX: use normal malloc? */
	int out_len = 0;

	SECStatus rv = PK11_AEADOp(aead->context, generator,
				   /*fixedbits*/cipher->salt_size * 8,
				   /*nss-scribbles-on-this*/iv.ptr, iv.len,
				   aad.ptr, aad.len,
				   out_ptr, &out_len,
				   /*maxout*/text_and_tag.len,
				   text_and_tag.ptr + text_len, tag_len,
				   text_and_tag.ptr, text_len);

	bool ok;
	if (rv != SECSuccess) {
		llog_nss_error(RC_LOG, logger,
			       "AEAD encryption using %s_%u and PK11_AEADOp() failed",
			       cipher->common.fqn,
			       PK11_GetKeyLength(symkey) * BITS_IN_BYTE);
		ok = false;
	} else if ((unsigned)out_len != text_len) {
		/* should this be a pexpect fail? */
		llog_nss_error(RC_LOG, logger,
			       "AEAD encryption using %s_%u and PK11_AEADOp() failed (output length of %u not the expected %zd)",
			       cipher->common.fqn,
			       PK11_GetKeyLength(symkey) * BITS_IN_BYTE,
			       out_len, text_and_tag.len);
		ok = false;
	} else {
		ldbg(logger, "AEAD encryption using %s_%u and PK11_AEADOp() succeeded returning %d bytes",
		     cipher->common.fqn,
		     PK11_GetKeyLength(symkey) * BITS_IN_BYTE,
		     out_len);
		ok = true;
	}

	/* Copy updated text back.  */
	memcpy(text_and_tag.ptr, out_ptr, out_len);
	PR_Free(out_ptr);

	if (iv_source == FILL_WIRE_IV) {
		/*
		 * Cut out and then copy back the generated IV.
		 *
		 * The First time this op is used the .random_iv is
		 * returned, from then on .random_op^count is used.
		 */
		chunk_t out_iv = hunk_slice(iv, salt.len, iv.len);
		PASSERT(logger, out_iv.len == aead->random_iv.len);
		hunk_cpy(wire_iv, out_iv);
	}
	aead->count++;

	free_chunk_content(&iv);

	return ok;
}

static void cipher_op_context_destroy_aead_nss(struct cipher_op_context **aead,
					       struct logger *logger)
{
	PK11_Finalize((*aead)->context);
	PK11_DestroyContext((*aead)->context, PR_TRUE);
	free_chunk_content(&(*aead)->random_iv);
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
	.cipher_check = cipher_check_aead_nss,
	.cipher_op_context_create = cipher_op_context_create_aead_nss,
	.cipher_op_aead = cipher_op_aead_nss,
	.cipher_op_context_destroy = cipher_op_context_destroy_aead_nss,
};
