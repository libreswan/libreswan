/* NSS GCM for libreswan
 *
 * Copyright (C) 2014,2016,2018 Andrew Cagney
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

/*
 * Special advise from Bob Relyea - needs to go before any nss include
 *
 */
#define NSS_PKCS11_2_0_COMPAT 1

#include "lswlog.h"
#include "lswnss.h"
#include "prmem.h"
#include "prerror.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt_ops.h"
#include "rnd.h"

static bool ike_alg_nss_gcm(const struct encrypt_desc *alg,
			    shunk_t salt,
			    enum ike_alg_iv_source iv_source,
			    chunk_t wire_iv,
			    shunk_t aad,
			    chunk_t text_and_tag,
			    size_t text_len, size_t tag_len,
			    PK11SymKey *symkey,
			    enum ike_alg_crypt crypt,
			    struct logger *logger)
{
	/* must be contigious */
	PASSERT(logger, text_len + tag_len == text_and_tag.len);

	/* See pk11gcmtest.c */
	bool ok = true;

	CK_ATTRIBUTE_TYPE mode = (crypt == ENCRYPT ? CKA_ENCRYPT :
				  crypt == DECRYPT ? CKA_DECRYPT :
				  pexpect(0));
	SECItem dummy = {0};
	PK11Context *context = PK11_CreateContextBySymKey(alg->nss.mechanism,
							  CKA_NSS_MESSAGE|mode,
							  symkey, &dummy);
	if (context == NULL) {
		enum_buf ckm;
		passert_nss_error(logger, HERE,
				  "%s: PKCS11_CreateContextBySymKey(%s,%s) failed",
				  alg->common.fqn,
				  str_ike_alg_crypt(crypt),
				  str_nss_ckm(alg->nss.mechanism, &ckm));
	}

	switch (iv_source) {
	case USE_IV:
		break;
	case FILL_IV:
		fill_rnd_chunk(wire_iv);
		break;
	default:
		bad_case(iv_source);
	}
	chunk_t iv = clone_hunk_hunk(salt, wire_iv, "IV");

	/* Output buffer for transformed data. */
	uint8_t *out_ptr = PR_Malloc(text_and_tag.len); /* XXX: use normal malloc? */
	int out_len = 0;

	SECStatus rv = PK11_AEADOp(context,
				   CKG_NO_GENERATE/*XXX: should be CKG_GENERATE_RANDOM*/,
				   /*fixedbits*/alg->salt_size * 8,
				   iv.ptr, iv.len,
				   aad.ptr, aad.len,
				   out_ptr, &out_len,
				   /*maxout*/text_and_tag.len,
				   text_and_tag.ptr + text_len, tag_len,
				   text_and_tag.ptr, text_len);

	if (rv != SECSuccess) {
		llog_nss_error(RC_LOG, logger,
			       "AEAD encryption using %s_%u and PK11_AEADOp() failed",
			       alg->common.fqn,
			       PK11_GetKeyLength(symkey) * BITS_IN_BYTE);
		ok = false;
	} else if ((unsigned)out_len != text_len) {
		/* should this be a pexpect fail? */
		llog_nss_error(RC_LOG, logger,
			       "AEAD encryption using %s_%u and PK11_AEADOp() failed (output length of %u not the expected %zd)",
			       alg->common.fqn,
			       PK11_GetKeyLength(symkey) * BITS_IN_BYTE,
			       out_len, text_and_tag.len);
		ok = false;
	}

	memcpy(text_and_tag.ptr, out_ptr, out_len);
	PK11_Finalize(context);
	PK11_DestroyContext(context, PR_TRUE);
	PR_Free(out_ptr);
	free_chunk_content(&iv);

	return ok;
}

static void nss_gcm_check(const struct encrypt_desc *encrypt, struct logger *logger)
{
	const struct ike_alg *alg = &encrypt->common;
	pexpect_ike_alg(logger, alg, encrypt->nss.mechanism > 0);
}

const struct encrypt_ops ike_alg_encrypt_nss_gcm_ops = {
	.backend = "NSS(GCM)",
	.check = nss_gcm_check,
	.do_aead = ike_alg_nss_gcm,
};
