/*
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014 Andrew Cagney <andrew.cagney@gmail.com>
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
#include "prmem.h"
#include "prerror.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt_ops.h"
#include "crypt_cipher.h"
#include "lswnss.h"		/* for llog_nss_error() */

static void cipher_op_cbc_nss(const struct encrypt_desc *cipher,
			      struct cipher_op_context *context,
			      enum cipher_op op,
			      enum cipher_iv_source iv_source UNUSED,
			      PK11SymKey *symkey,
			      shunk_t salt UNUSED,
			      chunk_t wire_iv UNUSED,
			      chunk_t text,
			      chunk_t iv,
			      struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "NSS ike_alg_nss_cbc: %s - enter %p",
	      cipher->common.fqn, context);

	if (symkey == NULL) {
		llog_passert(logger, HERE,
			     "%s - NSS derived enc key in NULL",
			     cipher->common.fqn);
	}

	PEXPECT(logger, iv.len == cipher->enc_blocksize);
	SECItem ivitem;
	ivitem.type = siBuffer;
	ivitem.data = iv.ptr;
	ivitem.len = cipher->enc_blocksize;
	SECItem *secparam = PK11_ParamFromIV(cipher->nss.mechanism, &ivitem);
	if (secparam == NULL) {
		llog_passert(logger, HERE,
			     "%s - Failure to set up PKCS11 param (err %d)",
			     cipher->common.fqn, PR_GetError());
	}

	PK11Context *enccontext;
	enccontext = PK11_CreateContextBySymKey(cipher->nss.mechanism,
						(op == ENCRYPT ? CKA_ENCRYPT :
						 op == DECRYPT ? CKA_DECRYPT :
						 pexpect(0)),
						symkey, secparam);
	if (enccontext == NULL) {
		passert_nss_error(logger, HERE,
				  "%s: PKCS11 context creation failure",
				  cipher->common.fqn);
	}

	/* Output buffer for transformed data. */
	uint8_t *out_ptr = PR_Malloc(text.len);
	int out_len = 0; /* not size_t; ulgh */

	SECStatus rv = PK11_CipherOp(enccontext, out_ptr, &out_len, text.len,
				     text.ptr, text.len);
	if (rv != SECSuccess) {
		passert_nss_error(logger, HERE,
				  "%s: PKCS11 operation failure", cipher->common.fqn);
	}

	PK11_DestroyContext(enccontext, PR_TRUE);

	/*
	 * Update the IV ready for the next call to this function.
	 */
	uint8_t *new_iv;
	switch (op) {
	case ENCRYPT:
		/*
		 * The IV for the next encryption call is the last
		 * block of encrypted output data.
		 */
		new_iv = out_ptr + out_len - cipher->enc_blocksize;
		break;
	case DECRYPT:
		/*
		 * The IV for the next decryption call is the last
		 * block of the encrypted input data.
		 */
		new_iv = text.ptr + text.len - cipher->enc_blocksize;
		break;
	default:
		bad_case(op);
	}
	PEXPECT(logger, iv.len == cipher->enc_blocksize);
	memcpy(iv.ptr, new_iv, cipher->enc_blocksize);

	/*
	 * Finally, copy the transformed data back to the buffer.  Do
	 * this after extracting the IV.
	 */
	memcpy(text.ptr, out_ptr, text.len);
	PR_Free(out_ptr);

	if (secparam != NULL)
		SECITEM_FreeItem(secparam, PR_TRUE);
	ldbgf(DBG_CRYPT, logger, "NSS ike_alg_nss_cbc: %s - exit", cipher->common.fqn);
}

static void cipher_check_cbc_nss(const struct encrypt_desc *encrypt,
				 struct logger *logger)
{
	const struct ike_alg *alg = &encrypt->common;
	pexpect_ike_alg(logger, alg, encrypt->nss.mechanism > 0);
}

const struct encrypt_ops ike_alg_encrypt_nss_cbc_ops = {
	.backend = "NSS(CBC)",
	.cipher_check = cipher_check_cbc_nss,
	.cipher_op_normal = cipher_op_cbc_nss,
};
