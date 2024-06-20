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
#include "lswnss.h"		/* for llog_nss_error() */

static void ike_alg_nss_cbc(const struct encrypt_desc *alg,
			    chunk_t in_buf, chunk_t iv,
			    PK11SymKey *symkey,
			    enum ike_alg_crypt crypt,
			    struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "NSS ike_alg_nss_cbc: %s - enter", alg->common.fqn);

	if (symkey == NULL) {
		llog_passert(logger, HERE,
			     "%s - NSS derived enc key in NULL",
			     alg->common.fqn);
	}

	PEXPECT(logger, iv.len == alg->enc_blocksize);
	SECItem ivitem;
	ivitem.type = siBuffer;
	ivitem.data = iv.ptr;
	ivitem.len = alg->enc_blocksize;
	SECItem *secparam = PK11_ParamFromIV(alg->nss.mechanism, &ivitem);
	if (secparam == NULL) {
		llog_passert(logger, HERE,
			     "%s - Failure to set up PKCS11 param (err %d)",
			     alg->common.fqn, PR_GetError());
	}

	PK11Context *enccontext;
	enccontext = PK11_CreateContextBySymKey(alg->nss.mechanism,
						(crypt == ENCRYPT ? CKA_ENCRYPT :
						 crypt == DECRYPT ? CKA_DECRYPT :
						 pexpect(0)),
						symkey, secparam);
	if (enccontext == NULL) {
		passert_nss_error(logger, HERE,
				  "%s: PKCS11 context creation failure",
				  alg->common.fqn);
	}

	/* Output buffer for transformed data. */
	uint8_t *out_buf = PR_Malloc((PRUint32)in_buf.len);
	int out_buf_len = 0;

	SECStatus rv = PK11_CipherOp(enccontext, out_buf, &out_buf_len, in_buf.len,
				     in_buf.ptr, in_buf.len);
	if (rv != SECSuccess) {
		passert_nss_error(logger, HERE,
				  "%s: PKCS11 operation failure", alg->common.fqn);
	}

	PK11_DestroyContext(enccontext, PR_TRUE);

	/*
	 * Update the IV ready for the next call to this function.
	 */
	uint8_t *new_iv;
	switch (crypt) {
	case ENCRYPT:
		/*
		 * The IV for the next encryption call is the last
		 * block of encrypted output data.
		 */
		new_iv = out_buf + out_buf_len - alg->enc_blocksize;
		break;
	case DECRYPT:
		/*
		 * The IV for the next decryption call is the last
		 * block of the encrypted input data.
		 */
		new_iv = in_buf.ptr + in_buf.len - alg->enc_blocksize;
		break;
	default:
		bad_case(crypt);
	}
	PEXPECT(logger, iv.len == alg->enc_blocksize);
	memcpy(iv.ptr, new_iv, alg->enc_blocksize);

	/*
	 * Finally, copy the transformed data back to the buffer.  Do
	 * this after extracting the IV.
	 */
	memcpy(in_buf.ptr, out_buf, in_buf.len);
	PR_Free(out_buf);

	if (secparam != NULL)
		SECITEM_FreeItem(secparam, PR_TRUE);
	ldbgf(DBG_CRYPT, logger, "NSS ike_alg_nss_cbc: %s - exit", alg->common.fqn);
}

static void nss_cbc_check(const struct encrypt_desc *encrypt, struct logger *logger)
{
	const struct ike_alg *alg = &encrypt->common;
	pexpect_ike_alg(logger, alg, encrypt->nss.mechanism > 0);
}

const struct encrypt_ops ike_alg_encrypt_nss_cbc_ops = {
	.backend = "NSS(CBC)",
	.check = nss_cbc_check,
	.do_crypt = ike_alg_nss_cbc,
};
