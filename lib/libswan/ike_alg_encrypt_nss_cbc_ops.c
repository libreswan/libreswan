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

#include <libreswan.h>

#include "lswlog.h"
#include "prmem.h"
#include "prerror.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt_nss_cbc_ops.h"
#include "lswnss.h"		/* for lswlog_nss_error() */

static void ike_alg_nss_cbc(const struct encrypt_desc *alg,
			    uint8_t *in_buf, size_t in_buf_len, PK11SymKey *symkey,
			    uint8_t *iv, bool enc)
{
	DBG(DBG_CRYPT, DBG_log("NSS ike_alg_nss_cbc: %s - enter", alg->common.name));

	if (symkey == NULL) {
		PASSERT_FAIL("%s - NSS derived enc key in NULL",
			     alg->common.name);
	}

	SECItem ivitem;
	ivitem.type = siBuffer;
	ivitem.data = iv;
	ivitem.len = alg->enc_blocksize;
	SECItem *secparam = PK11_ParamFromIV(alg->nss.mechanism, &ivitem);
	if (secparam == NULL) {
		PASSERT_FAIL("%s - Failure to set up PKCS11 param (err %d)",
			     alg->common.name, PR_GetError());
	}

	PK11Context *enccontext;
	enccontext = PK11_CreateContextBySymKey(alg->nss.mechanism,
						enc ? CKA_ENCRYPT : CKA_DECRYPT,
						symkey, secparam);
	if (enccontext == NULL) {
		LSWLOG_PASSERT(buf) {
			lswlogf(buf, "NSS: %s: PKCS11 context creation failure",
				alg->common.name);
			lswlog_nss_error(buf);
		}
	}

	/* Output buffer for transformed data.  */
	uint8_t *out_buf = PR_Malloc((PRUint32)in_buf_len);
	int out_buf_len = 0;

	SECStatus rv = PK11_CipherOp(enccontext, out_buf, &out_buf_len, in_buf_len,
				     in_buf, in_buf_len);
	if (rv != SECSuccess) {
		LSWLOG_PASSERT(buf) {
			lswlogf(buf, "NSS: %s: PKCS11 operation failure",
				alg->common.name);
			lswlog_nss_error(buf);
		}
	}

	PK11_DestroyContext(enccontext, PR_TRUE);

	/*
	 * Update the IV ready for the next call to this function.
	 */
	uint8_t *new_iv;
	if (enc) {
		/*
		 * The IV for the next encryption call is the last
		 * block of encrypted output data.
		 */
		new_iv = out_buf + out_buf_len - alg->enc_blocksize;
	} else {
		/*
		 * The IV for the next decryption call is the last
		 * block of the encrypted input data.
		 */
		new_iv = in_buf + in_buf_len - alg->enc_blocksize;
	}
	memcpy(iv, new_iv, alg->enc_blocksize);

	/*
	 * Finally, copy the transformed data back to the buffer.  Do
	 * this after extracting the IV.
	 */
	memcpy(in_buf, out_buf, in_buf_len);
	PR_Free(out_buf);

	if (secparam != NULL)
		SECITEM_FreeItem(secparam, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS ike_alg_nss_cbc: %s - exit", alg->common.name));
}

static void nss_cbc_check(const struct encrypt_desc *encrypt)
{
	const struct ike_alg *alg = &encrypt->common;
	pexpect_ike_alg(alg, encrypt->nss.mechanism > 0);
}

const struct encrypt_ops ike_alg_encrypt_nss_cbc_ops = {
	.check = nss_cbc_check,
	.do_crypt = ike_alg_nss_cbc,
};
