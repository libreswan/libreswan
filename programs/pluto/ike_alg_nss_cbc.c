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

#include "defs.h"
#include "lswlog.h"
#include "prmem.h"
#include "prerror.h"

#include "constants.h"
#include "ike_alg.h"
#include "ike_alg_nss_cbc.h"

void ike_alg_nss_cbc(CK_MECHANISM_TYPE ciphermech, const struct encrypt_desc *alg,
		u_int8_t *in_buf, size_t in_buf_len, PK11SymKey *symkey,
		u_int8_t *iv, bool enc)
{
	DBG(DBG_CRYPT, DBG_log("NSS ike_alg_nss_cbc: %s - enter", alg->common.name));

	if (symkey == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "ike_alg_nss_cbc: %s - NSS derived enc key in NULL",
		       alg->common.name);
		exit_pluto(10);
	}

	SECItem ivitem;
	ivitem.type = siBuffer;
	ivitem.data = iv;
	ivitem.len = alg->enc_blocksize;
	SECItem *secparam = PK11_ParamFromIV(ciphermech, &ivitem);
	if (secparam == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "ike_alg_nss_cbc: %s - Failure to set up PKCS11 param (err %d)",
		       alg->common.name, PR_GetError());
		exit_pluto(10);
	}

	PK11Context *enccontext;
	enccontext = PK11_CreateContextBySymKey(ciphermech,
						enc ? CKA_ENCRYPT : CKA_DECRYPT,
						symkey, secparam);
	if (enccontext == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "ike_alg_nss_cbc: %s - PKCS11 context creation failure (err %d)",
		       alg->common.name, PR_GetError());
		exit_pluto(10);
	}


	/* Output buffer for transformed data.  */
	u_int8_t *out_buf = PR_Malloc((PRUint32)in_buf_len);
	int out_buf_len = 0;

	SECStatus rv = PK11_CipherOp(enccontext, out_buf, &out_buf_len, in_buf_len,
				     in_buf, in_buf_len);
	if (rv != SECSuccess) {
		loglog(RC_LOG_SERIOUS,
		       "ike_alg_nss_cbc: %s - PKCS11 operation failure (err %d)",
		       alg->common.name, PR_GetError());
		exit_pluto(10);
	}

	PK11_DestroyContext(enccontext, PR_TRUE);

	/*
	 * Update the IV ready for the next call to this function.
	 */
	u_int8_t *new_iv;
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
