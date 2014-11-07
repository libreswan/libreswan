/*
 * Copyright (C) 2014 Paul Wouters <paul@libreswan.org>
 *
 * Based on ike_alg_camellia.c
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
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <libreswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "crypto.h"
#include "alg_info.h"
#include "ike_alg.h"

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include "lswconf.h"
#include "lswlog.h"

static void do_camellia_cbc(u_int8_t *buf, size_t buf_len, PK11SymKey *symkey,
		   u_int8_t *iv, bool enc)
{

	u_int8_t iv_bak[CAMELLIA_BLOCK_SIZE];
	u_int8_t *new_iv = NULL;    /* logic will avoid copy to NULL */
	u_int8_t *tmp_buf;

	CK_MECHANISM_TYPE ciphermech;
	SECItem ivitem;
	SECItem *secparam;
	PK11Context *enccontext;
	SECStatus rv;
	int outlen;

	DBG(DBG_CRYPT, DBG_log("NSS do_camellia_cbc: enter"));
	ciphermech = CKM_CAMELLIA_CBC; /*libreswan provides padding*/

	if (symkey == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "do_camellia_cbc: NSS derived enc key in NULL");
		abort();
	}

	ivitem.type = siBuffer;
	ivitem.data = iv;
	ivitem.len = CAMELLIA_BLOCK_SIZE;

	secparam = PK11_ParamFromIV(ciphermech, &ivitem);
	if (secparam == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "do_camellia_cbc: Failure to set up PKCS11 param (err %d)",
		       PR_GetError());
		abort();
	}

	outlen = 0;
	tmp_buf = PR_Malloc((PRUint32)buf_len);

	if (!enc) {
		new_iv = iv_bak;
		memcpy(new_iv,
		       (char*) buf + buf_len - CAMELLIA_BLOCK_SIZE,
		       CAMELLIA_BLOCK_SIZE);
	}

	enccontext = PK11_CreateContextBySymKey(ciphermech,
						enc ? CKA_ENCRYPT : CKA_DECRYPT, symkey,
						secparam);
	if (enccontext == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "do_camellia_cbc: PKCS11 context creation failure (err %d)",
		       PR_GetError());
		abort();
	}

	rv = PK11_CipherOp(enccontext, tmp_buf, &outlen, buf_len, buf,
			      buf_len);
	if (rv != SECSuccess) {
		loglog(RC_LOG_SERIOUS,
		       "do_camellia_cbc: PKCS11 operation failure (err %d)",
		       PR_GetError());
		abort();
	}
	PK11_DestroyContext(enccontext, PR_TRUE);
	memcpy(buf, tmp_buf, buf_len);

	if (enc)
		new_iv = (u_int8_t*) buf + buf_len - CAMELLIA_BLOCK_SIZE;

	memcpy(iv, new_iv, CAMELLIA_BLOCK_SIZE);
	PR_Free(tmp_buf);

	if (secparam != NULL)
		SECITEM_FreeItem(secparam, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS do_camellia_cbc: exit"));
}

struct encrypt_desc algo_camellia_cbc =
{
	.common = {
		.name = "camellia",
		.officname = "camellia",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_CAMELLIA_CBC,
		.algo_v2id =   IKEv2_ENCR_CAMELLIA_CBC,
		.algo_next =   NULL,
	},
	.enc_ctxsize =   sizeof(camellia_context),
	.enc_blocksize = CAMELLIA_BLOCK_SIZE,
	.ivsize =       CAMELLIA_BLOCK_SIZE,
	.keyminlen =    CAMELLIA_KEY_MIN_LEN,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.keymaxlen =    CAMELLIA_KEY_MAX_LEN,
	.do_crypt =     do_camellia_cbc,
};

static void do_camellia_ctr(u_int8_t *buf UNUSED, size_t buf_len UNUSED, PK11SymKey *symkey UNUSED,
                  u_int8_t *nonce_iv UNUSED, bool enc UNUSED)
{
	DBG(DBG_CRYPT, DBG_log("NSS do_camellia_ctr: stubb only"));
}

struct encrypt_desc algo_camellia_ctr =
{
	.common = {
		.name = "camellia_ctr",
		.officname = "camellia_ctr",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_CAMELLIA_CTR,
		.algo_v2id =   IKEv2_ENCR_CAMELLIA_CTR,
		.algo_next =   NULL,
	},
	.enc_ctxsize =   sizeof(camellia_context),
	.enc_blocksize = CAMELLIA_BLOCK_SIZE,
	.ivsize = 8,
	.keyminlen =    CAMELLIA_KEY_MIN_LEN,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.keymaxlen =    CAMELLIA_KEY_MAX_LEN,
	.do_crypt =     do_camellia_ctr,
};

void ike_alg_camellia_init(void)
{
	if (ike_alg_register_enc(&algo_camellia_cbc) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_camellia_cbc for IKE");
	if (ike_alg_register_enc(&algo_camellia_ctr) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_camellia_ctr for IKE");
}
