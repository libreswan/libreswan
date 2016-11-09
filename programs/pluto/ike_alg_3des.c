/* 3des, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <prerror.h>
#include <prmem.h>

#include <libreswan.h>

#include "constants.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_3des.h"

static void do_3des_nss(u_int8_t *buf, size_t buf_len,
			PK11SymKey *symkey, u_int8_t *iv, bool enc)
{
	u_int8_t *tmp_buf;
	u_int8_t *new_iv;

	CK_MECHANISM_TYPE ciphermech;
	SECItem ivitem;
	SECItem *secparam;
	PK11Context *enccontext = NULL;
	SECStatus rv;
	int outlen;

	DBG(DBG_CRYPT,
		DBG_log("NSS: do_3des init start"));

	ciphermech = CKM_DES3_CBC;	/* libreswan provides padding */

	if (symkey == NULL) {
		loglog(RC_LOG_SERIOUS,
			"do_3des: NSS derived enc key is NULL");
		abort();
	}

	ivitem.type = siBuffer;
	ivitem.data = iv;
	ivitem.len = DES_CBC_BLOCK_SIZE;

	secparam = PK11_ParamFromIV(ciphermech, &ivitem);
	if (secparam == NULL) {
		loglog(RC_LOG_SERIOUS,
			"do_3des: Failure to set up PKCS11 param (err %d)",
			PR_GetError());
		abort();
	}

	outlen = 0;
	tmp_buf = PR_Malloc((PRUint32)buf_len);
	new_iv = (u_int8_t*)PR_Malloc((PRUint32)DES_CBC_BLOCK_SIZE);

	if (!enc)
		memcpy(new_iv, (char*) buf + buf_len - DES_CBC_BLOCK_SIZE,
			DES_CBC_BLOCK_SIZE);

	enccontext = PK11_CreateContextBySymKey(ciphermech,
						enc ? CKA_ENCRYPT :
						CKA_DECRYPT, symkey,
						secparam);
	if (enccontext == NULL) {
		loglog(RC_LOG_SERIOUS,
			"do_3des: PKCS11 context creation failure (err %d)",
			PR_GetError());
		abort();
	}
	rv = PK11_CipherOp(enccontext, tmp_buf, &outlen, buf_len, buf,
			buf_len);
	if (rv != SECSuccess) {
		loglog(RC_LOG_SERIOUS,
			"do_3des: PKCS11 operation failure (err %d)",
			PR_GetError());
		abort();
	}

	if (enc)
		memcpy(new_iv, (char*) tmp_buf + buf_len - DES_CBC_BLOCK_SIZE,
			DES_CBC_BLOCK_SIZE);

	memcpy(buf, tmp_buf, buf_len);
	memcpy(iv, new_iv, DES_CBC_BLOCK_SIZE);
	PK11_DestroyContext(enccontext, PR_TRUE);
	PR_Free(tmp_buf);
	PR_Free(new_iv);

	if (secparam != NULL)
		SECITEM_FreeItem(secparam, PR_TRUE);

	DBG(DBG_CRYPT,
		DBG_log("NSS: do_3des init end"));
}

/* encrypt or decrypt part of an IKE message using 3DES
 * See RFC 2409 "IKE" Appendix B
 */
static void do_3des(u_int8_t *buf, size_t buf_len,
		    PK11SymKey *key, u_int8_t *iv, bool enc)
{
	passert(key != NULL);
	do_3des_nss(buf, buf_len, key, iv, enc);
}

struct encrypt_desc ike_alg_encrypt_3des_cbc =
{
	.common = {
		.name = "3des_cbc",
		.officname =     "3des",
		.algo_type =     IKE_ALG_ENCRYPT,
		.ikev1_oakley_id = OAKLEY_3DES_CBC,
		.ikev1_esp_id = ESP_3DES,
		.ikev2_id = IKEv2_ENCR_3DES,
		.fips =          TRUE,
		.do_ike_test = ike_alg_true,
	},
	.enc_ctxsize =      8 * 16 * 3, /* sizeof(des_key_schedule) * 3 */
	.enc_blocksize =    DES_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =           DES_CBC_BLOCK_SIZE,
	.keylen_omitted = TRUE,
	.keydeflen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.keyminlen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.keymaxlen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.do_crypt =         do_3des,
};
