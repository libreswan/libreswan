/*
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include "klips-crypto/aes_cbc.h"
#include "alg_info.h"
#include "ike_alg.h"

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include "lswconf.h"
#include "lswlog.h"

static void aes_xcbc_init_thunk(union hash_ctx *ctx)
{
	aes_xcbc_init(&ctx->ctx_aes_xcbc);
}

static void aes_xcbc_write_thunk(union hash_ctx *ctx, const unsigned char *datap, size_t length)
{
	aes_xcbc_write(&ctx->ctx_aes_xcbc, datap, length);
}

static void aes_xcbc_final_thunk(u_char *hash, union hash_ctx *ctx)
{
	aes_xcbc_final(hash, &ctx->ctx_aes_xcbc);
}

static void do_aes_cbc(u_int8_t *buf, size_t buf_len, PK11SymKey *symkey,
		   u_int8_t *iv, bool enc)
{

	u_int8_t iv_bak[AES_CBC_BLOCK_SIZE];
	u_int8_t *new_iv = NULL;    /* logic will avoid copy to NULL */
	u_int8_t *tmp_buf;

	CK_MECHANISM_TYPE ciphermech;
	SECItem ivitem;
	SECItem *secparam;
	PK11Context *enccontext;
	SECStatus rv;
	int outlen;

	DBG(DBG_CRYPT, DBG_log("NSS do_aes_cbc: enter"));
	ciphermech = CKM_AES_CBC; /*libreswan provides padding*/

	if (symkey == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "do_aes_cbc: NSS derived enc key in NULL\n");
		abort();
	}

	ivitem.type = siBuffer;
	ivitem.data = iv;
	ivitem.len = AES_CBC_BLOCK_SIZE;

	secparam = PK11_ParamFromIV(ciphermech, &ivitem);
	if (secparam == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "do_aes_cbc: Failure to set up PKCS11 param (err %d)\n",
		       PR_GetError());
		abort();
	}

	outlen = 0;
	tmp_buf = PR_Malloc((PRUint32)buf_len);

	if (!enc) {
		new_iv = iv_bak;
		memcpy(new_iv,
		       (char*) buf + buf_len - AES_CBC_BLOCK_SIZE,
		       AES_CBC_BLOCK_SIZE);
	}

	enccontext = PK11_CreateContextBySymKey(ciphermech,
						enc ? CKA_ENCRYPT : CKA_DECRYPT, symkey,
						secparam);
	if (enccontext == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "do_aes_cbc: PKCS11 context creation failure (err %d)\n",
		       PR_GetError());
		abort();
	}

	rv = PK11_CipherOp(enccontext, tmp_buf, &outlen, buf_len, buf,
			      buf_len);
	if (rv != SECSuccess) {
		loglog(RC_LOG_SERIOUS,
		       "do_aes_cbc: PKCS11 operation failure (err %d)\n",
		       PR_GetError());
		abort();
	}
	PK11_DestroyContext(enccontext, PR_TRUE);
	memcpy(buf, tmp_buf, buf_len);

	if (enc)
		new_iv = (u_int8_t*) buf + buf_len - AES_CBC_BLOCK_SIZE;

	memcpy(iv, new_iv, AES_CBC_BLOCK_SIZE);
	PR_Free(tmp_buf);

	if (secparam != NULL)
		SECITEM_FreeItem(secparam, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS do_aes_cbc: exit"));
}

struct encrypt_desc algo_aes_cbc =
{
	.common = {
		.name = "aes",
		.officname = "aes",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_AES_CBC,
		.algo_v2id =   IKEv2_ENCR_AES_CBC,
		.algo_next =   NULL,
	},
	.enc_ctxsize =   sizeof(aes_context),
	.enc_blocksize = AES_CBC_BLOCK_SIZE,
	.ivsize =       AES_CBC_BLOCK_SIZE,
	.keyminlen =    AES_KEY_MIN_LEN,
	.keydeflen =    AES_KEY_DEF_LEN,
	.keymaxlen =    AES_KEY_MAX_LEN,
	.do_crypt =     do_aes_cbc,
};

static void do_aes_ctr(u_int8_t *buf UNUSED, size_t buf_len UNUSED, PK11SymKey *symkey UNUSED,
                  u_int8_t *nonce_iv UNUSED, bool enc UNUSED)
{
	DBG(DBG_CRYPT, DBG_log("NSS do_aes_ctr: stubb only"));
}

struct encrypt_desc algo_aes_ctr =
{
	.common = {
		.name = "aes_ctr",
		.officname = "aes_ctr",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_AES_CTR,
		.algo_v2id =   IKEv2_ENCR_AES_CTR,
		.algo_next =   NULL,
	},
	.enc_ctxsize =   sizeof(aes_context),
	.enc_blocksize = AES_BLOCK_SIZE,
	.ivsize = 8,
	.keyminlen =    AES_KEY_MIN_LEN,
	.keydeflen =    AES_KEY_DEF_LEN,
	.keymaxlen =    AES_KEY_MAX_LEN,
	.do_crypt =     do_aes_ctr,
};

static struct hash_desc hash_desc_aes_xcbc = {
        .common = { .officname =  "aes_xcbc",
                    .algo_type = IKE_ALG_HASH,
                    .algo_id = OAKLEY_AES_XCBC, /* stolen from IKEv2 */
                    .algo_v2id = IKEv2_PRF_AES128_XCBC,
                    .algo_next = NULL, },
        .hash_ctx_size = sizeof(aes_xcbc_context),
        .hash_key_size = AES_XCBC_DIGEST_SIZE,
        .hash_digest_len = AES_XCBC_DIGEST_SIZE,
        .hash_integ_len = 0,    /* Not applicable */
        .hash_block_size = AES_CBC_BLOCK_SIZE,
        .hash_init = aes_xcbc_init_thunk,
        .hash_update = aes_xcbc_write_thunk,
        .hash_final = aes_xcbc_final_thunk,
};

#ifdef NOT_YET
static struct hash_desc integ_desc_aes_xcbc = {
        .common = { .officname =  "aes_xcbc",
                    .algo_type = IKE_ALG_INTEG,
                    .algo_id = OAKLEY_AES_XCBC, /* stolen from IKEv2 */
                    .algo_v2id = IKEv2_AUTH_AES_XCBC_96,
                    .algo_next = NULL, },
        .hash_ctx_size = sizeof(aes_xcbc_context),
        .hash_key_size = AES_XCBC_DIGEST_SIZE,
        .hash_digest_len = AES_XCBC_DIGEST_SIZE,
        .hash_integ_len = AES_XCBC_DIGEST_SIZE_TRUNC, /* XXX 96 */
        .hash_block_size = AES_CBC_BLOCK_SIZE,
        .hash_init = aes_xcbc_init_thunk,
        .hash_update = aes_xcbc_write_thunk,
        .hash_final = aes_xcbc_final_thunk,
};
#endif

void ike_alg_aes_init(void)
{
	if (ike_alg_register_enc(&algo_aes_cbc) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_cbc for IKE");
	if (ike_alg_register_enc(&algo_aes_ctr) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ctr for IKE");

	/* Waiting on NSS support - but we need registration so ESP will work */
	if (ike_alg_register_hash(&hash_desc_aes_xcbc) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register hash algo_aes_xcbc for IKE");
#if 0
	ike_alg_add(&integ_desc_aes_xcbc.common);
#endif
}
