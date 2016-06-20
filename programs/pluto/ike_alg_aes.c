/*
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2015 Andrew Cagney <andrew.cagney@gmail.com>
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
#include "lswfips.h"
#include "lswlog.h"
#include "ike_alg_nss_cbc.h"
#include "ctr_test_vectors.h"
#include "cbc_test_vectors.h"
#include "gcm_test_vectors.h"

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
		       u_int8_t *iv, bool enc);

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
	.pad_to_blocksize = TRUE,
	.wire_iv_size =       AES_CBC_BLOCK_SIZE,
	.keyminlen =    AES_KEY_MIN_LEN,
	.keydeflen =    AES_KEY_DEF_LEN,
	.keymaxlen =    AES_KEY_MAX_LEN,
	.do_crypt =     do_aes_cbc,
};

static void do_aes_cbc(u_int8_t *buf, size_t buf_len, PK11SymKey *symkey,
		       u_int8_t *iv, bool enc)
{
	ike_alg_nss_cbc(CKM_AES_CBC, &algo_aes_cbc,
			buf, buf_len, symkey, iv, enc);
}

static void do_aes_ctr(u_int8_t *buf, size_t buf_len, PK11SymKey *sym_key,
		       u_int8_t *counter_block, bool encrypt)
{
	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: enter"));

	if (sym_key == NULL) {
		loglog(RC_LOG_SERIOUS, "do_aes_ctr: NSS derived enc key in NULL");
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}

	CK_AES_CTR_PARAMS counter_param;
	counter_param.ulCounterBits = sizeof(u_int32_t) * 8;/* Per RFC 3686 */
	memcpy(counter_param.cb, counter_block, sizeof(counter_param.cb));
	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&counter_param;
	param.len = sizeof(counter_param);

	/* Output buffer for transformed data.  */
	u_int8_t *out_buf = PR_Malloc((PRUint32)buf_len);
	unsigned int out_len = 0;

	if (encrypt) {
		SECStatus rv = PK11_Encrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf_len,
					    buf, buf_len);
		if (rv != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_ctr: PK11_Encrypt failure (err %d)", PR_GetError());
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf_len,
					    buf, buf_len);
		if (rv != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_ctr: PK11_Decrypt failure (err %d)", PR_GetError());
			exit_pluto(PLUTO_EXIT_NSS_FAIL);
		}
	}

	memcpy(buf, out_buf, buf_len);
	PR_Free(out_buf);

	/*
	 * Finally update the counter located at the end of the
	 * counter_block. It is incremented by 1 for every full or
	 * partial block encoded/decoded.
	 *
	 * There's a portability assumption here that the IV buffer is
	 * at least sizeof(u_int32_t) (4-byte) aligned.
	 */
	u_int32_t *counter = (u_int32_t*)(counter_block + AES_BLOCK_SIZE
					  - sizeof(u_int32_t));
	u_int32_t old_counter = ntohl(*counter);
	size_t increment = (buf_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	u_int32_t new_counter = old_counter + increment;
	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: counter-block updated from 0x%lx to 0x%lx for %zd bytes",
			       (unsigned long)old_counter, (unsigned long)new_counter, buf_len));
	if (new_counter < old_counter) {
		/* Wrap ... */
		loglog(RC_LOG_SERIOUS,
		       "do_aes_ctr: counter wrapped");
		/* what next??? */
	}
	*counter = htonl(new_counter);

	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: exit"));
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
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	8,
	.salt_size = 4,
	.keyminlen =    AES_KEY_MIN_LEN,
	.keydeflen =    AES_KEY_DEF_LEN,
	.keymaxlen =    AES_KEY_MAX_LEN,
	.do_crypt =     do_aes_ctr,
};

bool do_aes_gcm(u_int8_t *salt, size_t salt_size,
		u_int8_t *wire_iv, size_t wire_iv_size,
		u_int8_t *aad, size_t aad_size,
		u_int8_t *text_and_tag,
		size_t text_size, size_t tag_size,
		PK11SymKey *sym_key, bool enc)
{
	/* See pk11gcmtest.c */
	bool ok = TRUE;

	u_int8_t iv[AES_BLOCK_SIZE];
	passert(sizeof iv >= wire_iv_size + salt_size);
	memcpy(iv, salt, salt_size);
	memcpy(iv + salt_size, wire_iv, wire_iv_size);

	CK_GCM_PARAMS gcm_params;
	gcm_params.pIv = iv;
	gcm_params.ulIvLen = salt_size + wire_iv_size;
	gcm_params.pAAD = aad;
	gcm_params.ulAADLen = aad_size;
	gcm_params.ulTagBits = tag_size * 8;

	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&gcm_params;
	param.len = sizeof gcm_params;

	/* Output buffer for transformed data.  */
	size_t text_and_tag_size = text_size + tag_size;
	u_int8_t *out_buf = PR_Malloc(text_and_tag_size);
	unsigned int out_len = 0;

	if (enc) {
		SECStatus rv = PK11_Encrypt(sym_key, CKM_AES_GCM, &param,
					    out_buf, &out_len, text_and_tag_size,
					    text_and_tag, text_size);
		if (rv != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_gcm: PK11_Encrypt failure (err %d)", PR_GetError());
			ok = FALSE;
		} else if (out_len != text_and_tag_size) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_gcm: PK11_Encrypt output length of %u not the expected %zd",
			       out_len, text_and_tag_size);
			ok = FALSE;
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_GCM, &param,
					    out_buf, &out_len, text_and_tag_size,
					    text_and_tag, text_and_tag_size);
		if (rv != SECSuccess) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_gcm: PK11_Decrypt failure (err %d)", PR_GetError());
			ok = FALSE;
		} else if (out_len != text_size) {
			loglog(RC_LOG_SERIOUS,
			       "do_aes_gcm: PK11_Decrypt output length of %u not the expected %zd",
			       out_len, text_size);
			ok = FALSE;
		}
	}

	memcpy(text_and_tag, out_buf, out_len);
	PR_Free(out_buf);

	return ok;
}

static struct encrypt_desc algo_aes_gcm_8 =
{
	.common = {
		.name = "aes_gcm",
		.officname = "aes_gcm",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_AES_GCM_8,
		.algo_v2id =   IKEv2_ENCR_AES_GCM_8,
		.algo_next =   NULL,
	},
	.enc_ctxsize =   sizeof(aes_context),
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	8,
	.salt_size = AES_GCM_SALT_BYTES,
	.keyminlen =    AES_GCM_KEY_MIN_LEN,
	.keydeflen =    AES_GCM_KEY_DEF_LEN,
	.keymaxlen =    AES_GCM_KEY_MAX_LEN,
	.aead_tag_size = 8,
	.do_aead_crypt_auth =     do_aes_gcm,
};

static struct encrypt_desc algo_aes_gcm_12 =
{
	.common = {
		.name = "aes_gcm_12",
		.officname = "aes_gcm_12",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_AES_GCM_12,
		.algo_v2id =   IKEv2_ENCR_AES_GCM_12,
		.algo_next =   NULL,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	.salt_size = AES_GCM_SALT_BYTES,
	.keyminlen =     AEAD_AES_KEY_MIN_LEN,
	.keydeflen =     AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =     AEAD_AES_KEY_MAX_LEN,
	.aead_tag_size = 12,
	.do_aead_crypt_auth =     do_aes_gcm,
};

static struct encrypt_desc algo_aes_gcm_16 =
{
	.common = {
		.name = "aes_gcm_16",
		.officname = "aes_gcm_16",
		.algo_type =  IKE_ALG_ENCRYPT,
		.algo_id =     OAKLEY_AES_GCM_16,
		.algo_v2id =    IKEv2_ENCR_AES_GCM_16,
		.algo_next =  NULL,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	.salt_size = AES_GCM_SALT_BYTES,
	.keyminlen =    AEAD_AES_KEY_MIN_LEN,
	.keydeflen =    AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =    AEAD_AES_KEY_MAX_LEN,
	.aead_tag_size = 16,
	.do_aead_crypt_auth =     do_aes_gcm,
};

#ifdef NOT_YET
/*
 * XXX: This code is duplicated in kernel_netlink.c.  Once this is
 * enabled, the latter can be deleted.
 */
static struct encrypt_desc algo_aes_ccm_8 =
{
	.common = {
		.name = "aes_ccm_8",
		.officname = "aes_ccm_8",
		.algo_type =    IKE_ALG_ENCRYPT,
		.algo_id =      OAKLEY_AES_CCM_8,
		.algo_v2id =    IKEv2_ENCR_AES_CCM_8,
		.algo_next =    NULL,
	},
	.enc_blocksize =  AES_BLOCK_SIZE,
	.wire_iv_size =  8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keyminlen =      AEAD_AES_KEY_MIN_LEN,
	.keydeflen =      AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =      AEAD_AES_KEY_MAX_LEN,
};

static struct encrypt_desc algo_aes_ccm_12 =
{
	.common = {
		.name = "aes_ccm_12",
		.officname = "aes_ccm_12",
		.algo_type =    IKE_ALG_ENCRYPT,
		.algo_id =      OAKLEY_AES_CCM_12,
		.algo_v2id =    IKEv2_ENCR_AES_CCM_12,
		.algo_next =    NULL,
	},
	.enc_blocksize =  AES_BLOCK_SIZE,
	.wire_iv_size =  8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keyminlen =      AEAD_AES_KEY_MIN_LEN,
	.keydeflen =      AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =      AEAD_AES_KEY_MAX_LEN,
};

static struct encrypt_desc algo_aes_ccm_16 =
{
	.common = {
		.name = "aes_ccm_16",
		.officname = "aes_ccm_16",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_id =      OAKLEY_AES_CCM_16,
		.algo_v2id =   IKEv2_ENCR_AES_CCM_16,
		.algo_next =   NULL,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keyminlen =     AEAD_AES_KEY_MIN_LEN,
	.keydeflen =     AEAD_AES_KEY_DEF_LEN,
	.keymaxlen =     AEAD_AES_KEY_MAX_LEN,
};
#endif

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
	if (!test_aes_cbc(&algo_aes_cbc)) {
		loglog(RC_LOG_SERIOUS, "CKM_AES_CBC: test failure");
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}
	if (ike_alg_register_enc(&algo_aes_cbc) != 1) {
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_cbc for IKE");
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}

	if (!test_aes_ctr(&algo_aes_ctr)) {
		loglog(RC_LOG_SERIOUS, "CKM_AES_CTR: test failure");
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}
	if (ike_alg_register_enc(&algo_aes_ctr) != 1) {
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ctr for IKE");
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}

	if (!test_aes_gcm()) {
		loglog(RC_LOG_SERIOUS, "CKM_AES_GCM: test failure");
	}
	if (ike_alg_register_enc(&algo_aes_gcm_8) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_8 for IKE");
	if (ike_alg_register_enc(&algo_aes_gcm_12) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_12 for IKE");
	if (ike_alg_register_enc(&algo_aes_gcm_16) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_16 for IKE");

#ifdef NOT_YET
	/*
	 * XXX: This code is duplicated in kernel_netlink.c.  Once
	 * this is enabled, the latter can be deleted.
	 */
	if (!ike_alg_register_enc(&algo_aes_ccm_8))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_8 for IKE");
	if (!ike_alg_register_enc(&algo_aes_ccm_12))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_12 for IKE");
	if (!ike_alg_register_enc(&algo_aes_ccm_16))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_16 for IKE");
#endif

	/* Waiting on NSS support - but we need registration so ESP will work */
	if (ike_alg_register_hash(&hash_desc_aes_xcbc) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register hash algo_aes_xcbc for IKE");
#if 0
	ike_alg_add(&integ_desc_aes_xcbc.common);
#endif
}
