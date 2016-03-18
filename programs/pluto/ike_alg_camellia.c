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
#include "lswfips.h"
#include "lswlog.h"

#include "ike_alg_nss_cbc.h"
#include "cbc_test_vectors.h"

static void do_camellia_cbc(u_int8_t *buf, size_t buf_len, PK11SymKey *symkey,
			    u_int8_t *iv, bool enc);

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
	.pad_to_blocksize = TRUE,
	.wire_iv_size =       CAMELLIA_BLOCK_SIZE,
	.keyminlen =    CAMELLIA_KEY_MIN_LEN,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.keymaxlen =    CAMELLIA_KEY_MAX_LEN,
	.do_crypt =     do_camellia_cbc,
};

static void do_camellia_cbc(u_int8_t *buf, size_t buf_len, PK11SymKey *symkey,
			    u_int8_t *iv, bool enc)
{
	ike_alg_nss_cbc(CKM_CAMELLIA_CBC, &algo_camellia_cbc,
			buf, buf_len, symkey, iv, enc);
}

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
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	CAMELLIA_BLOCK_SIZE,
	.keyminlen =    CAMELLIA_KEY_MIN_LEN,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.keymaxlen =    CAMELLIA_KEY_MAX_LEN,
	.do_crypt =     do_camellia_ctr,
};

void ike_alg_camellia_init(void)
{
	if (!test_camellia_cbc(&algo_camellia_cbc)) {
		loglog(RC_LOG_SERIOUS, "CKM_CAMELLIA_CBC: test failure");
		exit_pluto(PLUTO_EXIT_NSS_FAIL);
	}
	if (ike_alg_register_enc(&algo_camellia_cbc) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_camellia_cbc for IKE");

	/* test_camellia_ctr(&algo_camellia_ctr); */
	if (ike_alg_register_enc(&algo_camellia_ctr) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_camellia_ctr for IKE");
}
