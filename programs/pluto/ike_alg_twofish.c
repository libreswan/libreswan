/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2011-2012 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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
#include "libtwofish/twofish_cbc.h"
#include "alg_info.h"
#include "ike_alg.h"

#define  TWOFISH_CBC_BLOCK_SIZE (128 / BITS_PER_BYTE)
#define  TWOFISH_KEY_MIN_LEN    128
#define  TWOFISH_KEY_DEF_LEN    128
#define  TWOFISH_KEY_MAX_LEN    256

static void do_twofish(u_int8_t *buf, size_t buf_size, PK11SymKey *key,
		       u_int8_t *iv, bool enc)
{
	twofish_context twofish_ctx;
	char iv_bak[TWOFISH_CBC_BLOCK_SIZE];
	char *new_iv = NULL;    /* logic will avoid copy to NULL */
	u_int8_t *bare_key_ptr;
	size_t bare_key_len;

	/* unpack key from PK11SymKey (or crash!) */
	{
		SECStatus status = PK11_ExtractKeyValue(key);
		SECItem *keydata;

		passert(status == SECSuccess);
		keydata = PK11_GetKeyData(key);
		bare_key_ptr = keydata->data;
		bare_key_len = keydata->len;
		// SECITEM_FreeItem(keydata, PR_TRUE);
	}

	twofish_set_key(&twofish_ctx, bare_key_ptr, bare_key_len);
	/*
	 *	my TWOFISH cbc does not touch passed IV (optimization for
	 *	ESP handling), so I must "emulate" des-like IV
	 *	crunching
	 */
	if (!enc) {
		memcpy(new_iv = iv_bak,
		       (char*) buf + buf_size - TWOFISH_CBC_BLOCK_SIZE,
		       TWOFISH_CBC_BLOCK_SIZE);
	}

	twofish_cbc_encrypt(&twofish_ctx, buf, buf, buf_size, iv, enc);

	if (enc)
		new_iv = (char*) buf + buf_size - TWOFISH_CBC_BLOCK_SIZE;

	memcpy(iv, new_iv, TWOFISH_CBC_BLOCK_SIZE);
}

static struct encrypt_desc encrypt_desc_twofish =
{
	.common = {
		.name = "twofish",
		.officname = "twofish",
		.algo_type = IKE_ALG_ENCRYPT,
		.algo_id = OAKLEY_TWOFISH_CBC,
		.algo_v2id = IKEv2_ENCR_TWOFISH_CBC,
		.algo_next = NULL,
	},
	.enc_ctxsize = sizeof(twofish_context),
	.enc_blocksize = TWOFISH_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size = TWOFISH_CBC_BLOCK_SIZE,
	.keydeflen = TWOFISH_KEY_MIN_LEN,
	.keyminlen = TWOFISH_KEY_DEF_LEN,
	.keymaxlen = TWOFISH_KEY_MAX_LEN,
	.do_crypt = do_twofish,
};

static struct encrypt_desc encrypt_desc_twofish_ssh =
{
	.common = {
		.name = "twofish_ssh", /* We don't know if this is right */
		.officname = "twofish_ssh", /* We don't know if this is right */
		.algo_type = IKE_ALG_ENCRYPT,
		.algo_id = OAKLEY_TWOFISH_CBC_SSH,
		.algo_v2id = IKEv2_ENCR_TWOFISH_CBC_SSH,
		.algo_next = NULL,
	},
	.enc_ctxsize = sizeof(twofish_context),
	.enc_blocksize = TWOFISH_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size = TWOFISH_CBC_BLOCK_SIZE,
	.keydeflen = TWOFISH_KEY_MIN_LEN,
	.keyminlen = TWOFISH_KEY_DEF_LEN,
	.keymaxlen = TWOFISH_KEY_MAX_LEN,
	.do_crypt = do_twofish,
};

void ike_alg_twofish_init(void)
{
	if (!ike_alg_register_enc(&encrypt_desc_twofish_ssh))
		libreswan_log(
			"ike_alg_twofish_init(): Experimental OAKLEY_TWOFISH_CBC_SSH activation failed");

	if (!ike_alg_register_enc(&encrypt_desc_twofish))
		libreswan_log(
			"ike_alg_twofish_init(): OAKLEY_TWOFISH_CBC activation failed");
}
