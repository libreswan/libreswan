/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
#include "libserpent/serpent_cbc.h"
#include "alg_info.h"
#include "ike_alg.h"

#define  SERPENT_CBC_BLOCK_SIZE (128 / BITS_PER_BYTE)
#define  SERPENT_KEY_MIN_LEN    128
#define  SERPENT_KEY_DEF_LEN    128
#define  SERPENT_KEY_MAX_LEN    256

static void do_serpent(u_int8_t *buf, size_t buf_size, PK11SymKey *key,
		       u_int8_t *iv, bool enc)
{
	serpent_context serpent_ctx;
	u_int8_t iv_bak[SERPENT_CBC_BLOCK_SIZE];
	u_int8_t *new_iv = buf + buf_size - SERPENT_CBC_BLOCK_SIZE;
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

	serpent_set_key(&serpent_ctx, bare_key_ptr, bare_key_len);
	/*
	 *	my SERPENT cbc does not touch passed IV (optimization for
	 *	ESP handling), so I must "emulate" des-like IV
	 *	crunching
	 */
	if (!enc) {
		memcpy(iv_bak, new_iv, SERPENT_CBC_BLOCK_SIZE);
		new_iv = iv_bak;
	}

	serpent_cbc_encrypt(&serpent_ctx, buf, buf, buf_size, iv, enc);

	memcpy(iv, new_iv, SERPENT_CBC_BLOCK_SIZE);
}

static struct encrypt_desc encrypt_desc_serpent =
{
	.common = {
		.name = "serpent",
		.officname = "serpent",
		.algo_type = IKE_ALG_ENCRYPT,
		.algo_id = OAKLEY_SERPENT_CBC,
		.algo_v2id = IKEv2_ENCR_SERPENT_CBC,
		.algo_next = NULL,
	},
	.enc_ctxsize = sizeof(struct serpent_context),
	.enc_blocksize = SERPENT_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size = SERPENT_CBC_BLOCK_SIZE,
	.keyminlen = SERPENT_KEY_MIN_LEN,
	.keydeflen = SERPENT_KEY_DEF_LEN,
	.keymaxlen = SERPENT_KEY_MAX_LEN,
	.do_crypt = do_serpent,
};

void ike_alg_serpent_init(void)
{
	if (!ike_alg_register_enc(&encrypt_desc_serpent))
		libreswan_log(
			"ike_alg_serpent_init(): OAKLEY_SERPENT_CBC activation failed");
}
