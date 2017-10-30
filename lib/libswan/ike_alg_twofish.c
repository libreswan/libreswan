/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2011-2012 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016-2017 Andrew Cagney <cagney@gnu.org>
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
#include "lswlog.h"
#include "libtwofish/twofish_cbc.h"
#include "ike_alg.h"
#include "ike_alg_twofish.h"
#include "ietf_constants.h"

static void do_twofish(const struct encrypt_desc *alg UNUSED,
		       u_int8_t *buf, size_t buf_size, PK11SymKey *key,
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

static void twofish_check(const struct encrypt_desc *alg UNUSED)
{
}

static const struct encrypt_ops twofish_encrypt_ops = {
	.check = twofish_check,
	.do_crypt = do_twofish,
};

const struct encrypt_desc ike_alg_encrypt_twofish_cbc =
{
	.common = {
		.name = "twofish",
		.fqn = "TWOFISH_CBC",
		.names = { "twofish", "twofish_cbc", },
		.officname = "twofish",
		.algo_type = IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_TWOFISH_CBC,
			[IKEv1_ESP_ID] = ESP_TWOFISH,
			[IKEv2_ALG_ID] = IKEv2_ENCR_TWOFISH_CBC,
		},
	},
	.enc_blocksize = TWOFISH_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size = TWOFISH_CBC_BLOCK_SIZE,
	.keydeflen = TWOFISH_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.encrypt_ops = &twofish_encrypt_ops,
};

const struct encrypt_desc ike_alg_encrypt_twofish_ssh =
{
	.common = {
		.name = "twofish_ssh", /* We don't know if this is right */
		.fqn = "TWOFISH_SSH", /* We don't know if this is right */
		.names = { "twofish_ssh", "twofish_cbc_ssh", },
		.officname = "twofish_ssh", /* We don't know if this is right */
		.algo_type = IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_TWOFISH_CBC_SSH,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_ENCR_TWOFISH_CBC_SSH,
		},
	},
	.enc_blocksize = TWOFISH_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size = TWOFISH_CBC_BLOCK_SIZE,
	.keydeflen = TWOFISH_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.encrypt_ops = &twofish_encrypt_ops,
};
