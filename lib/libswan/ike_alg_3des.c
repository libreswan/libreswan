/* 3des, for libreswan
 *
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <prerror.h>
#include <prmem.h>
#include <blapit.h>

#include <libreswan.h>

#include "constants.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_3des.h"
#include "ike_alg_nss_cbc.h"

const struct encrypt_desc ike_alg_encrypt_3des_cbc =
{
	.common = {
		.name = "3des_cbc",
		.fqn = "3DES_CBC",
		.names = { "3des", "3des_cbc", },
		.officname =     "3des",
		.algo_type =     IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_3DES_CBC,
			[IKEv1_ESP_ID] = ESP_3DES,
			[IKEv2_ALG_ID] = IKEv2_ENCR_3DES,
		},
		.fips =          TRUE,
	},
	.nss = {
		.mechanism = CKM_DES3_CBC,
	},
	.enc_blocksize =    DES_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =           DES_CBC_BLOCK_SIZE,
	.keylen_omitted = TRUE,
	.keydeflen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.key_bit_lengths = { DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE, },
	.encrypt_ops = &ike_alg_nss_cbc_encrypt_ops,
};
