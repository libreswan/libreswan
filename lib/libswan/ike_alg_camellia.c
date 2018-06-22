/*
 * Copyright (C) 2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Paul Wouters <paul@libreswan.org>
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
#include "lswlog.h"
#include "ike_alg.h"

#include "ike_alg_encrypt_nss_cbc_ops.h"
#include "ike_alg_camellia.h"

/* Camellia is a drop-in replacement for AES */

#ifndef CAMELLIA_BLOCK_SIZE
# define CAMELLIA_BLOCK_SIZE  16
#endif

#if CAMELLIA_BLOCK_SIZE == 32
#define CAMELLIA_KS_LENGTH   120
#define CAMELLIA_RC_LENGTH    29
#else
#define CAMELLIA_KS_LENGTH   (4 * CAMELLIA_BLOCK_SIZE)
#define CAMELLIA_RC_LENGTH   ((9 * CAMELLIA_BLOCK_SIZE) / 8 - 8)
#endif

typedef struct {
	u_int32_t camellia_Nkey;                     // the number of words in the key input block
	u_int32_t camellia_Nrnd;                     // the number of cipher rounds
	u_int32_t camellia_e_key[CAMELLIA_KS_LENGTH];     // the encryption key schedule
	u_int32_t camellia_d_key[CAMELLIA_KS_LENGTH];     // the decryption key schedule
} camellia_context;

struct encrypt_desc ike_alg_encrypt_camellia_cbc =
{
	.common = {
		.name = "camellia",
		.fqn = "CAMELLIA_CBC",
		.names = { "camellia", "camellia_cbc", },
		.officname = "camellia",
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_CAMELLIA_CBC,
			[IKEv1_ESP_ID] = ESP_CAMELLIA,
			[IKEv2_ALG_ID] = IKEv2_ENCR_CAMELLIA_CBC,
		},
	},
	.nss = {
		.mechanism = CKM_CAMELLIA_CBC,
	},
	.enc_blocksize = CAMELLIA_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =       CAMELLIA_BLOCK_SIZE,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.encrypt_ops = &ike_alg_encrypt_nss_cbc_ops,
};

struct encrypt_desc ike_alg_encrypt_camellia_ctr =
{
	.common = {
		.name = "camellia_ctr",
		.fqn = "CAMELLIA_CTR",
		.names = { "camellia_ctr", },
		.officname = "camellia_ctr",
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_CAMELLIA_CTR,
			[IKEv1_ESP_ID] = ESP_CAMELLIA_CTR, /* not assigned in/for IKEv1 */
			[IKEv2_ALG_ID] = IKEv2_ENCR_CAMELLIA_CTR,
		},
	},
	.enc_blocksize = CAMELLIA_BLOCK_SIZE,
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	CAMELLIA_BLOCK_SIZE,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, }
};
