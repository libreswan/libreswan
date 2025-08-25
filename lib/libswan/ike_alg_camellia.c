/*
 * Copyright (C) 2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Paul Wouters <paul@libreswan.org>
 *
 * Based on ike_alg_camellia.c
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_encrypt_ops.h"
#include "lsw-pfkeyv2.h"	/* for SADB_*ALG_* */

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
	uint32_t camellia_Nkey;                     // the number of words in the key input block
	uint32_t camellia_Nrnd;                     // the number of cipher rounds
	uint32_t camellia_e_key[CAMELLIA_KS_LENGTH];     // the encryption key schedule
	uint32_t camellia_d_key[CAMELLIA_KS_LENGTH];     // the decryption key schedule
} camellia_context;

const struct encrypt_desc ike_alg_encrypt_camellia_cbc =
{
	.common = {
		.fqn = "CAMELLIA_CBC",
		.names = "camellia,camellia_cbc",
		.type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_CAMELLIA_CBC,
			[IKEv1_IPSEC_ID] = IKEv1_ESP_CAMELLIA,
			[IKEv2_ALG_ID] = IKEv2_ENCR_CAMELLIA_CBC,
#ifdef SADB_X_EALG_CAMELLIACBC
			[SADB_ALG_ID] = SADB_X_EALG_CAMELLIACBC,
#endif
		},
	},
	.nss = {
		.mechanism = CKM_CAMELLIA_CBC,
	},
	.enc_blocksize = CAMELLIA_BLOCK_SIZE,
	.pad_to_blocksize = true,
	.wire_iv_size =       CAMELLIA_BLOCK_SIZE,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.encrypt_ops = &ike_alg_encrypt_nss_cbc_ops,
	.encrypt_netlink_xfrm_name = "cbc(camellia)",
	.encrypt_tcpdump_name = "camellia",
	.encrypt_ike_audit_name = "camellia",
	.encrypt_kernel_audit_name = "CAMELLIA",
};

const struct encrypt_desc ike_alg_encrypt_camellia_ctr =
{
	.common = {
		.fqn = "CAMELLIA_CTR",
		.names = "camellia_ctr",
		.type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_CAMELLIA_CTR,
			[IKEv1_IPSEC_ID] = IKEv1_ESP_CAMELLIA_CTR, /* not assigned in/for IKEv1 */
			[IKEv2_ALG_ID] = IKEv2_ENCR_CAMELLIA_CTR,
		},
	},
	.enc_blocksize = CAMELLIA_BLOCK_SIZE,
	.pad_to_blocksize = false,
	.wire_iv_size =	CAMELLIA_BLOCK_SIZE,
	.keydeflen =    CAMELLIA_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.encrypt_tcpdump_name = "camellia_ctr",
	.encrypt_ike_audit_name = "camellia_ctr",
	.encrypt_kernel_audit_name = "CAMELLIA_CTR",
};
