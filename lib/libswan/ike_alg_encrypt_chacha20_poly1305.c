/* chacha20 poly1305 for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#include <pkcs11.h>

#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_encrypt_ops.h"
#include "lsw-pfkeyv2.h"

/*
 * See: https://tools.ietf.org/html/rfc7634#section-2
 */

const struct encrypt_desc ike_alg_encrypt_chacha20_poly1305 = {
	.common = {
		.fqn = "CHACHA20_POLY1305",
		.names = "chacha20_poly1305,chacha20poly1305",
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_ENCR_CHACHA20_POLY1305,
#ifdef SADB_X_EALG_CHACHA20POLY1305
			[SADB_ALG_ID] = SADB_X_EALG_CHACHA20POLY1305,
#endif
		},
	},
	.keylen_omitted = true,
	.enc_blocksize = 16,
	.pad_to_blocksize = false,
	.wire_iv_size = 64/*bits*/ / 8,
	.salt_size = 32/*bits*/ / 8,
	.keydeflen = 256,
	.key_bit_lengths = { 256, },
	.aead_tag_size = 128 /*bits*/ / 8,
	.encrypt_netlink_xfrm_name = "rfc7539esp(chacha20,poly1305)",
	.encrypt_tcpdump_name = "chacha20_poly1305",
	.encrypt_ike_audit_name = "chacha20_poly1305",
	.encrypt_kernel_audit_name = "chacha20_poly1305",
#ifdef CKM_NSS_CHACHA20_POLY1305
	.nss = {
		.mechanism = CKM_NSS_CHACHA20_POLY1305,
	},
	.encrypt_ops = &ike_alg_encrypt_nss_aead_ops,
#endif
};
