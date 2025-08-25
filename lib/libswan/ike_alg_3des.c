/* 3des, for libreswan
 *
 * Copyright (C) 2016-2017 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include "constants.h"		/* for BYTES_FOR_BITS() */
#include "ietf_constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_encrypt_ops.h"
#include "lsw-pfkeyv2.h"	/* for SADB_*ALG_* */

const struct encrypt_desc ike_alg_encrypt_3des_cbc =
{
	.common = {
		.fqn = "3DES_CBC",
		.names = "3des,3des_cbc",
		.type =     IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_3DES_CBC,
			[IKEv1_IPSEC_ID] = IKEv1_ESP_3DES,
			[IKEv2_ALG_ID] = IKEv2_ENCR_3DES,
#ifdef SADB_EALG_3DESCBC
			[SADB_ALG_ID] = SADB_EALG_3DESCBC,
#endif
		},
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_DES3_CBC,
	},
	.enc_blocksize =    DES_CBC_BLOCK_SIZE,
	.pad_to_blocksize = true,
	.wire_iv_size =           DES_CBC_BLOCK_SIZE,
	.keylen_omitted = true,
	.keydeflen =        DES_CBC_BLOCK_SIZE * 3 * BITS_IN_BYTE,
	.key_bit_lengths = { DES_CBC_BLOCK_SIZE * 3 * BITS_IN_BYTE, },
	.encrypt_ops = &ike_alg_encrypt_nss_cbc_ops,
	.encrypt_netlink_xfrm_name = "des3_ede",
	.encrypt_tcpdump_name = "3des",
	.encrypt_ike_audit_name = "3des",
	.encrypt_kernel_audit_name = "3DES",
};
