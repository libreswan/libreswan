/*
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

#include "ietf_constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "sadb.h"

/*
 * https://tools.ietf.org/html/rfc2144.html
 * https://tools.ietf.org/html/rfc2451#section-2.2
 * https://en.wikipedia.org/wiki/CAST-128
 *
 * ESP_CAST is the cast5 algorithm, not cast6.  Avoid padding by only
 * allowing 128-bit keys.
 */

const struct encrypt_desc ike_alg_encrypt_cast_cbc =
{
	.common = {
		.name = "cast",
		.fqn = "CAST_CBC",
		.names = { "cast", "cast_cbc", },
		.algo_type = IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_CAST_CBC,
			[IKEv1_ESP_ID] = ESP_CAST,
			[IKEv2_ALG_ID] = IKEv2_ENCR_CAST,
		},
	},
	.enc_blocksize = 8,
	.pad_to_blocksize = true,
	.wire_iv_size = 8,
	.keydeflen = CAST_KEY_DEF_LEN,
	.key_bit_lengths = { CAST_KEY_DEF_LEN, },
#ifdef SADB_X_EALG_CASTCBC
	.encrypt_sadb_ealg_id = SADB_X_EALG_CASTCBC,
#endif
#ifdef SADB_X_EALG_CAST128CBC
	.encrypt_sadb_ealg_id = SADB_X_EALG_CAST128CBC,
#endif
	.encrypt_netlink_xfrm_name = "cast5",
	.encrypt_tcpdump_name = "cast",
	.encrypt_ike_audit_name = "cast",
	.encrypt_kernel_audit_name = "CAST",
};
