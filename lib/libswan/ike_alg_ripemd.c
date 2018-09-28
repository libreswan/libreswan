/* RIPEMD, for libreswan.
 *
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
 *
 */

#include "constants.h"		/* for BYTES_FOR_BITS() */
#include "ietf_constants.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "sadb.h"

/*
 * See: https://tools.ietf.org/html/rfc2857
 *
 * While NSS seemingly supports RIPEMD160, let's not go there.
 */

const struct integ_desc ike_alg_integ_hmac_ripemd_160_96 = {
	.common = {
		.name = "ripemd",
		.fqn = "HMAC_RIPEMD_160_96",
		.names = { "ripemd", "hmac_ripemd", "hmac_ripemd_160_96", },
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_RIPEMD,
			[IKEv2_ALG_ID] = -1,
		},
	},
	.integ_keymat_size = BYTES_FOR_BITS(160),
	.integ_output_size = BYTES_FOR_BITS(96),
	.integ_ikev1_ah_transform = AH_RIPEMD,
#ifdef SADB_X_AALG_RIPEMD160HMAC
	.integ_sadb_aalg_id = SADB_X_AALG_RIPEMD160HMAC,
#endif
	.integ_netlink_xfrm_name = "hmac(rmd160)",
	.integ_tcpdump_name = "ripemd",
	.integ_ike_audit_name = "ripemd",
	.integ_kernel_audit_name = "HMAC_RIPEMD",
};
