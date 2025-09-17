/* IKE modular algorithm handling interface, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include "ike_alg_sn.h"
#include "ike_alg.h"

const struct sn_desc ike_alg_sn_32_bit_sequential = {
	.common = {
		.type = &ike_alg_sn,
		.fqn = "32_BIT_SEQUENTIAL",
		.names = "32_bit_sequential,no",
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_SN_32_BIT_SEQUENTIAL,
		},
		.fips.approved = true, /* it's meaningless */
	},
};

const struct sn_desc ike_alg_sn_partial_64_bit_sequential = {
	.common = {
		.type = &ike_alg_sn,
		.fqn = "PARTIAL_64_BIT_SEQUENTIAL",
		.names = "partial_64_bit_sequential,yes",
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_SN_PARTIAL_64_BIT_SEQUENTIAL,
		},
		.fips.approved = true, /* it's meaningless */
	},
};

const struct sn_desc ike_alg_sn_32_bit_unspecified = {
	.common = {
		.type = &ike_alg_sn,
		.fqn = "32_BIT_UNSPECIFIED",
		.names = "32_bit_unspecified,32bit",
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_SN_32_BIT_UNSPECIFIED,
		},
		.fips.approved = true, /* it's meaningless */
	},
};
