/*
 * Copyright (C) 2022  Andrew Cagney
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

#include <stdint.h>

#include "ietf_constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_integ.h"
#include "ike_alg_kem.h"
#include "ike_alg_kem_ops.h"

/*
 * RFC 8420
 */

const struct hash_desc ike_alg_hash_identity = {
	.common = {
		.fqn = "IDENTITY",
		.names = "identity",
		.type = &ike_alg_hash,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_HASH_ALGORITHM_IDENTITY,
		},
		.fips.approved = true,
	},
};
