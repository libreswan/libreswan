/*
 * IKE modular algorithm handling interface, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include "ike_alg_dh.h"

/*
 * Oakley group description
 *
 * See:
 * RFC-2409 "The Internet key exchange (IKE)" Section 6
 * RFC-3526 "More Modular Exponential (MODP) Diffie-Hellman groups"
 */

/* magic signifier */
const struct oakley_group_desc unset_group = {
	.group = OAKLEY_GROUP_invalid,
};

struct oakley_group_desc oakley_group_modp1024 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "modp1024",
		.officname = "modp1024",
		.ikev1_oakley_id = OAKLEY_GROUP_MODP1024,
	},
	.group = OAKLEY_GROUP_MODP1024,
	.gen = MODP_GENERATOR,
	.modp = MODP1024_MODULUS,
	.bytes = BYTES_FOR_BITS(1024),
};

struct oakley_group_desc oakley_group_modp1536 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "modp1536",
		.officname = "modp1536",
		.ikev1_oakley_id = OAKLEY_GROUP_MODP1536,
	},
	.group = OAKLEY_GROUP_MODP1536,
	.gen = MODP_GENERATOR,
	.modp = MODP1536_MODULUS,
	.bytes = BYTES_FOR_BITS(1536),
};

struct oakley_group_desc oakley_group_modp2048 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "modp2048",
		.officname = "modp2048",
		.ikev1_oakley_id = OAKLEY_GROUP_MODP2048,
		.fips = TRUE,
	},
	.group = OAKLEY_GROUP_MODP2048,
	.gen = MODP_GENERATOR,
	.modp = MODP2048_MODULUS,
	.bytes = BYTES_FOR_BITS(2048),
};

struct oakley_group_desc oakley_group_modp3072 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "modp3072",
		.officname = "modp3072",
		.ikev1_oakley_id = OAKLEY_GROUP_MODP3072,
		.fips = TRUE,
	},
	.group = OAKLEY_GROUP_MODP3072,
	.gen = MODP_GENERATOR,
	.modp = MODP3072_MODULUS,
	.bytes = BYTES_FOR_BITS(3072),
};

struct oakley_group_desc oakley_group_modp4096 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "modp4096",
		.officname = "modp4096",
		.ikev1_oakley_id = OAKLEY_GROUP_MODP4096,
		.fips = TRUE,
	},
	.group = OAKLEY_GROUP_MODP4096,
	.gen = MODP_GENERATOR,
	.modp = MODP4096_MODULUS,
	.bytes = BYTES_FOR_BITS(4096),
};

struct oakley_group_desc oakley_group_modp6144 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "modp6144",
		.officname = "modp6144",
		.ikev1_oakley_id = OAKLEY_GROUP_MODP6144,
		.fips = TRUE,
	},
	.group = OAKLEY_GROUP_MODP6144,
	.gen = MODP_GENERATOR,
	.modp = MODP6144_MODULUS,
	.bytes = BYTES_FOR_BITS(6144),
};

struct oakley_group_desc oakley_group_modp8192 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "modp8192",
		.officname = "modp8192",
		.ikev1_oakley_id = OAKLEY_GROUP_MODP8192,
		.fips = TRUE,
	},
	.group = OAKLEY_GROUP_MODP8192,
	.gen = MODP_GENERATOR,
	.modp = MODP8192_MODULUS,
	.bytes = BYTES_FOR_BITS(8192),
};

#ifdef USE_DH22
struct oakley_group_desc oakley_group_dh22 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "dh22",
		.officname = "dh22",
		.ikev1_oakley_id = OAKLEY_GROUP_DH22,
	},
	.group = OAKLEY_GROUP_DH22,
	.gen = MODP_GENERATOR_DH22,
	.modp = MODP1024_MODULUS_DH22,
	.bytes = BYTES_FOR_BITS(1024),
};
#endif

struct oakley_group_desc oakley_group_dh23 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "dh23",
		.officname = "dh23",
		.ikev1_oakley_id = OAKLEY_GROUP_DH23,
	},
	.group = OAKLEY_GROUP_DH23,
	.gen = MODP_GENERATOR_DH23,
	.modp = MODP2048_MODULUS_DH23,
	.bytes = BYTES_FOR_BITS(2048),
};

struct oakley_group_desc oakley_group_dh24 = {
	.common = {
		.algo_type = IKE_ALG_DH,
		.name = "dh24",
		.officname = "dh24",
		.ikev1_oakley_id = OAKLEY_GROUP_DH24,
	},
	.group = OAKLEY_GROUP_DH24,
	.gen = MODP_GENERATOR_DH24,
	.modp = MODP2048_MODULUS_DH24,
	.bytes = BYTES_FOR_BITS(2048),
};
