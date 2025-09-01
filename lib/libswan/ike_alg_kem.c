/*
 * IKE modular algorithm handling interface, for libreswan
 *
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include "constants.h"
#include "lswlog.h"
#include "ike_alg.h"

#include "ike_alg_kem.h"
#include "ike_alg_kem_ops.h"

/*
 * Oakley group description
 *
 * See:
 * RFC-2409 "The Internet key exchange (IKE)" Section 6
 * RFC-3526 "More Modular Exponential (MODP) Diffie-Hellman groups"
 */

/* magic signifier */
const struct kem_desc unset_group = {
	.group = 65535, /* Reserved for private use */
};

#ifdef USE_DH2
const struct kem_desc ike_alg_kem_modp1024 = {
	.common = {
		.type = IKE_ALG_KEM,
		.fqn = "MODP1024",
		.names = "modp1024,dh2",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_MODP1024,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_MODP1024,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_MODP1024,
		},
	},
	.group = OAKLEY_GROUP_MODP1024,
	.gen = MODP_GENERATOR,
	.modp = MODP1024_MODULUS,
	.bytes = BYTES_FOR_BITS(1024),
	.initiator_bytes = BYTES_FOR_BITS(1024),
	.responder_bytes = BYTES_FOR_BITS(1024),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};
#endif

const struct kem_desc ike_alg_kem_modp1536 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "MODP1536",
		.names = "modp1536,dh5",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_MODP1536,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_MODP1536,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_MODP1536,
		},
	},
	.group = OAKLEY_GROUP_MODP1536,
	.gen = MODP_GENERATOR,
	.modp = MODP1536_MODULUS,
	.bytes = BYTES_FOR_BITS(1536),
	.initiator_bytes = BYTES_FOR_BITS(1536),
	.responder_bytes = BYTES_FOR_BITS(1536),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};

const struct kem_desc ike_alg_kem_modp2048 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "MODP2048",
		.names = "modp2048,dh14",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_MODP2048,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_MODP2048,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_MODP2048,
		},
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_MODP2048,
	.gen = MODP_GENERATOR,
	.modp = MODP2048_MODULUS,
	.bytes = BYTES_FOR_BITS(2048),
	.initiator_bytes = BYTES_FOR_BITS(2048),
	.responder_bytes = BYTES_FOR_BITS(2048),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};

const struct kem_desc ike_alg_kem_modp3072 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "MODP3072",
		.names = "modp3072,dh15",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_MODP3072,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_MODP3072,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_MODP3072,
		},
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_MODP3072,
	.gen = MODP_GENERATOR,
	.modp = MODP3072_MODULUS,
	.bytes = BYTES_FOR_BITS(3072),
	.initiator_bytes = BYTES_FOR_BITS(3072),
	.responder_bytes = BYTES_FOR_BITS(3072),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};

const struct kem_desc ike_alg_kem_modp4096 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "MODP4096",
		.names = "modp4096,dh16",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_MODP4096,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_MODP4096,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_MODP4096,
		},
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_MODP4096,
	.gen = MODP_GENERATOR,
	.modp = MODP4096_MODULUS,
	.bytes = BYTES_FOR_BITS(4096),
	.initiator_bytes = BYTES_FOR_BITS(4096),
	.responder_bytes = BYTES_FOR_BITS(4096),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};

const struct kem_desc ike_alg_kem_modp6144 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "MODP6144",
		.names = "modp6144,dh17",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_MODP6144,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_MODP6144,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_MODP6144,
		},
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_MODP6144,
	.gen = MODP_GENERATOR,
	.modp = MODP6144_MODULUS,
	.bytes = BYTES_FOR_BITS(6144),
	.initiator_bytes = BYTES_FOR_BITS(6144),
	.responder_bytes = BYTES_FOR_BITS(6144),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};

const struct kem_desc ike_alg_kem_modp8192 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "MODP8192",
		.names = "modp8192,dh18",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_MODP8192,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_MODP8192,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_MODP8192,
		},
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_MODP8192,
	.gen = MODP_GENERATOR,
	.modp = MODP8192_MODULUS,
	.bytes = BYTES_FOR_BITS(8192),
	.initiator_bytes = BYTES_FOR_BITS(8192),
	.responder_bytes = BYTES_FOR_BITS(8192),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};

const struct kem_desc ike_alg_kem_secp256r1 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "DH19",
		.names = "dh19,ecp_256,ecp256",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_ECP_256,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_ECP_256,
		},
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_ECP_256,
	.bytes = BYTES_FOR_BITS(256) * 2,
	.initiator_bytes = BYTES_FOR_BITS(256) * 2,
	.responder_bytes = BYTES_FOR_BITS(256) * 2,
	.nss_oid = SEC_OID_SECG_EC_SECP256R1,
	.nss_adds_ec_point_form_uncompressed = true,
	.kem_ops = &ike_alg_kem_ecp_nss_ops,
};

const struct kem_desc ike_alg_kem_secp384r1 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "DH20",
		.names = "dh20,ecp_384,ecp384",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_ECP_384,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_ECP_384,
		},
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_ECP_384,
	.bytes = BYTES_FOR_BITS(384) * 2,
	.initiator_bytes = BYTES_FOR_BITS(384) * 2,
	.responder_bytes = BYTES_FOR_BITS(384) * 2,
	.nss_oid = SEC_OID_SECG_EC_SECP384R1,
	.nss_adds_ec_point_form_uncompressed = true,
	.kem_ops = &ike_alg_kem_ecp_nss_ops,
};

const struct kem_desc ike_alg_kem_secp521r1 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "DH21",
		.names = "dh21,ecp_521,ecp521",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_ECP_521,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_ECP_521,
		},
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_ECP_521,
	.bytes = BYTES_FOR_BITS(521) * 2,
	.initiator_bytes = BYTES_FOR_BITS(521) * 2,
	.responder_bytes = BYTES_FOR_BITS(521) * 2,
	.nss_oid = SEC_OID_SECG_EC_SECP521R1,
	.nss_adds_ec_point_form_uncompressed = true,
	.kem_ops = &ike_alg_kem_ecp_nss_ops,
};

#ifdef USE_DH22
const struct kem_desc ike_alg_kem_dh22 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "DH22",
		.names = "dh22",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_DH22,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_DH22,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_DH22,
		},
		.fips.approved = false, /* SP 800-56A rev 3 */
	},
	.group = OAKLEY_GROUP_DH22,
	.gen = MODP_GENERATOR_DH22,
	.modp = MODP1024_MODULUS_DH22,
	.bytes = BYTES_FOR_BITS(1024),
	.initiator_bytes = BYTES_FOR_BITS(1024),
	.responder_bytes = BYTES_FOR_BITS(1024),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};
#endif

#ifdef USE_DH23
const struct kem_desc ike_alg_kem_dh23 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "DH23",
		.names = "dh23",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_DH23,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_DH23,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_DH23,
		},
		.fips.approved = false, /* SP 800-56A rev 3 */
	},
	.group = OAKLEY_GROUP_DH23,
	.gen = MODP_GENERATOR_DH23,
	.modp = MODP2048_MODULUS_DH23,
	.bytes = BYTES_FOR_BITS(2048),
	.initiator_bytes = BYTES_FOR_BITS(2048),
	.responder_bytes = BYTES_FOR_BITS(2048),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};
#endif

#ifdef USE_DH24
const struct kem_desc ike_alg_kem_dh24 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "DH24",
		.names = "dh24",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_DH24,
			[IKEv1_IPSEC_ID] = OAKLEY_GROUP_DH24,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_DH24,
		},
		.fips.approved = false, /* SP 800-56A rev 3 */
	},
	.group = OAKLEY_GROUP_DH24,
	.gen = MODP_GENERATOR_DH24,
	.modp = MODP2048_MODULUS_DH24,
	.bytes = BYTES_FOR_BITS(2048),
	.initiator_bytes = BYTES_FOR_BITS(2048),
	.responder_bytes = BYTES_FOR_BITS(2048),
	.kem_ops = &ike_alg_kem_modp_nss_ops,
};
#endif

/* https://tools.ietf.org/html/rfc8031 */

#ifdef USE_DH31
const struct kem_desc ike_alg_kem_curve25519 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "DH31",
		.names = "dh31,curve25519",
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_GROUP_CURVE25519,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_CURVE25519,
		},
	},
	.group = OAKLEY_GROUP_CURVE25519,
	.bytes = 32 /* octets */,
	.initiator_bytes = 32 /* octets */,
	.responder_bytes = 32 /* octets */,
	.nss_oid = SEC_OID_CURVE25519,
	.kem_ops = &ike_alg_kem_ecp_nss_ops,
};
#endif

/* https://datatracker.ietf.org/doc/draft-ietf-ipsecme-ikev2-mlkem/ */

#ifdef USE_ML_KEM_512
const struct kem_desc ike_alg_kem_ml_kem_512 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "ML_KEM_512",
		.names = "ml_kem_512,mlkem512",
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_ML_KEM_512,
		},
	},
	.group = OAKLEY_GROUP_ML_KEM_512,
	/* Data Size on Octets on wire */
	.initiator_bytes = 800,
	.responder_bytes = 768,
	.kem_ops = &ike_alg_kem_ml_kem_nss_ops,
};
#endif

#ifdef USE_ML_KEM_768
const struct kem_desc ike_alg_kem_ml_kem_768 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "ML_KEM_768",
		.names = "ml_kem_768,mlkem768",
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_ML_KEM_768,
		},
	},
	.group = OAKLEY_GROUP_ML_KEM_768,
	/* Data Size on Octets on wire */
	.initiator_bytes = 1184,
	.responder_bytes = 1088,
	.kem_ops = &ike_alg_kem_ml_kem_nss_ops,
};
#endif

#ifdef USE_ML_KEM_1024
const struct kem_desc ike_alg_kem_ml_kem_1024 = {
	.common = {
		.type = &ike_alg_kem,
		.fqn = "ML_KEM_1024",
		.names = "ml_kem_1024,mlkem1024",
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_ML_KEM_1024,
		},
	},
	.group = OAKLEY_GROUP_ML_KEM_1024,
	/* Data Size on Octets on wire */
	.initiator_bytes = 1568,
	.responder_bytes = 1568,
	.kem_ops = &ike_alg_kem_ml_kem_nss_ops,
};
#endif
