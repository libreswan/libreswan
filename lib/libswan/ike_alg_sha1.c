/* crypto interfaces
 *
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
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
#include "ike_alg_hash.h"
#include "ike_alg_prf.h"
#include "ike_alg_integ.h"
#include "ike_alg_prf_mac_ops.h"
#include "ike_alg_prf_ikev1_ops.h"
#include "ike_alg_prf_ikev2_ops.h"
#include "lsw-pfkeyv2.h"	/* for SADB_*ALG_* */

const struct prf_desc ike_alg_prf_sha1 = {
	.common = {
		.fqn = "HMAC_SHA1",
		.names = "sha,sha1,hmac_sha1",
		.algo_type = IKE_ALG_PRF,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA1,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_HMAC_SHA1,
		},
		.fips.approved = true,
	},
	.nss = {
		.mechanism = CKM_SHA_1_HMAC,
	},
	.prf_key_size = SHA1_DIGEST_SIZE,
	.prf_output_size = SHA1_DIGEST_SIZE,
	.hasher = &ike_alg_hash_sha1,
	.prf_mac_ops = &ike_alg_prf_mac_nss_ops,
#ifdef USE_NSS_KDF
	.prf_ikev1_ops = &ike_alg_prf_ikev1_nss_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_nss_ops,
#else
	.prf_ikev1_ops = &ike_alg_prf_ikev1_mac_ops,
	.prf_ikev2_ops = &ike_alg_prf_ikev2_mac_ops,
#endif
	.prf_ike_audit_name = "sha1",
};

const struct integ_desc ike_alg_integ_sha1 = {
	.common = {
		.fqn = "HMAC_SHA1_96",
		.names = "sha,sha1,sha1_96,hmac_sha1,hmac_sha1_96",
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_SHA1,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_HMAC_SHA1,
			[IKEv2_ALG_ID] = IKEv2_INTEG_HMAC_SHA1_96,
#ifdef SADB_AALG_SHA1HMAC
			[SADB_ALG_ID] = SADB_AALG_SHA1HMAC,
#endif
		},
		.fips.approved = true,
	},
	.integ_keymat_size = SHA1_DIGEST_SIZE,
	.integ_output_size = SHA1_DIGEST_SIZE_96,
	.integ_ikev1_ah_transform = IKEv1_AH_SHA,
	.prf = &ike_alg_prf_sha1,
	.integ_netlink_xfrm_name = "sha1",
	.integ_tcpdump_name = "sha1",
	.integ_ike_audit_name = "sha1",
	.integ_kernel_audit_name = "HMAC_SHA1",
};
