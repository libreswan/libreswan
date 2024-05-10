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

#include <stdint.h>

#include "ietf_constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_integ.h"
#include "ike_alg_dh.h"
#include "ike_alg_encrypt_ops.h"
#include "ike_alg_dh_ops.h"
#include "lsw-pfkeyv2.h"	/* for SADB_*ALG_* */

/*
 * References for NULL.
 *
 * https://tools.ietf.org/html/rfc2410
 */

const struct encrypt_desc ike_alg_encrypt_null =
{
	.common = {
		.fqn = "NULL",
		.names = "null",
		.algo_type = IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = IKEv1_ESP_NULL,
			[IKEv2_ALG_ID] = IKEv2_ENCR_NULL,
#ifdef SADB_EALG_NULL
			[SADB_ALG_ID] = SADB_EALG_NULL,
#endif
		},
	},
	.enc_blocksize =  1,
	.wire_iv_size =  0,
	.pad_to_blocksize = false,
	.keylen_omitted = true,
	.keydeflen = 0,
	.key_bit_lengths = { 0, },
	.encrypt_netlink_xfrm_name = "cipher_null",
	.encrypt_tcpdump_name = "null",
	.encrypt_ike_audit_name = "null",
	.encrypt_kernel_audit_name = "NULL",
	.encrypt_ops = &ike_alg_encrypt_null_ops,
};

/*
 * This gets negotiated and can ever go across the wire.
 */
const struct integ_desc ike_alg_integ_none = {
	.common = {
		.fqn = "NONE",
		.names = "none,null",
		.algo_type = IKE_ALG_INTEG,
		.id = {
			/*
			 * Not [IKEv1_OAKLEY_ID] = AUTH_ALGORITHM_NONE
			 * or AUTH_ALGORITHM_NULL_KAME?
			 */
			[IKEv1_OAKLEY_ID] = -1,
			/*
			 * Not ESP_KAME_NULL=251?
			 *
			 * XXX: enabling this for ESP also enables it
			 * for AH which isn't valid.  It gets rejected
			 * down the track.  One fix would be to
			 * finally add IKEv1_AH_ID.
			 */
			[IKEv1_IPSEC_ID] = AUTH_ALGORITHM_NONE, /* not NULL_KAME? */
			[IKEv2_ALG_ID] = IKEv2_INTEG_NONE,
#ifdef SADB_X_AALG_NULL
			/* This is from BSD's KAME */
			[SADB_ALG_ID] = SADB_X_AALG_NULL,
#endif
		},
		/*
		* Because aes_gcm-null is valid in FIPS mode, "none"
		* integrity is an allowed FIPS algorithm.
		*
		* Other code gets the job of rejecting "none" when not
		* AEAD.
		*/
		.fips.approved = true,
	},
	.integ_netlink_xfrm_name = "digest_null",
	.integ_tcpdump_name = "none",
	.integ_ike_audit_name = "none",
	.integ_kernel_audit_name = "NONE",
};

/*
 * Blame RFC7296!
 */
const struct dh_desc ike_alg_dh_none = {
	.common = {
		.fqn = "NONE",
		.names = "none,null,dh0",
		.algo_type = IKE_ALG_DH,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = OAKLEY_GROUP_NONE,
		},
		/*
		 * IKEv2, during the initial exchanges, negotiates a
		 * child SA without DH (or if screwing with the RFC,
		 * DH=NONE).  Either way, the result is a child state
		 * with .ta_dh == &ike_alg_dh_none.
		 *
		 * Other code gets the job of rejecting "none".
		 */
		.fips.approved = true,
	},
	.group = OAKLEY_GROUP_NONE,
	/*
	 * While patently untrue, this does keep things happy.
	 */
	.dh_ops = &ike_alg_dh_nss_modp_ops,
};
