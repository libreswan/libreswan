/* MD5, for libreswan.
 *
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
#include "ike_alg_hash_ops.h"

const struct hash_desc ike_alg_hash_md5 = {
	.common = {
		.fqn = "MD5",
		.names = "md5",
		.algo_type = IKE_ALG_HASH,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_MD5,
			[IKEv1_IPSEC_ID] = -1,
			[IKEv2_ALG_ID] = -1,
		},
	},
	.nss = {
		.oid_tag = SEC_OID_MD5,
		.derivation_mechanism = CKM_MD5_KEY_DERIVATION,
	},
	.hash_digest_size = MD5_DIGEST_SIZE,
	.hash_block_size = 64,	/* B from RFC 2104 */
	.hash_ops = &ike_alg_hash_nss_ops,
};
