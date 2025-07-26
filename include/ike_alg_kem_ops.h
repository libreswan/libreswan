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

#ifndef IKE_ALG_DH_OPS_H
#define IKE_ALG_DH_OPS_H

#include "diag.h"
#include "chunk.h"

struct logger;

struct kem_ops {
	const char *backend;

	/*
	 * Delegate responsibility for checking OPS specific fields.
	 */
	void (*const check)(const struct kem_desc *alg, struct logger *logger);

	/*
	 * Create the local secret and KE for remote.
	 *
	 * The LOCAL_PUBK parameter is arguably redundant - just the
	 * KE bytes and private key are needed - however MODP's
	 * CALC_G_IR() uses LOCAL_PUBK to fudge up the remote's public
	 * key.
	 *
	 * SIZEOF_KE == .BYTES from above, but pass it in so both ends
	 * can perform a sanity check.
	 */
	void (*calc_local_secret)(const struct kem_desc *group,
				  SECKEYPrivateKey **local_privk,
				  SECKEYPublicKey **locak_pubk,
				  struct logger *logger);
	shunk_t (*local_secret_ke)(const struct kem_desc *group,
				   const SECKEYPublicKey *local_pubk);
	diag_t (*calc_shared_secret)(const struct kem_desc *group,
				     SECKEYPrivateKey *local_privk,
				     const SECKEYPublicKey *local_pubk,
				     chunk_t remote_ke,
				     PK11SymKey **shared_secret,
				     struct logger *logger) MUST_USE_RESULT;
};

extern const struct kem_ops ike_alg_kem_ecp_nss_ops;
extern const struct kem_ops ike_alg_kem_modp_nss_ops;

#endif
