/* Key Exchange Method algorithms, for libreswan
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

#include <keyhi.h>

#include "crypt_kem.h"
#include "ike_alg.h"
#include "ike_alg_kem_ops.h"
#include "passert.h"

void crypt_kem_key_gen(const struct kem_desc *kem,
		       SECKEYPrivateKey **initiator_private_key,
		       SECKEYPublicKey **initiator_public_key,
		       struct logger *logger)
{
	kem->kem_ops->calc_local_secret(kem, initiator_private_key, initiator_public_key, logger);
	PASSERT(logger, (*initiator_private_key) != NULL);
	PASSERT(logger, (*initiator_public_key) != NULL);
}

chunk_t crypt_kem_public_ke(const struct kem_desc *kem,
			    SECKEYPublicKey *public_key,
			    struct logger *logger UNUSED)
{
	shunk_t initiator_ke = kem->kem_ops->local_secret_ke(kem, public_key);
	return clone_hunk(initiator_ke, "initiator-ke");
}

diag_t crypt_kem_encaps(const struct kem_desc *kem,
			shunk_t initiator_ke,
			chunk_t *responder_ke_out,
			PK11SymKey **shared_secret,
			struct logger *logger)
{
	diag_t d = NULL;
	SECKEYPrivateKey *responder_private_key = NULL;
	SECKEYPublicKey *responder_public_key = NULL;
	kem->kem_ops->calc_local_secret(kem, &responder_private_key, &responder_public_key, logger);
	PASSERT(logger, responder_private_key != NULL);
	PASSERT(logger, responder_public_key != NULL);
	d = kem->kem_ops->calc_shared_secret(kem, responder_private_key, responder_public_key,
					     initiator_ke, shared_secret, logger);
	if (d != NULL) {
		SECKEY_DestroyPublicKey(responder_public_key);
		SECKEY_DestroyPrivateKey(responder_private_key);
		return d;
	}
	shunk_t responder_ke = kem->kem_ops->local_secret_ke(kem, responder_public_key);
	(*responder_ke_out) = clone_hunk(responder_ke, "responder-ke");
	SECKEY_DestroyPublicKey(responder_public_key);
	SECKEY_DestroyPrivateKey(responder_private_key);
	return NULL;
}

diag_t crypt_kem_decaps(const struct kem_desc *kem,
			SECKEYPrivateKey *initiator_private_key,
			const SECKEYPublicKey *initiator_public_key,
			shunk_t responder_ke,
			PK11SymKey **shared_secret,
			struct logger *logger)
{
	return kem->kem_ops->calc_shared_secret(kem, initiator_private_key, initiator_public_key,
						responder_ke, shared_secret, logger);
}

