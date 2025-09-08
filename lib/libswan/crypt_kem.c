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
#include "crypt_symkey.h"

#include "ike_alg.h"
#include "ike_alg_kem_ops.h"
#include "passert.h"
#include "lswalloc.h"

diag_t crypt_kem_key_gen(const struct kem_desc *kem,
			 struct kem_initiator **initiator,
			 struct logger *logger)
{
	(*initiator) = alloc_thing(struct kem_initiator, "kem-initiator");
	(*initiator)->kem = kem;
	kem->kem_ops->calc_local_secret(kem,
					&(*initiator)->internal.private_key,
					&(*initiator)->internal.public_key,
					logger);
	PASSERT(logger, (*initiator)->internal.private_key != NULL);
	PASSERT(logger, (*initiator)->internal.public_key != NULL);
	(*initiator)->ke = kem->kem_ops->local_secret_ke(kem, (*initiator)->internal.public_key);
	PASSERT(logger, (*initiator)->ke.len == kem->initiator_bytes);
	return NULL;
}

diag_t crypt_kem_encapsulate(const struct kem_desc *kem,
			     shunk_t initiator_ke,
			     struct kem_responder **responder,
			     struct logger *logger)
{
	PASSERT(logger, initiator_ke.len == kem->initiator_bytes);
	(*responder) = alloc_thing(struct kem_responder, "kem-responder");
	(*responder)->kem = kem;

	diag_t d;
	if (kem->kem_ops->kem_encapsulate != NULL) {
		d = kem->kem_ops->kem_encapsulate((*responder), initiator_ke, logger);
	} else {
		kem->kem_ops->calc_local_secret(kem, &(*responder)->internal.private_key, &(*responder)->internal.public_key, logger);
		PASSERT(logger, (*responder)->internal.private_key != NULL);
		PASSERT(logger, (*responder)->internal.public_key != NULL);
		d = kem->kem_ops->calc_shared_secret(kem,
						     (*responder)->internal.private_key,
						     (*responder)->internal.public_key,
						     initiator_ke,
						     &(*responder)->shared_key,
						     logger);
		if (d != NULL) {
			free_kem_responder(responder, logger);
			return d;
		}
		(*responder)->ke = kem->kem_ops->local_secret_ke(kem, (*responder)->internal.public_key);
	}

	if (d != NULL) {
		free_kem_responder(responder, logger);
		return d;
	}

	PASSERT(logger, (*responder)->shared_key != NULL);
	PASSERT(logger, (*responder)->ke.len == kem->responder_bytes);
	return NULL;
}

diag_t crypt_kem_decapsulate(struct kem_initiator *initiator,
			     shunk_t responder_ke,
			     struct logger *logger)
{
	PASSERT(logger, responder_ke.len == initiator->kem->responder_bytes);
	diag_t d;
	if (initiator->kem->kem_ops->kem_decapsulate != NULL) {
		d = initiator->kem->kem_ops->kem_decapsulate(initiator, responder_ke, logger);
	} else {
		d = initiator->kem->kem_ops->calc_shared_secret(initiator->kem,
								initiator->internal.private_key,
								initiator->internal.public_key,
								responder_ke,
								&initiator->shared_key,
								logger);
	}

	if (d != NULL) {
		return d;
	}

	PASSERT(logger, initiator->shared_key != NULL);
	return NULL;
}

void free_kem_initiator(struct kem_initiator **initiator,
			const struct logger *logger)
{
	if (*initiator == NULL) {
		return;
	}

	SECKEY_DestroyPublicKey((*initiator)->internal.public_key);
	SECKEY_DestroyPrivateKey((*initiator)->internal.private_key);
	symkey_delref(logger, "initiator shared key", &(*initiator)->shared_key);
	pfreeany((*initiator));
}

void free_kem_responder(struct kem_responder **responder,
			const struct logger *logger)
{
	if (*responder == NULL) {
		return;
	}

	SECKEY_DestroyPublicKey((*responder)->internal.public_key);
	SECKEY_DestroyPrivateKey((*responder)->internal.private_key);
	symkey_delref(logger, "responder shared key", &(*responder)->shared_key);
	free_chunk_content(&(*responder)->internal.ke);
	pfreeany((*responder));
}
