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

#ifndef CRYPT_KEM_H
#define CRYPT_KEM_H

#include <pk11pub.h>

#include "shunk.h"
#include "chunk.h"
#include "diag.h"

struct logger;
struct kem_desc;

void crypt_kem_key_gen(const struct kem_desc *kem,
		       SECKEYPrivateKey **initiator_private_key,
		       SECKEYPublicKey **initiator_public_key,
		       struct logger *logger);

chunk_t crypt_kem_public_ke(const struct kem_desc *kem,
			    SECKEYPublicKey *public_key,
			    struct logger *logger);

diag_t crypt_kem_encaps(const struct kem_desc *kem,
			shunk_t initiator_ke,
			chunk_t *responder_ke,
			PK11SymKey **shared_secret,
			struct logger *logger);

diag_t crypt_kem_decaps(const struct kem_desc *kem,
			SECKEYPrivateKey *initiator_private_key,
			const SECKEYPublicKey *initiator_public_key,/*for param*/
			shunk_t responder_ke,
			PK11SymKey **shared_secret,
			struct logger *logger);

#endif
